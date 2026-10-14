# agent-gateway-lab : un LLM Mistral auto-hébergé, joignable uniquement par
# la passerelle (mTLS), sans aucun port entrant, avec une chaîne de release
# signée par KMS et vérifiée à chaque démarrage.

terraform {
  required_version = ">= 1.10"
  backend "s3" {
    key = "agent-gateway-lab/terraform.tfstate"
  }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = var.project, ManagedBy = "terraform" }
  }
}

data "aws_caller_identity" "me" {}
data "aws_partition" "p" {}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_availability_zones" "az" {
  state = "available"
}

locals {
  account_id = data.aws_caller_identity.me.account_id
  bucket     = "${var.project}-releases-${local.account_id}"
  log_group  = "/${var.project}/runtime"
  ssm_prefix = "/${var.project}/tls"
}

# ---------------------------------------------------------------- réseau
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.project }
}

# Le groupe par défaut ne laisse rien passer.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.this.id
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
}

# Sous-réseau public sans NAT Gateway (environ 1 $/jour) : l'instance a une IP
# publique pour sortir en 443, mais aucun port entrant n'est ouvert.
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  availability_zone       = data.aws_availability_zones.az.names[0]
  map_public_ip_on_launch = true # sortie sans NAT, aucun port entrant
  tags                    = { Name = "${var.project}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Le modèle (2 Go) passe par le réseau AWS, gratuitement.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.public.id]
}

resource "aws_security_group" "instance" {
  name        = "${var.project}-instance"
  description = "Aucun port entrant. Sortie HTTPS uniquement (SSM, S3, KMS, CloudWatch, registres d'images)."
  vpc_id      = aws_vpc.this.id

  egress {
    description = "HTTPS sortant"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # registres d'images publics, pas de NAT ni de proxy
  }
}

resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.this.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow.arn
  iam_role_arn         = aws_iam_role.flow.arn
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/${var.project}/vpc-flow"
  retention_in_days = 14
}

resource "aws_iam_role" "flow" {
  name = "${var.project}-flow-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "flow" {
  role = aws_iam_role.flow.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow.arn}:*"
    }]
  })
}

# ------------------------------------------------- chaîne de release signée
resource "aws_kms_key" "release" {
  description              = "Signature des manifestes de release (sign: admin, verify: instance)"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 7
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AdministrationParIAM"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.p.partition}:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        # Même un rôle très privilégié ne peut pas signer depuis l'instance.
        Sid       = "JamaisDeSignatureDepuisLInstance"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "kms:Sign"
        Resource  = "*"
        Condition = { ArnLike = { "aws:PrincipalArn" = aws_iam_role.instance.arn } }
      }
    ]
  })
}

resource "aws_kms_alias" "release" {
  name          = "alias/${var.project}-release"
  target_key_id = aws_kms_key.release.key_id
}

resource "aws_s3_bucket" "releases" {
  bucket        = local.bucket
  force_destroy = true # artefacts reconstructibles depuis le dépôt
}

resource "aws_s3_bucket_versioning" "releases" {
  bucket = aws_s3_bucket.releases.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "releases" {
  bucket = aws_s3_bucket.releases.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # intégrité assurée par la signature KMS, pas de secret ici
    }
  }
}

resource "aws_s3_bucket_public_access_block" "releases" {
  bucket                  = aws_s3_bucket.releases.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "releases" {
  bucket = aws_s3_bucket.releases.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "releases" {
  bucket = aws_s3_bucket.releases.id
  rule {
    id     = "anciennes-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_policy" "releases" {
  bucket = aws_s3_bucket.releases.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "TLSObligatoire"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.releases.arn, "${aws_s3_bucket.releases.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        # L'instance lit, elle n'écrit jamais : un attaquant sur l'instance ne
        # peut pas empoisonner la prochaine release.
        Sid       = "InstanceEnLectureSeule"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutBucketPolicy"]
        Resource  = [aws_s3_bucket.releases.arn, "${aws_s3_bucket.releases.arn}/*"]
        Condition = { ArnLike = { "aws:PrincipalArn" = aws_iam_role.instance.arn } }
      }
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.releases]
}

# ------------------------------------------------------------- instance
resource "aws_iam_role" "instance" {
  name = "${var.project}-instance"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:${data.aws_partition.p.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "instance" {
  role = aws_iam_role.instance.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "LireLesReleases"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = ["${aws_s3_bucket.releases.arn}/releases/*", "${aws_s3_bucket.releases.arn}/models/*"]
      },
      {
        Sid      = "VerifierSeulement"
        Effect   = "Allow"
        Action   = ["kms:Verify", "kms:GetPublicKey", "kms:DescribeKey"]
        Resource = aws_kms_key.release.arn
      },
      {
        Sid      = "CertificatsTLS"
        Effect   = "Allow"
        Action   = "ssm:GetParameter"
        Resource = "arn:${data.aws_partition.p.partition}:ssm:${var.region}:${local.account_id}:parameter${local.ssm_prefix}/*"
      },
      {
        Sid      = "Journaux"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
        Resource = "${aws_cloudwatch_log_group.runtime.arn}:*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.project}-instance"
  role = aws_iam_role.instance.name
}

resource "aws_cloudwatch_log_group" "runtime" {
  name              = local.log_group
  retention_in_days = 30
}

resource "aws_instance" "llm" {
  ami                         = data.aws_ssm_parameter.al2023.value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.instance.id]
  iam_instance_profile        = aws_iam_instance_profile.instance.name
  associate_public_ip_address = true # sortie sans NAT, aucun port entrant
  monitoring                  = false

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1 # les conteneurs n'atteignent pas l'IMDS
    http_endpoint               = "enabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 30
    encrypted             = true
    delete_on_termination = true
  }

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    region         = var.region
    bucket         = aws_s3_bucket.releases.bucket
    kms_key        = aws_kms_key.release.arn
    log_group      = aws_cloudwatch_log_group.runtime.name
    ssm_prefix     = local.ssm_prefix
    ctx            = var.context_size
    verify_release = base64encode(file("${path.module}/../scripts/verify-release.sh"))
    run_stack      = base64encode(file("${path.module}/../scripts/run-stack.sh"))
  })

  tags = { Name = "${var.project}-llm" }

  lifecycle {
    ignore_changes = [ami] # pas de remplacement à chaque nouvelle AMI
  }
}

# Coût : arrêt automatique après une heure sans activité.
resource "aws_cloudwatch_metric_alarm" "idle_stop" {
  alarm_name          = "${var.project}-idle-stop"
  alarm_description   = "Arrête l'instance après ${var.idle_minutes} min de CPU < 3 %"
  namespace           = "AWS/EC2"
  metric_name         = "CPUUtilization"
  dimensions          = { InstanceId = aws_instance.llm.id }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = var.idle_minutes / 5
  threshold           = 3
  comparison_operator = "LessThanThreshold"
  alarm_actions       = ["arn:${data.aws_partition.p.partition}:automate:${var.region}:ec2:stop"]
}
