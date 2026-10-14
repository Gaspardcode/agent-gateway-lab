# Détection sur l'audit de la passerelle. Les règles lisibles sont dans
# detection/rules/*.yml (Sigma) ; ici leur traduction en filtres CloudWatch.

locals {
  # nom => [motif de filtre, seuil sur 5 min, description]
  detections = {
    ReleaseVerificationFailed = ["{ $.event = \"release_verification_failed\" }", 1, "Release non vérifiée au démarrage (AML.T0010) : la pile n'a pas démarré"]
    ExfiltrationBlocked       = ["{ $.exfil IS TRUE }", 1, "Tentative d'exfiltration par le modèle (AML.T0057 / AML.T0025)"]
    IndirectInjection         = ["{ $.tainted IS TRUE }", 3, "Contenu d'outil contaminé par une injection (AML.T0051.001)"]
    ToolViolation             = ["{ $.tool_violation IS TRUE }", 1, "Outil hors du périmètre du client (AML.T0053)"]
    AuthFailures              = ["{ $.auth_fail IS TRUE }", 5, "Échecs mTLS ou clients inconnus"]
    RateLimited               = ["{ $.rate_limited IS TRUE }", 20, "Rafale de requêtes (déni de service, coût)"]
  }
}

resource "aws_cloudwatch_log_metric_filter" "d" {
  for_each       = local.detections
  name           = "${var.project}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.runtime.name
  pattern        = each.value[0]
  metric_transformation {
    name          = each.key
    namespace     = "AgentGatewayLab"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_sns_topic" "alerts" {
  name              = "${var.project}-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "d" {
  for_each            = local.detections
  alarm_name          = "${var.project}-${each.key}"
  alarm_description   = each.value[2]
  namespace           = "AgentGatewayLab"
  metric_name         = each.key
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = each.value[1]
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  depends_on          = [aws_cloudwatch_log_metric_filter.d]
}

# Requêtes d'investigation prêtes à l'emploi (Logs Insights).
resource "aws_cloudwatch_query_definition" "q" {
  for_each = {
    "decisions-par-client" = <<-EOT
      filter event = "chat"
      | stats count(*) as n by client, decision
      | sort n desc
    EOT
    "chaines-d-attaque"    = <<-EOT
      filter event = "chat" and decision in ["block", "would_block", "redact"]
      | fields @timestamp, client, decision, request_id, tools_called.0 as outil, findings.0.rule as regle, findings.0.detail as detail
      | sort @timestamp desc
    EOT
    "latence-modele"       = <<-EOT
      filter event = "chat" and ispresent(upstream_ms)
      | stats avg(upstream_ms) as moy_ms, pct(upstream_ms, 95) as p95_ms, sum(completion_tokens) as tokens by bin(15m)
    EOT
    "demarrages"           = <<-EOT
      filter @logStream = "boot" or event = "startup"
      | fields @timestamp, event, detail, mode
      | sort @timestamp desc
    EOT
  }
  name            = "${var.project}/${each.key}"
  log_group_names = [aws_cloudwatch_log_group.runtime.name]
  query_string    = each.value
}
