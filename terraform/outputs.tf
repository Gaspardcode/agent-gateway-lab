output "instance_id" {
  value = aws_instance.llm.id
}

output "release_bucket" {
  value = aws_s3_bucket.releases.bucket
}

output "kms_key" {
  value = aws_kms_alias.release.name
}

output "log_group" {
  value = aws_cloudwatch_log_group.runtime.name
}

output "tunnel" {
  description = "Ouvre la passerelle sur https://localhost:8443 (mTLS) depuis le serveur"
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.llm.id} --document-name AWS-StartPortForwardingSession --parameters portNumber=8443,localPortNumber=8443"
}
