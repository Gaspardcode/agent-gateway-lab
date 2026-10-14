variable "region" {
  type    = string
  default = "eu-north-1"
}

variable "project" {
  type    = string
  default = "agl"
}

variable "vpc_cidr" {
  type    = string
  default = "10.30.0.0/16"
}

variable "instance_type" {
  description = "m7i-flex.large : 2 vCPU, 8 Go, éligible au free plan. Le modèle 3B Q4 tient en environ 3 Go."
  type        = string
  default     = "m7i-flex.large"
}

variable "context_size" {
  type    = number
  default = 8192
}

variable "idle_minutes" {
  type    = number
  default = 60
  validation {
    condition     = var.idle_minutes >= 10 && var.idle_minutes % 5 == 0
    error_message = "Multiple de 5, au moins 10."
  }
}

variable "alert_email" {
  description = "Adresse qui reçoit les alarmes (confirmation par e-mail). Vide = pas d'abonnement."
  type        = string
  default     = ""
}
