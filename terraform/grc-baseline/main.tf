terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project         = "acme-health-intake"
      ManagedBy       = "terraform"
      ComplianceScope = "hipaa"
      DataClass       = "phi"
    }
  }
}

data "aws_caller_identity" "current" {}