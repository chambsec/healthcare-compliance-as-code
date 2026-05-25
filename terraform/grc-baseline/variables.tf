variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "aws_profile" {
  type    = string
  default = "default"
}

variable "starter_uploads_bucket_id" {
  type        = string
  description = "The ID of the starter's uploads bucket (from starter outputs)."
}

variable "starter_uploads_bucket_arn" {
  type        = string
  description = "The ARN of the starter's uploads bucket (from starter outputs)."
}

variable "starter_dynamodb_table_arn" {
  type        = string
  description = "The ARN of the starter's DynamoDB table (from starter outputs)."
}

variable "starter_lambda_role_id" {
  type        = string
  description = "The ID of the starter's Lambda IAM role."
}

variable "starter_lambda_function_name" {
  type        = string
  description = "The name of the starter's Lambda function."
}

variable "starter_private_subnet_ids" {
  type        = list(string)
  description = "Private subnet IDs from the starter VPC."
}

variable "starter_vpc_id" {
  type        = string
  description = "VPC ID from the starter."
}