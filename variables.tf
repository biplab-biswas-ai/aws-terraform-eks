#
# Variables Configuration
#

variable "cluster-name" {
  default = "bt-eks-cicd-tooling-cluster"
  type    = "string"
}

variable "instance_type" {
  default = "m4.large"
  type    = "string"
}

variable "vpc" {
  description = "existing VPC id"
  default     = "place the vpc_id here"
}
