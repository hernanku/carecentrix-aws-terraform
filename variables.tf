variable "aws_access_key" {}
variable "aws_secret_key" {}
variable "aws_region" {}
data "aws_availability_zones" "available" {}
variable "vpc_cidr" {}

variable "cidrs" {
  type = map
}

variable "key_name" {}
variable "domain_name" {}
variable "dev_instance_type" {}
variable "dev_ami" {}
variable "elb_healthy_threshold" {}
variable "elb_unhealthy_threshold" {}
variable "elb_timeout" {}
variable "elb_interval" {}
variable "asg_max" {}
variable "asg_min" {}
variable "asg_grace" {}
variable "asg_hct" {}
variable "asg_cap" {}
variable "lc_instance_type" {}
variable "delegation_set" {}

