#
# EKS Worker Nodes Resources
#  * IAM role allowing Kubernetes actions to access other AWS services
#  * EC2 Security Group to allow networking traffic
#  * Data source to fetch latest EKS worker AMI
#  * AutoScaling Launch Configuration to configure worker instances
#  * AutoScaling Group to launch worker instances
#

resource "aws_iam_role" "demo-node" {
  name = "terraform-eks-demo-node"

  assume_role_policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "*",
            "Resource": "*",
            "Effect": "Allow",
            "Sid": "InitialAllow"
        },
        {
            "Action": [
                "iam:UpdateSAMLProvider",
                "iam:DeleteSAMLProvider"
            ],
            "Resource": "arn:aws:iam::*:saml-provider/BT-IDP",
            "Effect": "Deny",
            "Sid": "DenyIDPAccess"
        },
        {
            "Action": "iam:*",
            "Resource": [
                "arn:aws:iam::041063015838:role/Dcp*",
                "arn:aws:iam::041063015838:role/AWS*",
                "arn:aws:iam::041063015838:role/StackSet-AWS-Landing-Zone*"
            ],
            "Effect": "Deny",
            "Sid": "DenyRoleAccess"
        },
        {
            "Condition": {
                "StringNotEquals": {
                    "iam:PermissionsBoundary": "arn:aws:iam::041063015838:policy/DcpSandboxPermissionsBoundaryPolicy"
                }
            },
            "Action": [
                "iam:PutRolePermissionsBoundary",
                "iam:PutUserPermissionsBoundary"
            ],
            "Resource": "*",
            "Effect": "Deny",
            "Sid": "DenyPbRemoval"
        },
        {
            "Condition": {
                "StringNotEquals": {
                    "iam:PermissionsBoundary": "arn:aws:iam::041063015838:policy/DcpSandboxPermissionsBoundaryPolicy"
                }
            },
            "Action": [
                "iam:CreateRole",
                "iam:CreateUser"
            ],
            "Resource": "*",
            "Effect": "Deny",
            "Sid": "DenyUserCreation"
        },
        {
            "Action": "aws-portal:ModifyBilling",
            "Resource": "*",
            "Effect": "Deny"
        },
        {
            "Action": [
                "iam:DeleteAccountPasswordPolicy",
                "iam:UpdateAccountPasswordPolicy"
            ],
            "Resource": "*",
            "Effect": "Deny"
        },
        {
            "Action": [
                "*"
            ],
            "Resource": [
                "arn:aws:iam::041063015838:policy/StackSet-AWS-Landing-Zone*",
                "arn:aws:iam::041063015838:role/StackSet-AWS-Landing-Zone*",
                "arn:aws:iam::041063015838:policy/Dcp-*",
                "arn:aws:iam::041063015838:role/Dcp-*"
            ],
            "Effect": "Deny"
        },
        {
            "Action": [
                "cloudformation:Delete*",
                "cloudformation:Update*",
                "cloudformation:Set*",
                "cloudformation:Cancel*",
                "cloudformation:Create*",
                "cloudformation:Execute*"
            ],
            "Resource": [
                "arn:aws:cloudformation:*:041063015838:stack/StackSet-AWS-Landing-Zone-Baseline-*",
                "arn:aws:cloudformation:*:041063015838:stack/Dcp-*"
            ],
            "Effect": "Deny"
        },
        {
            "Action": [
                "cloudtrail:Delete*",
                "cloudtrail:Start*",
                "cloudtrail:Stop*",
                "cloudtrail:Update*",
                "cloudtrail:Remove*"
            ],
            "Resource": [
                "arn:aws:cloudtrail:*:041063015838:trail/Dcp-*"
            ],
            "Effect": "Deny"
        },
        {
            "Action": "*",
            "Resource": "arn:aws:logs::041063015838:log-group:CloudTrail/Landing-Zone-Logs*",
            "Effect": "Deny"
        },
        {
            "Action": [
                "cloudwatch:Delete*",
                "cloudwatch:Disable*",
                "cloudwatch:Enable*",
                "cloudwatch:Put*",
                "cloudwatch:Set*"
            ],
            "Resource": [
                "arn:aws:cloudwatch:*:041063015838:alarm:Dcp-*",
                "arn:aws:cloudwatch::041063015838:dashboard/Dcp-*"
            ],
            "Effect": "Deny"
        },
        {
            "Action": [
                "events:Delete*",
                "events:Disable*",
                "events:Enable*",
                "events:Put*",
                "events:Remove*"
            ],
            "Resource": [
                "arn:aws:events:*:041063015838:rule/Dcp-*"
            ],
            "Effect": "Deny"
        },
        {
            "Action": [
                "logs:Delete*",
                "logs:Untag*"
            ],
            "Resource": [
                "arn:aws:logs:*:041063015838:log-group:*Dcp-*"
            ],
            "Effect": "Deny"
        },
        {
            "Action": [
               "config:Delete*",
                "config:Put*",
                "config:Start*",
                "config:Stop*"
            ],
            "Resource": "*",
            "Effect": "Deny"
        },
        {
            "Action": [
                "dynamodb:Delete*",
                "dynamodb:Restore*",
                "dynamodb:Update*",
                "dynamodb:Tag*",
                "dynamodb:Untag*"
            ],
            "Resource": [
                "arn:aws:dynamodb:*:041063015838:table/Dcp-*"
            ],
            "Effect": "Deny"
        },
        {
            "Condition": {
                "StringEquals": {
                    "ec2:ResourceTag/Owner": "DCP"
                }
            },
            "Action": [
                "ec2:Delete*",
                "ec2:Update*",
                "ec2:Put*",
                "ec2:Tag*",
                "ec2:Untag*",
                "ec2:Start*",
                "ec2:Stop*"
            ],
            "Resource": [
                "arn:aws:ec2:*:041063015838:*/*"
            ],
            "Effect": "Deny"
        },
        {
            "Condition": {
                "StringLike": {
                    "elasticloadbalancing:ResourceTag/Owner": "DCP"
                }
            },
            "Action": [
                "elasticloadbalancing:Create*",
                "elasticloadbalancing:Delete*",
                "elasticloadbalancing:Add*",
                "elasticloadbalancing:Remove*",
                "elasticloadbalancing:Register*",
                "elasticloadbalancing:Set*",
                "elasticloadbalancing:Modify*"
            ],
            "Resource": [
                "arn:aws:elasticloadbalancing:*:041063015838:loadbalancer/*"
            ],
            "Effect": "Deny"
        },
        {
            "Action": [
                "lambda:Add*",
                "lambda:Remove*",
                "lambda:Delete*",
                "lambda:Publish*",
                "lambda:Tag*",
                "lambda:Untag*",
                "lambda:Update*"
            ],
            "Resource": [
                "arn:aws:lambda:*:041063015838:function:Dcp-*",
                "arn:aws:lambda:*:041063015838:function:StackSet-AWS-Landing-Zone-*"
            ],
            "Effect": "Deny"
        },
        {
            "Action": [
                "sns:Create*",
                "sns:Confirm*",
                "sns:Delete*",
                "sns:Publish*",
                "sns:Set*",
                "sns:Subscribe*",
                "sns:Unsubscribe*"
            ],
            "Resource": [
                "arn:aws:sns:*:041063015838:Dcp-*"
            ],
            "Effect": "Deny"
        },
        {
            "Action": [
                "sqs:Add*",
                "sqs:Delete*",
                "sqs:Change*",
                "sqs:Purge*",
                "sqs:Remove*",
                "sqs:Receive*",
                "sqs:Send*",
                "sqs:Set*",
                "sqs:Tag*",
                "sqs:Untag*"
            ],
            "Resource": [
                "arn:aws:sqs:*:041063015838:Dcp-*"
            ],
            "Effect": "Deny"
        },
        {
            "Action": [
                "s3:Add*",
                "s3:Put*",
                "s3:Delete*",
                "s3:Tag*",
                "s3:Untag*",
                "s3:Create*",
                "s3:Remove*"
            ],
            "Resource": [
                "arn:aws:s3:::dcp-*"
            ],
            "Effect": "Deny"
        },
        {
            "Action": [
                "ssm:Create*",
                "ssm:Delete*",
                "ssm:Put*",
                "ssm:Update*"
            ],
            "Resource": [
                "arn:aws:ssm:*:041063015838:parameter/BT/Sandbox/EndDatetime",
                "arn:aws:ssm:*:041063015838:parameter/BT/Sandbox/BillingRestriction"
            ],
            "Effect": "Deny"
        }
    ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "demo-node-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = "${aws_iam_role.demo-node.name}"
}

resource "aws_iam_role_policy_attachment" "demo-node-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = "${aws_iam_role.demo-node.name}"
}

resource "aws_iam_role_policy_attachment" "demo-node-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = "${aws_iam_role.demo-node.name}"
}

resource "aws_iam_instance_profile" "demo-node" {
  name = "terraform-eks-demo"
  role = "${aws_iam_role.demo-node.name}"
}

resource "aws_security_group" "demo-node" {
  name        = "terraform-eks-demo-node"
  description = "Security group for all nodes in the cluster"
  vpc_id      = "${var.vpc}"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = "${
    map(
     "Name", "terraform-eks-demo-node",
     "kubernetes.io/cluster/${var.cluster-name}", "owned",
    )
  }"
}

resource "aws_security_group_rule" "demo-node-ingress-self" {
  description              = "Allow node to communicate with each other"
  from_port                = 0
  protocol                 = "-1"
  security_group_id        = "${aws_security_group.demo-node.id}"
  source_security_group_id = "${aws_security_group.demo-node.id}"
  to_port                  = 65535
  type                     = "ingress"
}

resource "aws_security_group_rule" "demo-node-ingress-cluster" {
  description              = "Allow worker Kubelets and pods to receive communication from the cluster control plane"
  from_port                = 1025
  protocol                 = "tcp"
  security_group_id        = "${aws_security_group.demo-node.id}"
  source_security_group_id = "${aws_security_group.demo-cluster.id}"
  to_port                  = 65535
  type                     = "ingress"
}

data "aws_ami" "eks-worker" {
  filter {
    name   = "name"
    values = ["amazon-eks-node-${aws_eks_cluster.demo.version}-v*"]
  }

  most_recent = true
  owners      = ["602401143452"] # Amazon EKS AMI Account ID
}

# EKS currently documents this required userdata for EKS worker nodes to
# properly configure Kubernetes applications on the EC2 instance.
# We utilize a Terraform local here to simplify Base64 encoding this
# information into the AutoScaling Launch Configuration.
# More information: https://docs.aws.amazon.com/eks/latest/userguide/launch-workers.html
locals {
  demo-node-userdata = <<USERDATA
#!/bin/bash
set -o xtrace
/etc/eks/bootstrap.sh --apiserver-endpoint '${aws_eks_cluster.demo.endpoint}' --b64-cluster-ca '${aws_eks_cluster.demo.certificate_authority.0.data}' '${var.cluster-name}'
USERDATA
}

resource "aws_launch_configuration" "demo" {
  associate_public_ip_address = true
  iam_instance_profile        = "${aws_iam_instance_profile.demo-node.name}"
  image_id                    = "${data.aws_ami.eks-worker.id}"
  instance_type               = "m4.large"
  name_prefix                 = "terraform-eks-demo"
  security_groups             = ["${aws_security_group.demo-node.id}"]
  user_data_base64            = "${base64encode(local.demo-node-userdata)}"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "demo" {
  desired_capacity     = 2
  launch_configuration = "${aws_launch_configuration.demo.id}"
  max_size             = 2
  min_size             = 1
  name                 = "terraform-eks-demo"
  vpc_zone_identifier  = "${aws_subnet.demo[*].id}"

  tag {
    key                 = "Name"
    value               = "terraform-eks-demo"
    propagate_at_launch = true
  }

  tag {
    key                 = "kubernetes.io/cluster/${var.cluster-name}"
    value               = "owned"
    propagate_at_launch = true
  }
}
