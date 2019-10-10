#
# EKS Cluster Resources
#  * IAM Role to allow EKS service to manage other AWS services
#  * EC2 Security Group to allow networking traffic with EKS cluster
#  * EKS Cluster
#

resource "aws_iam_role" "demo-cluster" {
  name = "terraform-eks-demo-cluster"

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

resource "aws_iam_role_policy_attachment" "demo-cluster-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = "${aws_iam_role.demo-cluster.name}"
}

resource "aws_iam_role_policy_attachment" "demo-cluster-AmazonEKSServicePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = "${aws_iam_role.demo-cluster.name}"
}

resource "aws_security_group" "demo-cluster" {
  name        = "terraform-eks-demo-cluster"
  description = "Cluster communication with worker nodes"
  vpc_id      = "${var.vpc}"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "terraform-eks-demo"
  }
}

resource "aws_security_group_rule" "demo-cluster-ingress-node-https" {
  description              = "Allow pods to communicate with the cluster API Server"
  from_port                = 443
  protocol                 = "tcp"
  security_group_id        = "${aws_security_group.demo-cluster.id}"
  source_security_group_id = "${aws_security_group.demo-node.id}"
  to_port                  = 443
  type                     = "ingress"
}

resource "aws_security_group_rule" "demo-cluster-ingress-workstation-https" {
  cidr_blocks       = ["${local.workstation-external-cidr}"]
  description       = "Allow workstation to communicate with the cluster API Server"
  from_port         = 443
  protocol          = "tcp"
  security_group_id = "${aws_security_group.demo-cluster.id}"
  to_port           = 443
  type              = "ingress"
}

resource "aws_eks_cluster" "demo" {
  name     = "${var.cluster-name}"
  role_arn = "${aws_iam_role.demo-cluster.arn}"

  vpc_config {
    security_group_ids = ["${aws_security_group.demo-cluster.id}"]
    subnet_ids         = "${aws_subnet.demo[*].id}"
  }

  depends_on = [
    "aws_iam_role_policy_attachment.demo-cluster-AmazonEKSClusterPolicy",
    "aws_iam_role_policy_attachment.demo-cluster-AmazonEKSServicePolicy",
  ]
}
