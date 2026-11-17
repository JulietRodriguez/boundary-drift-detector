"""Resource type names and ARNs.

AWS Config uses CloudFormation-style type names (AWS::S3::Bucket); Terraform
uses its own (aws_s3_bucket). Everything is compared in the AWS Config form.
"""

from __future__ import annotations

TERRAFORM_TO_AWS = {
    "aws_s3_bucket": "AWS::S3::Bucket",
    "aws_instance": "AWS::EC2::Instance",
    "aws_ebs_volume": "AWS::EC2::Volume",
    "aws_security_group": "AWS::EC2::SecurityGroup",
    "aws_vpc": "AWS::EC2::VPC",
    "aws_subnet": "AWS::EC2::Subnet",
    "aws_internet_gateway": "AWS::EC2::InternetGateway",
    "aws_nat_gateway": "AWS::EC2::NatGateway",
    "aws_eip": "AWS::EC2::EIP",
    "aws_db_instance": "AWS::RDS::DBInstance",
    "aws_rds_cluster": "AWS::RDS::DBCluster",
    "aws_lb": "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "aws_alb": "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "aws_lambda_function": "AWS::Lambda::Function",
    "aws_dynamodb_table": "AWS::DynamoDB::Table",
    "aws_kms_key": "AWS::KMS::Key",
    "aws_iam_role": "AWS::IAM::Role",
    "aws_iam_user": "AWS::IAM::User",
    "aws_iam_policy": "AWS::IAM::Policy",
    "aws_cloudtrail": "AWS::CloudTrail::Trail",
    "aws_cloudwatch_log_group": "AWS::Logs::LogGroup",
    "aws_sns_topic": "AWS::SNS::Topic",
    "aws_sqs_queue": "AWS::SQS::Queue",
    "aws_ecr_repository": "AWS::ECR::Repository",
    "aws_ecs_cluster": "AWS::ECS::Cluster",
    "aws_eks_cluster": "AWS::EKS::Cluster",
    "aws_efs_file_system": "AWS::EFS::FileSystem",
    "aws_secretsmanager_secret": "AWS::SecretsManager::Secret",
    "aws_wafv2_web_acl": "AWS::WAFv2::WebACL",
    "aws_cloudfront_distribution": "AWS::CloudFront::Distribution",
    "aws_api_gateway_rest_api": "AWS::ApiGateway::RestApi",
    "aws_config_configuration_recorder": "AWS::Config::ConfigurationRecorder",
    "aws_guardduty_detector": "AWS::GuardDuty::Detector",
}

# Terraform resources that configure another resource rather than being one.
# Some SSP generators list them as inventory items; there is nothing in AWS
# Config to match them against, so a declared one is not compared (and counted).
TERRAFORM_SETTINGS_TYPES = frozenset(
    {
        "aws_s3_bucket_server_side_encryption_configuration",
        "aws_s3_bucket_public_access_block",
        "aws_s3_bucket_versioning",
        "aws_s3_bucket_policy",
        "aws_s3_bucket_acl",
        "aws_s3_bucket_logging",
        "aws_s3_bucket_lifecycle_configuration",
        "aws_s3_bucket_ownership_controls",
    }
)

# AWS Config records some things that are not assets of a system (compliance
# results, recovery points). They are ignored unless the boundary lists them.
DEFAULT_IGNORED_TYPES = frozenset(
    {
        "AWS::Config::ResourceCompliance",
        "AWS::Config::ConformancePackCompliance",
        "AWS::Backup::RecoveryPoint",
        "AWS::SSM::ManagedInstanceInventory",
        "AWS::SSM::PatchCompliance",
        "AWS::SSM::AssociationCompliance",
    }
)


def normalize_type(raw: str | None) -> str:
    """aws_s3_bucket / AWS::S3::Bucket / aws::s3::bucket -> AWS::S3::Bucket. Unknown values pass through."""
    if not raw:
        return ""
    text = raw.strip()
    if text in TERRAFORM_TO_AWS:
        return TERRAFORM_TO_AWS[text]
    if "::" in text:
        # keep AWS's capitalization when we know the type
        for known in TERRAFORM_TO_AWS.values():
            if known.lower() == text.lower():
                return known
        return text
    return text


def _arn_part(arn: str | None, index: int) -> str | None:
    """arn:partition:service:region:account:resource -> the part at ``index`` (None if empty or not an ARN)."""
    if not arn or not arn.startswith("arn:"):
        return None
    parts = arn.split(":", 5)
    if len(parts) <= index:
        return None
    return parts[index] or None


def arn_region(arn: str | None) -> str | None:
    return _arn_part(arn, 3)


def arn_account(arn: str | None) -> str | None:
    return _arn_part(arn, 4)


def arn_resource_id(arn: str) -> str:
    """The last part of an ARN's resource field: bucket name, instance ID, key ID, function name..."""
    resource = arn.split(":", 5)[5] if arn.count(":") >= 5 else arn
    return resource.split("/")[-1].split(":")[-1]
