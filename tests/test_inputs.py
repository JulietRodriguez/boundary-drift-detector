"""Reading declared boundaries and actual inventories."""

import json

import pytest

from boundary_drift_detector.actual import config_item_to_resource, load_actual, terraform_to_resources
from boundary_drift_detector.awstypes import arn_account, arn_region, arn_resource_id, normalize_type
from boundary_drift_detector.declared import InputError, load_boundary
from tests.conftest import COMPAT, SAMPLES

# --- types and ARNs ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "out"),
    [("aws_s3_bucket", "AWS::S3::Bucket"), ("aws::s3::bucket", "AWS::S3::Bucket"), ("AWS::Foo::Bar", "AWS::Foo::Bar"),
     ("", ""), (None, ""), ("custom", "custom")],
)  # fmt: skip
def test_normalize_type(raw, out):
    assert normalize_type(raw) == out


def test_arn_parts():
    a = "arn:aws:ec2:us-east-1:111122223333:instance/i-1"
    assert (arn_region(a), arn_account(a), arn_resource_id(a)) == ("us-east-1", "111122223333", "i-1")
    assert arn_region("arn:aws:s3:::bucket") is None and arn_resource_id("arn:aws:s3:::bucket") == "bucket"
    assert arn_region("not-an-arn") is None and arn_account(None) is None
    assert arn_resource_id("arn:aws:rds:us-east-1:1:db:mydb") == "mydb"
    assert arn_region("arn:aws") is None


# --- declared --------------------------------------------------------------------------------------


def test_load_yaml_boundary():
    b = load_boundary(SAMPLES / "boundary.yaml")
    assert b.name.startswith("SYNTHETIC") and len(b.resources) == 9
    assert b.regions == {"us-east-1"} and b.accounts == {"111122223333"}
    assert b.expect_encrypted is True and b.expect_public is False
    bucket = b.resources[0]
    assert (bucket.type, bucket.id, bucket.arn) == (
        "AWS::S3::Bucket",
        "cms-demo-case-files",
        "arn:aws:s3:::cms-demo-case-files",
    )
    alb = next(r for r in b.resources if r.name == "cms-demo-alb")
    assert alb.public is True and alb.region == "us-east-1"


def test_load_ssp_boundary():
    b = load_boundary(SAMPLES / "ssp.json")
    assert len(b.resources) == 9 and b.ssp_uuid
    assert all(r.ref for r in b.resources)
    db = next(r for r in b.resources if r.type == "AWS::RDS::DBInstance")
    assert db.encrypted is True and db.public is False and db.name == "cms-demo-db"


def test_ssp_from_oscal_ssp_generator():
    b = load_boundary(COMPAT / "oscal-ssp-generator_ssp.json")
    assert len(b.resources) == 10
    assert {r.type for r in b.resources} >= {"AWS::S3::Bucket", "AWS::KMS::Key"}  # terraform type names normalized


@pytest.mark.parametrize(
    ("name", "content", "message"),
    [
        ("b.json", "{bad", "not valid JSON"),
        ("b.yaml", "a: [", "not valid YAML"),
        ("b.yaml", "- 1", "mapping at the top level"),
        ("b.yaml", "hello: 1", "not an OSCAL SSP or a boundary"),
        ("b.yaml", "boundary: {}", "boundary.name is required"),
        ("b.yaml", "boundary: {name: x}\nresources: 5", "resources must be a list"),
        ("b.yaml", "boundary: {name: x}\nresources: [{type: AWS::S3::Bucket}]", "needs an id"),
        ("b.yaml", "boundary: {name: x}\nresources: [{id: abc}]", "resource type is required"),
        ("b.yaml", "boundary: {name: x}\nresources: [{id: abc, type: t, public: maybe}]", "expected yes/no"),
        ("b.json", {"system-security-plan": {}}, "no system-implementation/inventory-items"),
        (
            "b.json",
            {"system-security-plan": {"system-implementation": {"inventory-items": [{"props": []}]}}},
            "asset-id",
        ),
    ],
)
def test_boundary_errors(write, name, content, message):
    with pytest.raises(InputError, match=message):
        load_boundary(write(name, content))


def test_boundary_missing_file(tmp_path):
    with pytest.raises(InputError, match="file not found"):
        load_boundary(tmp_path / "x.yaml")


# --- AWS Config ------------------------------------------------------------------------------------


def ci(rtype, cfg=None, supp=None, **kw):
    return {"resourceType": rtype, "resourceId": "r1", "awsRegion": "us-east-1", "configuration": cfg or {},
            "supplementaryConfiguration": supp or {}, **kw}  # fmt: skip


PAB_ON = {"blockPublicAcls": True, "ignorePublicAcls": True, "blockPublicPolicy": True, "restrictPublicBuckets": True}


@pytest.mark.parametrize(
    ("item", "encrypted", "public"),
    [
        (ci("AWS::S3::Bucket", supp={"PublicAccessBlockConfiguration": json.dumps(PAB_ON),
                                     "ServerSideEncryptionConfiguration": {"rules": []}}), True, False),
        (ci("AWS::S3::Bucket"), None, None),
        (ci("AWS::S3::Bucket", supp={"AccessControlList": {"grantList": [{"grantee": "AllUsers"}]}}), None, True),
        (ci("AWS::S3::Bucket", supp={"BucketPolicy": {"policyText": json.dumps({"Statement": {
            "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}})}}), None, True),
        (ci("AWS::S3::Bucket", supp={"BucketPolicy": {"policyText": json.dumps({"Statement": [{
            "Effect": "Allow", "Principal": "*", "Condition": {"IpAddress": {}}}]})}}), None, False),
        (ci("AWS::EC2::Volume", {"encrypted": False}), False, None),
        (ci("AWS::EC2::Instance", {"publicIpAddress": "3.3.3.3"}), None, True),
        (ci("AWS::EC2::Instance", {"networkInterfaces": []}), None, False),
        (ci("AWS::EC2::Instance", {}), None, None),
        (ci("AWS::RDS::DBInstance", {"storageEncrypted": True, "publiclyAccessible": True}), True, True),
        (ci("AWS::ElasticLoadBalancingV2::LoadBalancer", {"scheme": "internal"}), None, False),
        (ci("AWS::ElasticLoadBalancingV2::LoadBalancer", {}), None, None),
        (ci("AWS::EC2::SecurityGroup", {"ipPermissions": [{"ipRanges": ["0.0.0.0/0"]}]}), None, True),
        (ci("AWS::EC2::SecurityGroup", {"ipPermissions": [{"ipv6Ranges": [{"cidrIpv6": "::/0"}]}]}), None, True),
        (ci("AWS::EC2::SecurityGroup", {"ipPermissions": [{"ipv4Ranges": [{"cidrIp": "10.0.0.0/8"}]}]}), None, False),
        (ci("AWS::EC2::SecurityGroup", {}), None, None),
        (ci("AWS::DynamoDB::Table"), True, False),
        (ci("AWS::EFS::FileSystem", {"Encrypted": True}), True, None),
        (ci("AWS::Lambda::Function", "not-a-dict"), None, None),
    ],
)  # fmt: skip
def test_config_attributes(item, encrypted, public):
    r = config_item_to_resource(item)
    assert (r.encrypted, r.public) == (encrypted, public)


@pytest.mark.parametrize(
    "wrap",
    [
        lambda items: {"Results": [json.dumps(i) for i in items]},
        lambda items: {"baseConfigurationItems": items},
        lambda items: {"configurationItems": items},
        lambda items: items,
    ],
)
def test_config_export_formats(write, wrap):
    items = [ci("AWS::S3::Bucket", arn="arn:aws:s3:::b", resourceName="b", accountId="1")]
    resources, fmt, skipped = load_actual(write("c.json", wrap(items)))
    assert fmt == "aws-config" and skipped == 0
    assert resources[0].arn == "arn:aws:s3:::b" and resources[0].account == "1"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{bad", "not valid JSON"),
        ({"x": 1}, "not an AWS Config export"),
        ({"configurationItems": [{"a": 1}]}, "no resourceType"),
    ],
)
def test_actual_errors(write, content, message):
    with pytest.raises(InputError, match=message):
        load_actual(write("a.json", content))


def test_actual_missing_file(tmp_path):
    with pytest.raises(InputError, match="file not found"):
        load_actual(tmp_path / "a.json")


# --- Terraform -------------------------------------------------------------------------------------


def tf(*resources):
    return {"version": 4, "resources": [
        {"mode": "managed", "type": t, "name": "n", "instances": [{"attributes": a}]} for t, a in resources]}  # fmt: skip


def test_terraform_sample_folds_helpers():
    resources, fmt, skipped = load_actual(SAMPLES / "terraform.tfstate")
    assert fmt == "terraform" and skipped == 4 and len(resources) == 9
    bucket = next(r for r in resources if r.id == "cms-demo-case-files")
    assert bucket.encrypted is True and bucket.public is False and bucket.region == "us-east-1"
    web = next(r for r in resources if r.id.endswith("0001") and r.type == "AWS::EC2::Instance")
    assert web.name == "cms-demo-web-1" and web.public is False


@pytest.mark.parametrize(
    ("tf_type", "attrs", "encrypted", "public"),
    [
        ("aws_s3_bucket", {"id": "b", "acl": "public-read"}, None, True),
        ("aws_s3_bucket", {"id": "b", "server_side_encryption_configuration": [{}]}, True, None),
        ("aws_ebs_volume", {"id": "v", "encrypted": True}, True, None),
        ("aws_instance", {"id": "i", "public_ip": "1.2.3.4"}, None, True),
        ("aws_instance", {"id": "i"}, None, None),
        ("aws_db_instance", {"id": "d", "storage_encrypted": False, "publicly_accessible": False}, False, False),
        ("aws_lb", {"id": "l", "internal": True}, None, False),
        ("aws_security_group", {"id": "s", "ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]}, None, True),
        ("aws_security_group", {"id": "s", "ingress": [{"ipv6_cidr_blocks": ["::/0"], "cidr_blocks": None}]}, None, True),
        ("aws_dynamodb_table", {"id": "t"}, True, False),
        ("aws_efs_file_system", {"id": "f", "encrypted": False}, False, None),
    ],
)  # fmt: skip
def test_terraform_attributes(tf_type, attrs, encrypted, public):
    (r,), _ = terraform_to_resources(tf((tf_type, attrs)))
    assert (r.encrypted, r.public) == (encrypted, public)


def test_terraform_show_json_and_public_access_block():
    state = {"values": {"root_module": {"resources": [
        {"mode": "managed", "type": "aws_s3_bucket", "values": {"id": "b", "region": "us-west-2"}},
        {"mode": "managed", "type": "aws_s3_bucket_public_access_block", "values": {"bucket": "b", "block_public_acls": False}},
        {"mode": "data", "type": "aws_caller_identity", "values": {}}],
        "child_modules": [{"resources": [{"mode": "managed", "type": "aws_kms_key", "values": {"id": "k"}}]}]}}}  # fmt: skip
    resources, skipped = terraform_to_resources(state)
    assert [r.type for r in resources] == ["AWS::S3::Bucket", "AWS::KMS::Key"] and skipped == 1
    assert resources[0].public is True and resources[0].region == "us-west-2"


def test_terraform_skips_data_sources():
    state = {
        "version": 4,
        "resources": [{"mode": "data", "type": "aws_s3_bucket", "instances": [{"attributes": {"id": "x"}}]}],
    }
    assert terraform_to_resources(state) == ([], 0)
