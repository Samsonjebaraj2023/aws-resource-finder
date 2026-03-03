from flask import Flask, request, jsonify
from flask_cors import CORS
import boto3, botocore, concurrent.futures

app = Flask(__name__)
CORS(app)

ALL_REGIONS = [
    "us-east-1","us-east-2","us-west-1","us-west-2",
    "eu-west-1","eu-west-2","eu-west-3","eu-central-1",
    "eu-north-1","eu-south-1","ap-southeast-1","ap-southeast-2",
    "ap-northeast-1","ap-northeast-2","ap-northeast-3","ap-south-1",
    "sa-east-1","ca-central-1","me-south-1","af-south-1"
]

def get_session(ak, sk, st=None):
    return boto3.Session(
        aws_access_key_id=ak,
        aws_secret_access_key=sk,
        aws_session_token=st or None
    )

def detect_type(rid):
    rid = rid.strip()
    if   rid.startswith("vpc-"):        return "vpc"
    elif rid.startswith("subnet-"):     return "subnet"
    elif rid.startswith("sg-"):         return "security_group"
    elif rid.startswith("i-"):          return "ec2_instance"
    elif rid.startswith("vol-"):        return "volume"
    elif rid.startswith("snap-"):       return "snapshot"
    elif rid.startswith("ami-"):        return "ami"
    elif rid.startswith("nat-"):        return "nat_gateway"
    elif rid.startswith("igw-"):        return "internet_gateway"
    elif rid.startswith("rtb-"):        return "route_table"
    elif rid.startswith("eni-"):        return "network_interface"
    elif rid.startswith("eipalloc-"):   return "elastic_ip"
    elif rid.startswith("s3://"):       return "s3_bucket"
    else:                               return "unknown"

def tag_name(obj):
    return next((t["Value"] for t in obj.get("Tags", []) if t["Key"] == "Name"), "N/A")

# ─────────────────────────────────────────────
#  Per-resource search functions
# ─────────────────────────────────────────────

def search_vpc(ec2, rid):
    items = ec2.describe_vpcs(VpcIds=[rid]).get("Vpcs", [])
    if not items: return {"found": False}
    v = items[0]
    return {"found": True, "type": "VPC", "id": v["VpcId"], "details": {
        "Name": tag_name(v), "CIDR": v["CidrBlock"], "State": v["State"],
        "IsDefault": v["IsDefault"], "InstanceTenancy": v.get("InstanceTenancy"),
        "DhcpOptionsId": v.get("DhcpOptionsId"), "Tags": v.get("Tags", [])}}

def search_subnet(ec2, rid):
    items = ec2.describe_subnets(SubnetIds=[rid]).get("Subnets", [])
    if not items: return {"found": False}
    s = items[0]
    return {"found": True, "type": "Subnet", "id": s["SubnetId"], "details": {
        "Name": tag_name(s), "VpcId": s["VpcId"], "CIDR": s["CidrBlock"],
        "AvailabilityZone": s["AvailabilityZone"], "State": s["State"],
        "AvailableIPs": s["AvailableIpAddressCount"],
        "MapPublicIpOnLaunch": s.get("MapPublicIpOnLaunch"),
        "Tags": s.get("Tags", [])}}

def search_security_group(ec2, rid):
    items = ec2.describe_security_groups(GroupIds=[rid]).get("SecurityGroups", [])
    if not items: return {"found": False}
    sg = items[0]
    return {"found": True, "type": "Security Group", "id": sg["GroupId"], "details": {
        "Name": sg["GroupName"], "Description": sg["Description"],
        "VpcId": sg.get("VpcId"),
        "InboundRules": len(sg.get("IpPermissions", [])),
        "OutboundRules": len(sg.get("IpPermissionsEgress", [])),
        "Tags": sg.get("Tags", [])}}

def search_ec2_instance(ec2, rid):
    reservations = ec2.describe_instances(InstanceIds=[rid]).get("Reservations", [])
    if not reservations: return {"found": False}
    inst = reservations[0]["Instances"][0]
    return {"found": True, "type": "EC2 Instance", "id": inst["InstanceId"], "details": {
        "Name": tag_name(inst), "State": inst["State"]["Name"],
        "InstanceType": inst["InstanceType"],
        "PublicIp": inst.get("PublicIpAddress", "N/A"),
        "PrivateIp": inst.get("PrivateIpAddress", "N/A"),
        "VpcId": inst.get("VpcId"), "SubnetId": inst.get("SubnetId"),
        "AMI": inst.get("ImageId"), "LaunchTime": str(inst.get("LaunchTime")),
        "Tags": inst.get("Tags", [])}}

def search_volume(ec2, rid):
    items = ec2.describe_volumes(VolumeIds=[rid]).get("Volumes", [])
    if not items: return {"found": False}
    v = items[0]
    return {"found": True, "type": "EBS Volume", "id": v["VolumeId"], "details": {
        "Name": tag_name(v), "State": v["State"],
        "Size": f"{v['Size']} GiB", "VolumeType": v["VolumeType"],
        "AvailabilityZone": v["AvailabilityZone"],
        "Encrypted": v["Encrypted"],
        "MultiAttach": v.get("MultiAttachEnabled", False),
        "Tags": v.get("Tags", [])}}

# ── FIX 1: Snapshot ──────────────────────────
def search_snapshot(ec2, rid):
    items = ec2.describe_snapshots(SnapshotIds=[rid]).get("Snapshots", [])
    if not items: return {"found": False}
    s = items[0]
    return {"found": True, "type": "Snapshot", "id": s["SnapshotId"], "details": {
        "Name": tag_name(s),
        "State": s["State"],
        "VolumeId": s.get("VolumeId", "N/A"),
        "VolumeSize": f"{s.get('VolumeSize','?')} GiB",
        "OwnerId": s.get("OwnerId"),
        "Encrypted": s.get("Encrypted", False),
        "StartTime": str(s.get("StartTime")),
        "Progress": s.get("Progress", "N/A"),
        "Description": s.get("Description", ""),
        "Tags": s.get("Tags", [])}}

# ── FIX 2: AMI ──────────────────────────────
def search_ami(ec2, rid):
    items = ec2.describe_images(ImageIds=[rid]).get("Images", [])
    if not items: return {"found": False}
    a = items[0]
    return {"found": True, "type": "AMI", "id": a["ImageId"], "details": {
        "Name": a.get("Name", "N/A"),
        "State": a.get("State"),
        "Architecture": a.get("Architecture"),
        "Platform": a.get("PlatformDetails", a.get("Platform", "Linux/UNIX")),
        "VirtualizationType": a.get("VirtualizationType"),
        "RootDeviceType": a.get("RootDeviceType"),
        "RootDeviceName": a.get("RootDeviceName"),
        "OwnerId": a.get("OwnerId"),
        "Public": a.get("Public", False),
        "CreationDate": a.get("CreationDate"),
        "Description": a.get("Description", ""),
        "Tags": a.get("Tags", [])}}

# ── FIX 3: NAT Gateway ──────────────────────
def search_nat_gateway(ec2, rid):
    items = ec2.describe_nat_gateways(NatGatewayIds=[rid]).get("NatGateways", [])
    if not items: return {"found": False}
    n = items[0]
    addrs = n.get("NatGatewayAddresses", [{}])
    first = addrs[0] if addrs else {}
    return {"found": True, "type": "NAT Gateway", "id": n["NatGatewayId"], "details": {
        "Name": tag_name(n),
        "State": n.get("State"),
        "ConnectivityType": n.get("ConnectivityType", "public"),
        "VpcId": n.get("VpcId"),
        "SubnetId": n.get("SubnetId"),
        "PublicIp": first.get("PublicIp", "N/A"),
        "PrivateIp": first.get("PrivateIp", "N/A"),
        "AllocationId": first.get("AllocationId", "N/A"),
        "NetworkInterfaceId": first.get("NetworkInterfaceId", "N/A"),
        "CreateTime": str(n.get("CreateTime")),
        "Tags": n.get("Tags", [])}}

# ── FIX 4: Internet Gateway ──────────────────
def search_igw(ec2, rid):
    items = ec2.describe_internet_gateways(InternetGatewayIds=[rid]).get("InternetGateways", [])
    if not items: return {"found": False}
    igw = items[0]
    attachments = igw.get("Attachments", [])
    attached_vpcs = [a["VpcId"] for a in attachments if a.get("State") == "available"]
    return {"found": True, "type": "Internet Gateway", "id": igw["InternetGatewayId"], "details": {
        "Name": tag_name(igw),
        "OwnerId": igw.get("OwnerId"),
        "State": attachments[0].get("State", "detached") if attachments else "detached",
        "AttachedVPCs": ", ".join(attached_vpcs) if attached_vpcs else "None",
        "AttachmentCount": len(attachments),
        "Tags": igw.get("Tags", [])}}

# ── FIX 5: Route Table ───────────────────────
def search_route_table(ec2, rid):
    items = ec2.describe_route_tables(RouteTableIds=[rid]).get("RouteTables", [])
    if not items: return {"found": False}
    rt = items[0]
    routes = rt.get("Routes", [])
    assoc = rt.get("Associations", [])
    main_assoc = any(a.get("Main") for a in assoc)
    subnet_assocs = [a["SubnetId"] for a in assoc if a.get("SubnetId")]
    return {"found": True, "type": "Route Table", "id": rt["RouteTableId"], "details": {
        "Name": tag_name(rt),
        "VpcId": rt.get("VpcId"),
        "IsMain": main_assoc,
        "RouteCount": len(routes),
        "AssociatedSubnets": len(subnet_assocs),
        "SubnetIds": ", ".join(subnet_assocs) if subnet_assocs else "None",
        "OwnerId": rt.get("OwnerId"),
        "Tags": rt.get("Tags", [])}}

# ── FIX 6: ENI (Network Interface) ──────────
def search_eni(ec2, rid):
    items = ec2.describe_network_interfaces(NetworkInterfaceIds=[rid]).get("NetworkInterfaces", [])
    if not items: return {"found": False}
    eni = items[0]
    private_ips = [ip["PrivateIpAddress"] for ip in eni.get("PrivateIpAddresses", [])]
    assoc = eni.get("Association", {})
    return {"found": True, "type": "Network Interface (ENI)", "id": eni["NetworkInterfaceId"], "details": {
        "Name": tag_name(eni),
        "Status": eni.get("Status"),
        "Description": eni.get("Description", ""),
        "InterfaceType": eni.get("InterfaceType"),
        "AvailabilityZone": eni.get("AvailabilityZone"),
        "VpcId": eni.get("VpcId"),
        "SubnetId": eni.get("SubnetId"),
        "PrivateIp": eni.get("PrivateIpAddress"),
        "AllPrivateIps": ", ".join(private_ips),
        "PublicIp": assoc.get("PublicIp", "N/A"),
        "MacAddress": eni.get("MacAddress"),
        "SourceDestCheck": eni.get("SourceDestCheck"),
        "AttachedInstance": eni.get("Attachment", {}).get("InstanceId", "N/A"),
        "OwnerId": eni.get("OwnerId"),
        "Tags": eni.get("Tags", [])}}

# ── FIX 7: Elastic IP ────────────────────────
def search_elastic_ip(ec2, rid):
    # rid is an AllocationId (eipalloc-xxx)
    items = ec2.describe_addresses(AllocationIds=[rid]).get("Addresses", [])
    if not items: return {"found": False}
    e = items[0]
    return {"found": True, "type": "Elastic IP", "id": e["AllocationId"], "details": {
        "Name": tag_name(e),
        "PublicIp": e.get("PublicIp"),
        "PrivateIp": e.get("PrivateIpAddress", "N/A"),
        "Domain": e.get("Domain"),
        "AssociationId": e.get("AssociationId", "Not associated"),
        "AssociatedInstance": e.get("InstanceId", "N/A"),
        "NetworkInterfaceId": e.get("NetworkInterfaceId", "N/A"),
        "NetworkBorderGroup": e.get("NetworkBorderGroup"),
        "PublicIpv4Pool": e.get("PublicIpv4Pool"),
        "Tags": e.get("Tags", [])}}

# ─────────────────────────────────────────────
#  Router: dispatch to correct search function
# ─────────────────────────────────────────────

SEARCH_FN_MAP = {
    "vpc":               search_vpc,
    "subnet":            search_subnet,
    "security_group":    search_security_group,
    "ec2_instance":      search_ec2_instance,
    "volume":            search_volume,
    "snapshot":          search_snapshot,
    "ami":               search_ami,
    "nat_gateway":       search_nat_gateway,
    "internet_gateway":  search_igw,
    "route_table":       search_route_table,
    "network_interface": search_eni,
    "elastic_ip":        search_elastic_ip,
}

def search_in_region(session, region, rid, rtype):
    fn = SEARCH_FN_MAP.get(rtype)
    if not fn:
        return region, {"found": False, "error": f"No handler for type: {rtype}"}
    try:
        ec2 = session.client("ec2", region_name=region)
        return region, fn(ec2, rid)
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        # These codes mean "not in this region", not an auth error
        NOT_FOUND_CODES = {
            "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
            "InvalidGroup.NotFound", "InvalidInstanceID.NotFound",
            "InvalidVolume.NotFound", "InvalidSnapshot.NotFound",
            "InvalidAMIID.NotFound", "InvalidNatGatewayID.NotFound",
            "InvalidInternetGatewayID.NotFound", "InvalidRouteTableID.NotFound",
            "InvalidNetworkInterfaceID.NotFound", "InvalidAllocationID.NotFound",
            "InvalidParameterValue", "InvalidAMIID.Unavailable",
        }
        if code in NOT_FOUND_CODES:
            return region, {"found": False}
        # For unexpected errors, bubble up the code so we can debug
        return region, {"found": False, "error": f"{code}: {e.response['Error']['Message']}"}
    except Exception as e:
        return region, {"found": False, "error": str(e)}

def search_single_resource(session, rid):
    rid = rid.strip()
    rtype = detect_type(rid)

    if rtype == "unknown":
        return {
            "resource_id": rid, "success": False,
            "error": "Unrecognized prefix. Supported: vpc-, subnet-, sg-, i-, vol-, snap-, ami-, nat-, igw-, rtb-, eni-, eipalloc-, s3://"
        }

    if rtype == "s3_bucket":
        try:
            bucket = rid.replace("s3://", "").strip("/")
            s3 = session.client("s3", region_name="us-east-1")
            buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
            if bucket not in buckets:
                return {"resource_id": rid, "success": False, "error": "S3 bucket not found"}
            loc = s3.get_bucket_location(Bucket=bucket).get("LocationConstraint") or "us-east-1"
            return {"resource_id": rid, "success": True, "resource_type": "S3 Bucket",
                    "region": loc, "details": {"Name": bucket, "Region": loc}, "regions_searched": 1}
        except Exception as e:
            return {"resource_id": rid, "success": False, "error": str(e)}

    found_result = found_region = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(search_in_region, session, r, rid, rtype): r for r in ALL_REGIONS}
        for future in concurrent.futures.as_completed(futures):
            region, result = future.result()
            if result.get("found"):
                found_result, found_region = result, region
                for f in futures: f.cancel()
                break

    if found_result:
        return {"resource_id": rid, "success": True,
                "resource_type": found_result["type"], "region": found_region,
                "details": found_result["details"], "regions_searched": len(ALL_REGIONS)}

    return {"resource_id": rid, "success": False,
            "error": f"Not found in any of {len(ALL_REGIONS)} regions. Check the ID is correct and your credentials have ec2:Describe* permissions.",
            "regions_searched": len(ALL_REGIONS)}

# ─────────────────────────────────────────────
#  API Routes
# ─────────────────────────────────────────────

@app.route("/api/validate", methods=["POST"])
def validate():
    d = request.json
    try:
        sess = get_session(d.get("access_key",""), d.get("secret_key",""), d.get("session_token",""))
        identity = sess.client("sts", region_name="us-east-1").get_caller_identity()
        return jsonify({"success": True, "account_id": identity["Account"],
                        "user_arn": identity["Arn"], "user_id": identity["UserId"]})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 401

@app.route("/api/search", methods=["POST"])
def search():
    d = request.json
    raw_ids = d.get("resource_ids", d.get("resource_id", ""))
    if isinstance(raw_ids, list):
        ids = [r.strip() for r in raw_ids if r.strip()]
    else:
        ids = [r.strip() for r in str(raw_ids).split(",") if r.strip()]

    if not ids:
        return jsonify({"success": False, "error": "At least one resource ID is required"}), 400

    sess = get_session(d.get("access_key",""), d.get("secret_key",""), d.get("session_token","") or None)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ids), 10)) as ex:
        futures = {ex.submit(search_single_resource, sess, rid): rid for rid in ids}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    id_order = {rid: i for i, rid in enumerate(ids)}
    results.sort(key=lambda r: id_order.get(r["resource_id"], 999))

    found_count = sum(1 for r in results if r.get("success"))
    return jsonify({
        "success": True, "total": len(ids),
        "found": found_count, "not_found": len(ids) - found_count,
        "results": results
    })

@app.route("/api/regions", methods=["GET"])
def regions_list():
    return jsonify({"regions": ALL_REGIONS, "count": len(ALL_REGIONS)})

if __name__ == "__main__":
    app.run(debug=True, port=5002)
