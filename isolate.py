import argparse
import boto3
from botocore.exceptions import ClientError

def detach_instance_role_and_security_groups(instance_id, region):
    # Create EC2 client
    ec2_client = boto3.client('ec2', region_name=region)

    # Detach instance IAM role
    try:
        response = ec2_client.disassociate_iam_instance_profile(
            AssociationId=instance_id
        )
        print("IAM role detached successfully.")
    except Exception as e:
        print("Failed to detach IAM role:", e)

    # Detach instance security groups
    try:
        instance = ec2_client.describe_instances(InstanceIds=[instance_id])
        security_groups = [group['GroupId'] for group in instance['Reservations'][0]['Instances'][0]['SecurityGroups']]
        if security_groups:
            ec2_client.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[],
            )
            print("Security groups detached successfully.")
    except Exception as e:
        print("Failed to detach security groups:", e)

def remove_public_ip(instance_id, region):
    # Create EC2 client
    ec2_client = boto3.client('ec2', region_name=region)

    # Modify instance to remove public IP
    try:
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            NoValue=True,
            SourceDestCheck={'Value': False}
        )
        print("Public IP removed successfully.")
    except Exception as e:
        print("Failed to remove public IP:", e)

def create_subnet(vpc_id, region):
    # Create EC2 resource
    ec2_resource = boto3.resource('ec2', region_name=region)

    # Create subnet
    try:
        subnet = ec2_resource.create_subnet(
            VpcId=vpc_id,
            CidrBlock='10.0.0.0/16',  # Update with desired CIDR block
        )
        print("Subnet created successfully with ID:", subnet.id)
        return subnet.id
    except Exception as e:
        print("Failed to create subnet:", e)

def modify_subnet_permissions(subnet_id, region):
    # Create EC2 resource
    ec2_resource = boto3.resource('ec2', region_name=region)

    # Modify subnet permissions
    try:
        subnet = ec2_resource.Subnet(subnet_id)
        subnet.modify_attribute(MapPublicIpOnLaunch={'Value': False})
        print("Subnet permissions modified successfully.")
    except Exception as e:
        print("Failed to modify subnet permissions:", e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AWS isolate EC2 Server. Input EC2 instance ID for server and region.")
    parser.add_argument("--instance", help="AWS EC2 Server Instance ID")
    parser.add_argument("--region", help="AWS EC2 Server Region")
    parser.add_argument("--profile", help="AWS profile name")
    args = parser.parse_args()

    profile_name = args.profile if args.profile else None
    instance_id = args.instance
    region = args.region
    print(f"Using AWS profile: {profile_name}")
    print(f"Using AWS EC2 Server Instance ID: {instance_id}")
    print(f"Using AWS Region: {region}")

    detach_instance_role_and_security_groups(instance_id, region)
    remove_public_ip(instance_id, region)

    ec2_client = boto3.client('ec2', region_name=region)
    instance = ec2_client.describe_instances(InstanceIds=[instance_id])
    vpc_id = instance['Reservations'][0]['Instances'][0]['VpcId']

    subnet_id = create_subnet(vpc_id, region)
    modify_subnet_permissions(subnet_id, region)
