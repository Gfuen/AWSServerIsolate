import argparse
import boto3
from botocore.exceptions import ClientError

def check_instance(instance_id, region):
    # Create EC2 client
    ec2_client = boto3.client('ec2', region_name=region)
    
    # Get instance information
    instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])

    # Check if instance exists
    if not instance_info['Reservations']:
        print("Instance not found.")
        exit()
    else:
        print("Instance Found!")
   

def detach_instance_role(instance_id, region):
    # Create EC2 client
    ec2_client = boto3.client('ec2', region_name=region)
    
    # Get instance information
    instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])

    # Detach instance IAM role
    try:
        # Get the instance's IAM instance profile ARN if it exists
        instance_profile_arn = instance_info['Reservations'][0]['Instances'][0].get('IamInstanceProfile', {}).get('Arn')

        # If no IAM instance profile is attached, print message and return
        if not instance_profile_arn:
            print("Instance doesn't have an IAM instance profile attached.")
            return

        response = ec2_client.disassociate_iam_instance_profile(
            AssociationId=instance_id
        )
        print("IAM role detached successfully.")
    except Exception as e:
        print("Failed to detach IAM role:", e)

def get_vpc_id(instance_id, region):
    ec2 = boto3.client('ec2', region_name=region)

    # Describe the instance
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance_info = response['Reservations'][0]['Instances'][0]
    except (IndexError, KeyError):
        print("Instance not found or does not have VPC information.")
        return None

    # Get the VPC ID
    vpc_id = instance_info.get('VpcId')

    if vpc_id:
        print(f"VPC ID for instance {instance_id}: {vpc_id}")
    else:
        print(f"Instance {instance_id} is not associated with any VPC.")

    return vpc_id

def detach_security_groups(instance_id, region):
    # Create EC2 client
    ec2_client = boto3.client('ec2', region_name=region)

    # Get instance information
    instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])

    # Detach instance security groups
    try:
        # Get the instance's security groups
        security_groups = instance_info['Reservations'][0]['Instances'][0].get('SecurityGroups', [])

        print("Security Groups found: ", security_groups)

        # Get the NoAccess security group ID
        default_sg_id = None
        for sg in security_groups:
            if sg['GroupName'] == 'NoAccessSecurityGroup':
                default_sg_id = sg['GroupId']
                break
                
        # Remove all security groups except the NoAccess one
        for sg in security_groups:
            if sg['GroupId'] != default_sg_id:
                ec2_client.modify_instance_attribute(
                    InstanceId=instance_id,
                    Groups=[default_sg_id]
                )
                print(f"Security group {sg['GroupName']} ({sg['GroupId']}) removed successfully.")

        print("Security groups detached successfully.")
    except Exception as e:
        print("Failed to detach security groups:", e)

def create_noaccess_security_group(vpc_id, region):
    ec2 = boto3.client('ec2', region_name=region)

    # Create security group
    response = ec2.create_security_group(
        Description='Security group with no inbound or outbound access',
        GroupName='NoAccessSecurityGroup',
        VpcId=vpc_id  
    )

    # Get security group ID
    security_group_id = response['GroupId']
    print(f"Security group created with ID: {security_group_id}")

    # Deny all inbound traffic
    ec2.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 1,
                'ToPort': 1,
                'IpRanges': [{'CidrIp': '0.0.0.0/32'}],
            }
        ]
    )

    # Deny all outbound traffic
    ec2.authorize_security_group_egress(
        GroupId=security_group_id,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 1,
                'ToPort': 1,
                'IpRanges': [{'CidrIp': '0.0.0.0/32'}],
            }
        ]
    )

    print("Inbound and outbound rules added to deny all traffic.")
    return security_group_id

def attach_noaccess_security_group(instance_id, security_group_id, region):
    ec2 = boto3.client('ec2', region_name=region)

    # Attach security group to instance
    response = ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[security_group_id]
    )

    print(f"Security group {security_group_id} attached to instance {instance_id}.")


def remove_public_ip(instance_id, region):
    # Create EC2 client
    ec2_client = boto3.client('ec2', region_name=region)

    # Get instance information
    instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])

    # Modify instance to remove public IP
    try:
        # Check if the instance has a public IP address
        if 'PublicIpAddress' not in instance_info:
            print("Instance does not have a public IP address.")
            return

        public_ip = instance_info['PublicIpAddress']

        # Disassociate the public IP address
        try:
            association_id = instance_info['NetworkInterfaces'][0]['Association']['AssociationId']
            ec2_client.disassociate_address(AssociationId=association_id)
            print(f"Public IP address {public_ip} disassociated successfully.")
        except (IndexError, KeyError):
            print("Error disassociating public IP address.")
    except Exception as e:
        print("Failed to remove public IP:", e)

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

    check_instance(instance_id, region)
    detach_instance_role(instance_id, region)
    remove_public_ip(instance_id, region)
    vpc_id = get_vpc_id(instance_id, region)
    sgroup_id = create_noaccess_security_group(vpc_id, region)
    attach_noaccess_security_group(instance_id, sgroup_id, region)
    detach_security_groups(instance_id, region)
