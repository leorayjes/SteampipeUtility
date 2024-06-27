import boto3
import os
import logging

organizations_client = boto3.client('organizations')
sts_client = boto3.client('sts')
ssm_client = boto3.client('ssm')

role_name = ""
# external_id = ssm_client.get_parameter_by_path(
#     Name="/steampipe/role/external_id",
#     WithDecryption=True 
# )['Parameter']['Value']
external_id = ""
accounts = organizations_client.list_accounts()['Accounts']

def get_current_context(sts_client):
    print(sts_client.get_caller_identity())

def generate_profiles(accounts, role_name, external_id):
    profile_template = """
[{profile_name}]
role_arn = {role_arn}
source_profile = default
external_id = {external_id}
""" 
    profiles = ""
    for account in accounts:
        account_id = account["Id"]
        profile_block = profile_template.format(
            profile_name=f"aws_{account_id}",
            role_arn=f"arn:aws:iam::{account_id}:role/{role_name}",
            source_profile="default",
            external_id=external_id
        )
        profiles += "\n" + profile_block
    
    return profiles.strip()

def generate_connections(accounts, regions):
    connection_template = """
connection "{connection_name}" {{
  plugin  = "aws"
  profile = {profile}
  regions = {regions}
}}
"""
    aggregate_connection = """
connection "aws_all" {{
  plugin  = "aws"
  profile = "aws_*"
  regions = "*"
}}
"""
    connections = ""
    connections += "\n" + aggregate_connection
    for account in accounts:
        account_id = account["Id"]
        connection_block = connection_template.format(
            connection_name=f"aws_{account_id}",
            plugin="aws",
            profile=f"aws_{account_id}",
            regions=str(regions).replace("'", '"')
        )
        connections += connection_block + "\n"

    return connections.strip()

regions = ["*"]

connections_result = generate_connections(accounts, regions)
profiles_result = generate_profiles(accounts, role_name, external_id)

aws_credentials_file_path = os.path.expanduser("~/.aws/credentials")
# steampipe_credentials_file_path = os.path.expanduser("~/.steampipe/config/aws.spc")
steampipe_credentials_file_path = os.path.expanduser("//wsl.localhost/Ubuntu/home/jesse/.steampipe/config/aws.spc")
# Write the configuration content to the AWS credentials file
with open(aws_credentials_file_path, 'a') as credentials_file:
    credentials_file.write(profiles_result)

# Write the configuration content to the Steampipe credentials file
with open(steampipe_credentials_file_path, 'a') as steampipe_credentials_file:
    steampipe_credentials_file.write(connections_result)

print(f"Configuration written to {aws_credentials_file_path}")
print(f"Configuration written to {steampipe_credentials_file_path}")
