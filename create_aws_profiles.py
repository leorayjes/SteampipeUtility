import boto3
import os

organizations_client = boto3.client('organizations')
sts_client = boto3.client('sts')
ssm_client = boto3.client('ssm')

role_name = ""
external_id = ssm_client.get_parameter_by_path(
    Name="/steampipe/role/external_id",
    WithDecryption=True 
)['Parameter']['Value']
accounts = organizations_client.list_accounts()['Accounts']

def get_current_context(sts_client):
    print(sts_client.get_caller_identity())

def generate_profiles(accounts):
    profile_template = """
[aws_{account_name}]
role_arn = arn:aws:iam::{account_id}:role/{role_name}
source_profile = default
external_id = {external_id}
""" 
#     cli_user = """
# [cli_user]
# aws_access_key_id = ""
# aws_secret_access_key = ""
# """
    # profiles += cli_user + "\n"
    for account in accounts:
        profile_block = profile_template.format(
            account_name=account["name"],
            account_id=account["id"],
            role_name=role_name,
            external_id=external_id
        )
        profiles += profile_block + "\n"
    
    return profiles.strip()

def generate_connections(accounts, regions):
    connection_template = """
connection "aws_{account_name}" {{
  plugin  = "aws"
  profile = "aws_{account_name}"
  regions = {regions}
}}
"""
    aggregate_connection = """
connection "aws_all" {{
  plugin  = "aws"
  profile = "aws_*"
  regions = {regions}
}}
"""
    connections += aggregate_connection + "\n"
    for account in accounts:
        connection_block = connection_template.format(
            account_name=account["name"],
            profile=account["profile"],
            regions=str(regions).replace("'", '"')
        )
        connections += connection_block + "\n"

    return connections.strip()

regions = ["*"]

connections_result = generate_connections(accounts, regions)
profiles_result = generate_profiles(accounts)

aws_credentials_file_path = os.path.expanduser("~/.aws/credentials")
steampipe_credentials_file_path = os.path.expanduser("~/.steampipe/config/aws.spc")

# Write the configuration content to the AWS credentials file
with open(aws_credentials_file_path, 'w') as credentials_file:
    credentials_file.write(profiles_result)

# Write the configuration content to the Steampipe credentials file
with open(steampipe_credentials_file_path, 'w') as credentials_file:
    credentials_file.write(connections_result)

print(f"Configuration written to {aws_credentials_file_path}")
print(f"Configuration written to {steampipe_credentials_file_path}")
print(f"Connections: \n {connections_result}")
print(f"Profiles: \n {profiles_result}")
