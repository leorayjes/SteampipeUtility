"""
generate_steampipe_connections.py

Lists every active account in an AWS Organization, assumes a caller-supplied
IAM role in each account, and writes temporary-credential-based Steampipe
connection blocks to ~/.steampipe/config/aws.spc.

Execution order:
  1. Validate local caller identity.
  2. Assume --role_name in the management (payer) account using local credentials.
  3. Use the resulting session to list all active accounts in the organization.
  4. Assume --role_name in each child account using the parent session credentials.
  5. Write all connection blocks to ~/.steampipe/config/aws.spc.

Usage:
    python generate_steampipe_connections.py \
        --role_name <ROLE_NAME> \
        --external_id <EXTERNAL_ID> \
        --payer_account_id <MANAGEMENT_ACCOUNT_ID>

Requirements:
    - boto3
    - Caller credentials must have sts:AssumeRole permission for the
      management account role. The management account role must have
      organizations:ListAccounts and sts:AssumeRole for member accounts.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
STEAMPIPE_CONFIG_PATH = Path("~/.steampipe/config/aws.spc").expanduser()
REGIONS = ["*"]

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate Steampipe AWS connection blocks for every account in an AWS Organization."
    )
    parser.add_argument(
        "--role_name",
        required=True,
        help="Name of the IAM role to assume in each member account.",
    )
    parser.add_argument(
        "--external_id",
        required=True,
        help="External ID required when assuming the role.",
    )
    parser.add_argument(
        "--payer_account_id",
        required=True,
        help="Account ID of the AWS Organizations management (payer) account.",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# AWS helpers
# ---------------------------------------------------------------------------

def list_active_accounts(org_client) -> list[dict]:
    """Return all ACTIVE accounts in the organization."""
    LOGGER.info("Listing accounts in the organization...")
    accounts: list[dict] = []
    paginator = org_client.get_paginator("list_accounts")
    for page in paginator.paginate():
        for account in page["Accounts"]:
            if account["Status"] == "ACTIVE":
                accounts.append(account)
            else:
                LOGGER.warning(
                    "Skipping account %s (%s) – status: %s",
                    account["Id"],
                    account.get("Name", "unknown"),
                    account["Status"],
                )
    LOGGER.info("Found %d active account(s).", len(accounts))
    return accounts


def assume_role(sts_client, account_id: str, role_name: str, external_id: str) -> dict | None:
    """
    Assume *role_name* in *account_id* using *external_id*.

    Returns the Credentials dict on success, or None on failure.
    """
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    LOGGER.info("Assuming role %s in account %s...", role_arn, account_id)
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="steampipe_config_generator",
            ExternalId=external_id,
        )
        LOGGER.info("Successfully assumed role in account %s.", account_id)
        return response["Credentials"]
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        LOGGER.error(
            "ClientError assuming role in account %s (%s): %s",
            account_id,
            error_code,
            exc,
        )
    except BotoCoreError as exc:
        LOGGER.error("BotoCoreError assuming role in account %s: %s", account_id, exc)
    return None


# ---------------------------------------------------------------------------
# Connection block generation
# ---------------------------------------------------------------------------

CONNECTION_TEMPLATE = """\
connection "{connection_name}" {{
  plugin        = "aws"
  access_key    = "{access_key}"
  secret_key    = "{secret_key}"
  session_token = "{session_token}"
  regions       = {regions}
}}
"""

AGGREGATE_CONNECTION = """\
connection "aws_all" {
  type        = "aggregator"
  plugin      = "aws"
  connections = ["aws_*"]
}
"""


def build_connection_block(account_id: str, credentials: dict, regions: list[str]) -> str:
    """Render a single Steampipe HCL connection block."""
    return CONNECTION_TEMPLATE.format(
        connection_name=f"aws_{account_id}",
        access_key=credentials["AccessKeyId"],
        secret_key=credentials["SecretAccessKey"],
        session_token=credentials["SessionToken"],
        regions=str(regions).replace("'", '"'),
    )


def generate_connections(
    accounts: list[dict],
    sts_client,
    role_name: str,
    external_id: str,
    regions: list[str],
) -> tuple[str, int, int]:
    """
    Iterate over *accounts*, assume the role in each, and build HCL blocks.

    Returns:
        (full_config_string, success_count, failure_count)
    """
    blocks: list[str] = [AGGREGATE_CONNECTION]
    success = 0
    failure = 0

    for account in accounts:
        account_id = account["Id"]
        account_name = account.get("Name", "unknown")
        credentials = assume_role(sts_client, account_id, role_name, external_id)
        if credentials is None:
            LOGGER.warning(
                "Skipping connection block for account %s (%s) – role assumption failed.",
                account_id,
                account_name,
            )
            failure += 1
            continue

        blocks.append(build_connection_block(account_id, credentials, regions))
        LOGGER.info("Connection block generated for account %s (%s).", account_id, account_name)
        success += 1

    return "\n".join(blocks), success, failure


# ---------------------------------------------------------------------------
# File writing
# ---------------------------------------------------------------------------

def write_config(config_path: Path, content: str) -> None:
    """Overwrite *config_path* with *content*, creating parent directories if needed."""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(content, encoding="utf-8")
    LOGGER.info("Steampipe config written to %s", config_path)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    # Validate caller identity so problems are caught early.
    sts_client = boto3.client("sts")
    try:
        identity = sts_client.get_caller_identity()
        LOGGER.info(
            "Running as: Account=%s, UserId=%s, Arn=%s",
            identity["Account"],
            identity["UserId"],
            identity["Arn"],
        )
    except (ClientError, BotoCoreError) as exc:
        LOGGER.critical("Unable to determine caller identity: %s", exc)
        sys.exit(1)

    # Step 1: Assume the role in the parent/management account using local credentials.
    LOGGER.info("Assuming role in management account %s...", args.payer_account_id)
    parent_credentials = assume_role(
        sts_client=sts_client,
        account_id=args.payer_account_id,
        role_name=args.role_name,
        external_id=args.external_id,
    )
    if parent_credentials is None:
        LOGGER.critical(
            "Could not assume role in management account %s. Aborting.",
            args.payer_account_id,
        )
        sys.exit(1)

    # Step 2: Build a boto3 session scoped to the parent account credentials.
    parent_session = boto3.Session(
        aws_access_key_id=parent_credentials["AccessKeyId"],
        aws_secret_access_key=parent_credentials["SecretAccessKey"],
        aws_session_token=parent_credentials["SessionToken"],
    )
    parent_sts_client = parent_session.client("sts")
    org_client = parent_session.client("organizations")

    # Step 3: List all active accounts in the organization via the parent session.
    try:
        accounts = list_active_accounts(org_client)
    except ClientError as exc:
        LOGGER.critical("Failed to list organization accounts: %s", exc)
        sys.exit(1)

    if not accounts:
        LOGGER.warning("No active accounts found. Nothing to write.")
        sys.exit(0)

    # Step 4: Assume the role in each child account using the parent session credentials.
    config_content, success_count, failure_count = generate_connections(
        accounts=accounts,
        sts_client=sts_client,
        role_name=args.role_name,
        external_id=args.external_id,
        regions=REGIONS,
    )

    if success_count == 0:
        LOGGER.error(
            "Role assumption failed for all %d account(s). Config file will not be written.",
            failure_count,
        )
        sys.exit(1)

    # Write the config file.
    write_config(STEAMPIPE_CONFIG_PATH, config_content + "\n")

    LOGGER.info(
        "Done. %d connection(s) written, %d skipped.",
        success_count,
        failure_count,
    )


if __name__ == "__main__":
    main()
