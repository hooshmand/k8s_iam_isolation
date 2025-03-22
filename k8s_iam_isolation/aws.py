import boto3
import click
import logging
from k8s_iam_isolation.main import cli


iam_client = boto3.client("iam")
account_id = boto3.client("sts").get_caller_identity().get("Account")


def list_iam_users():
    """
    Get a list of all IAM users in the AWS account using pagination.

    Returns:
        list: List of IAM user dictionaries
    """
    try:
        # Create a paginator for the list_users operation
        paginator = iam_client.get_paginator('list_users')
        page_iterator = paginator.paginate()

        all_users = []
        # Iterate through each page and extend the list of users
        for page in page_iterator:
            all_users.extend(page['Users'])
        return [{"name": user["UserName"], "arn": user["Arn"]} for user in all_users]
    except Exception as e:
        logging.error(f"Failed to list IAM users: {e}")
        return []


def list_iam_groups():
    """
    Get a list of all IAM groups in the AWS account using pagination.

    Returns:
        list: List of IAM group dictionaries
    """
    try:
        # Create a paginator for the list_groups operation
        paginator = iam_client.get_paginator('list_groups')
        page_iterator = paginator.paginate()

        all_groups = []
        # Iterate through each page and extend the list of groups
        for page in page_iterator:
            all_groups.extend(page['Groups'])
        return [{"name": group["GroupName"], "arn": group["Arn"]} for group in all_groups]
    except Exception as e:
        logging.error(f"Failed to list IAM groups: {e}")
        return []


def list_iam_roles():
    """
    Get a list of all IAM roles in the AWS account using pagination.

    Returns:
        list: List of IAM role dictionaries
    """
    try:
        # Create a paginator for the list_roles operation
        paginator = iam_client.get_paginator('list_roles')
        page_iterator = paginator.paginate()

        all_roles = []
        # Iterate through each page and extend the list of roles
        for page in page_iterator:
            all_roles.extend(page['Roles'])
        return [{"name": role["RoleName"], "arn": role["Arn"]} for role in all_roles]
    except Exception as e:
        logging.error(f"Failed to list IAM roles: {e}")
        return []


@click.command()
def list_entities():
    """List all IAM users, groups, and roles."""
    users = list_iam_users()
    groups = list_iam_groups()
    roles = list_iam_roles()

    click.echo("\n👤 IAM Users:")
    for user in users:
        click.echo(f"  - {user['name']} - {user['arn']}")

    click.echo("\n👥 IAM Groups:")
    for group in groups:
        click.echo(f"  - {group['name']} - {group['arn']}")

    click.echo("\n🎭 IAM Roles:")
    for role in roles:
        click.echo(f"  - {role['name']} - {role['arn']}")


@cli.group()
def aws():
    """Bulk operations on notes."""
    pass

aws.add_command(list_entities)
