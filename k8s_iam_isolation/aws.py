import boto3
import click
import logging
from botocore.exceptions import ClientError
from k8s_iam_isolation.main import cli


def list_iam_users(iam_client):
    """
    Get a list of all IAM users in the AWS account using pagination.

    Args:
        iam_client: An initialized boto3 IAM client.

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
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        logging.error(f"AWS API error listing IAM users (Code: {error_code}): {e}")
        return []
    except Exception as e:
        logging.error(f"An unexpected error occurred listing IAM users: {e}")
        return []


def list_iam_groups(iam_client):
    """
    Get a list of all IAM groups in the AWS account using pagination.

    Args:
        iam_client: An initialized boto3 IAM client.

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
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        logging.error(f"AWS API error listing IAM groups (Code: {error_code}): {e}")
        return []
    except Exception as e:
        logging.error(f"An unexpected error occurred listing IAM groups: {e}")
        return []


def list_iam_roles(iam_client):
    """
    Get a list of all IAM roles in the AWS account using pagination.

    Args:
        iam_client: An initialized boto3 IAM client.

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
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        logging.error(f"AWS API error listing IAM roles (Code: {error_code}): {e}")
        return []
    except Exception as e:
        logging.error(f"An unexpected error occurred listing IAM roles: {e}")
        return []


@click.command()
def list_entities():

    iam_client = boto3.client("iam")

    """List all IAM users, groups, and roles."""
    users = list_iam_users(iam_client)
    groups = list_iam_groups(iam_client)
    roles = list_iam_roles(iam_client)

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
