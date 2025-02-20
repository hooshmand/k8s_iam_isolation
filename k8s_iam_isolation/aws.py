import boto3
import click
import logging

iam_client = boto3.client("iam")
account_id = boto3.client("sts").get_caller_identity().get("Account")


def account_id():
    """List all IAM users."""
    try:
        users = iam_client.list_users()["Users"]
        return [{"name": user["UserName"], "arn": user["Arn"]} for user in users]
    except Exception as e:
        logging.error(f"Failed to list IAM users: {e}")
        return []


def list_iam_users():
    """List all IAM users."""
    try:
        users = iam_client.list_users()["Users"]
        return [{"name": user["UserName"], "arn": user["Arn"]} for user in users]
    except Exception as e:
        logging.error(f"Failed to list IAM users: {e}")
        return []


def list_iam_groups():
    """List all IAM groups."""
    try:
        groups = iam_client.list_groups()["Groups"]
        return [{"name": group["GroupName"], "arn": group["Arn"]} for group in groups]
    except Exception as e:
        logging.error(f"Failed to list IAM groups: {e}")
        return []


def list_iam_roles():
    """List all IAM roles."""
    try:
        roles = iam_client.list_roles()["Roles"]
        return [{"name": role["RoleName"], "arn": role["Arn"]} for role in roles]
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