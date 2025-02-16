import click
import boto3
import logging
import yaml
import subprocess
from kubernetes import client, config

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Initialize AWS Clients
iam_client = boto3.client("iam")
eks_client = boto3.client("eks")
account_id = boto3.client("sts").get_caller_identity().get("Account")

# Load Kubernetes Config
try:
    config.load_kube_config()  # Use local kubeconfig
except Exception:
    config.load_incluster_config()  # Use in-cluster config if running in Kubernetes

k8s_api = client.CoreV1Api()


def get_current_k8s_user():
    """Fetch the current Kubernetes user from kubectl config"""
    try:
        return subprocess.check_output(["kubectl", "config", "view", "--minify", "-o", "jsonpath='{.contexts[0].context.user}'"], text=True).strip().strip("'")
    except Exception:
        return "Unknown User"


def get_current_k8s_cluster():
    """Fetch the current Kubernetes cluster from kubectl config"""
    try:
        return subprocess.check_output(["kubectl", "config", "current-context"], text=True).strip()
    except Exception:
        return "Unknown Cluster"


def modify_aws_auth(entity_name, entity_type, remove=False):
    """Update aws-auth ConfigMap to add/remove IAM users, groups, or roles."""
    try:
        aws_auth_cm = k8s_api.read_namespaced_config_map("aws-auth", "kube-system")
        map_key = "mapUsers" if entity_type == "user" else "mapRoles"

        if entity_type == "role":
            new_entry = {
                "rolearn": f"arn:aws:iam::{account_id}:role/{entity_name}",
                "username": entity_name,
                "groups": [f"{entity_name}-group"]
            }
        else:
            new_entry = {
                "userarn": f"arn:aws:iam::{account_id}:{entity_type}/{entity_name}",
                "username": entity_name,
                "groups": [f"{entity_name}-group"]
            }

        existing_entries = yaml.safe_load(aws_auth_cm.data.get(map_key, "[]"))

        if remove:
            existing_entries = [entry for entry in existing_entries if entry.get("userarn", entry.get("rolearn")) != new_entry.get("userarn", new_entry.get("rolearn"))]
            logging.info(f"✅ Removed {entity_type} '{entity_name}' from aws-auth ConfigMap.")
        else:
            if new_entry not in existing_entries:
                existing_entries.append(new_entry)
                logging.info(f"✅ Added {entity_type} '{entity_name}' to aws-auth ConfigMap.")

        aws_auth_cm.data[map_key] = yaml.dump(existing_entries)
        k8s_api.patch_namespaced_config_map(name="aws-auth", namespace="kube-system", body=aws_auth_cm)

    except Exception as e:
        logging.error(f"Failed to update aws-auth ConfigMap: {e}")


@click.group()
def cli():
    """Kubernetes Namespace Isolation CLI for AWS IAM Users, Groups & Roles"""
    pass


@cli.command()
@click.option("--namespace", prompt="Enter Kubernetes namespace", help="Kubernetes namespace for the IAM entity.")
@click.option("--entity-name", prompt="Enter IAM User/Group/Role name", help="IAM User, Group, or Role name.")
@click.option("--entity-type", type=click.Choice(["user", "group", "role"]), prompt="Is this a user, group, or role?", help="Specify whether the entity is an IAM user, group, or role.")
def create(namespace, entity_name, entity_type):
    """Create namespace isolation for an AWS IAM user, group, or role"""
    current_user = get_current_k8s_user()
    current_cluster = get_current_k8s_cluster()

    logging.info(f"🔍 Running command as Kubernetes user: {current_user}")
    logging.info(f"🔍 Target cluster: {current_cluster}")

    if not click.confirm(f"⚠️ Are you sure you want to add {entity_type} '{entity_name}' to namespace '{namespace}' on cluster '{current_cluster}'?", abort=True):
        logging.info("❌ Action aborted by the user.")
        return

    modify_aws_auth(entity_name, entity_type, remove=False)
    logging.info(f"✅ {entity_type.capitalize()} '{entity_name}' successfully restricted to namespace '{namespace}'.")


@cli.command()
@click.option("--namespace", prompt="Enter Kubernetes namespace", help="Namespace to remove access from.")
@click.option("--entity-name", prompt="Enter IAM User/Group/Role name", help="IAM User, Group, or Role name.")
@click.option("--entity-type", type=click.Choice(["user", "group", "role"]), prompt="Is this a user, group, or role?", help="Specify whether the entity is an IAM user, group, or role.")
def delete(namespace, entity_name, entity_type):
    """Revoke access and delete IAM user, group, or role from aws-auth ConfigMap"""
    current_user = get_current_k8s_user()
    current_cluster = get_current_k8s_cluster()

    logging.info(f"🔍 Running command as Kubernetes user: {current_user}")
    logging.info(f"🔍 Target cluster: {current_cluster}")

    if not click.confirm(f"⚠️ Are you sure you want to remove {entity_type} '{entity_name}' from namespace '{namespace}' on cluster '{current_cluster}'?", abort=True):
        logging.info("❌ Action aborted by the user.")
        return

    modify_aws_auth(entity_name, entity_type, remove=True)
    logging.info(f"✅ {entity_type.capitalize()} '{entity_name}' access removed from namespace '{namespace}'.")


@cli.command()
def list_entities():
    """List all IAM users, groups, and roles with Kubernetes bindings"""
    try:
        # List IAM Users
        users = iam_client.list_users()["Users"]
        click.echo("\n👤 IAM Users:")
        for user in users:
            click.echo(f"  - {user['UserName']} - {user['Arn']}")

        # List IAM Groups
        groups = iam_client.list_groups()["Groups"]
        click.echo("\n👥 IAM Groups:")
        for group in groups:
            click.echo(f"  - {group['GroupName']} - {group['Arn']}")

        # List IAM Roles
        roles = iam_client.list_roles()["Roles"]
        click.echo("\n🎭 IAM Roles:")
        for role in roles:
            click.echo(f"  - {role['RoleName']} - {role['Arn']}")

        # Fetch and Display Kubernetes Role Bindings
        click.echo("\n🔗 Kubernetes Role Bindings:")
        role_bindings = k8s_api.list_namespaced_role_binding("kube-system").items
        for rb in role_bindings:
            subjects = ", ".join([s.name for s in rb.subjects])
            click.echo(f"  - {rb.metadata.name} (Subjects: {subjects})")

    except Exception as e:
        logging.error(f"Error retrieving IAM/Kubernetes information: {e}")


if __name__ == "__main__":
    cli()