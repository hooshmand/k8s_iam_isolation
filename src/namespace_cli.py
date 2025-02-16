import click
import boto3
import logging
import yaml
import subprocess
import os
from kubernetes import client, config

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Load Configuration
CONFIG_FILE = "config.yaml"
DEFAULTS = {"namespace": "default-namespace", "aws_account_id": None}

if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "r") as file:
        CONFIG = yaml.safe_load(file) or {}
        DEFAULTS.update(CONFIG)

# Initialize AWS Clients
iam_client = boto3.client("iam")
eks_client = boto3.client("eks")
account_id = DEFAULTS.get("aws_account_id") or boto3.client("sts").get_caller_identity().get("Account")

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


def modify_aws_auth(entity_name, entity_type, remove=False, dry_run=False):
    """Update aws-auth ConfigMap to add/remove IAM users, groups, or roles."""
    action = "Removing" if remove else "Adding"

    if dry_run:
        logging.info(f"📝 [Dry Run] {action} {entity_type} '{entity_name}' to aws-auth ConfigMap.")
        return

    try:
        aws_auth_cm = k8s_api.read_namespaced_config_map("aws-auth", "kube-system")
        map_key = "mapUsers" if entity_type == "user" else "mapRoles"

        new_entry = {
            "userarn" if entity_type != "role" else "rolearn": f"arn:aws:iam::{account_id}:{entity_type}/{entity_name}",
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
@click.option("--namespace", default=DEFAULTS["namespace"], prompt="Enter Kubernetes namespace", help="Kubernetes namespace for the IAM entity.")
@click.option("--entity-name", prompt="Enter IAM User/Group/Role name", help="IAM User, Group, or Role name.")
@click.option("--entity-type", type=click.Choice(["user", "group", "role"]), prompt="Is this a user, group, or role?", help="Specify whether the entity is an IAM user, group, or role.")
@click.option("--dry-run", is_flag=True, help="Simulate the action without applying changes.")
def create(namespace, entity_name, entity_type, dry_run):
    """Create namespace isolation for an AWS IAM user, group, or role"""
    current_user = get_current_k8s_user()
    current_cluster = get_current_k8s_cluster()

    logging.info(f"🔍 Running command as Kubernetes user: {current_user}")
    logging.info(f"🔍 Target cluster: {current_cluster}")

    if not click.confirm(f"⚠️ Are you sure you want to add {entity_type} '{entity_name}' to namespace '{namespace}' on cluster '{current_cluster}'?", abort=True):
        logging.info("❌ Action aborted by the user.")
        return

    modify_aws_auth(entity_name, entity_type, remove=False, dry_run=dry_run)
    logging.info(f"✅ {entity_type.capitalize()} '{entity_name}' successfully restricted to namespace '{namespace}'.")


@cli.command()
@click.option("--namespace", default=DEFAULTS["namespace"], prompt="Enter Kubernetes namespace", help="Namespace to remove access from.")
@click.option("--entity-name", prompt="Enter IAM User/Group/Role name", help="IAM User, Group, or Role name.")
@click.option("--entity-type", type=click.Choice(["user", "group", "role"]), prompt="Is this a user, group, or role?", help="Specify whether the entity is an IAM user, group, or role.")
@click.option("--dry-run", is_flag=True, help="Simulate the action without applying changes.")
def delete(namespace, entity_name, entity_type, dry_run):
    """Revoke access and delete IAM user, group, or role from aws-auth ConfigMap"""
    modify_aws_auth(entity_name, entity_type, remove=True, dry_run=dry_run)
    logging.info(f"✅ {entity_type.capitalize()} '{entity_name}' access removed from namespace '{namespace}'.")


if __name__ == "__main__":
    cli()