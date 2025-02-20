
import click
import yaml
import logging
from kubernetes import client, config


config.load_kube_config()
k8s_api = client.CoreV1Api()


def get_current_k8s_user():
    """Fetch the current Kubernetes user from the kubeconfig"""
    try:
        context, active_context = config.list_kube_config_contexts()
        return active_context["context"]["user"] if active_context else "Unknown User"
    except Exception:
        return "Unknown User"

def get_current_k8s_cluster():
    """Fetch the current Kubernetes cluster/context from the kubeconfig"""
    try:
        return config.list_kube_config_contexts()[1]["name"]
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


@click.command()
@click.option("--namespace", required=True, prompt="Enter Kubernetes namespace", help="Kubernetes namespace for the IAM entity.")
@click.option("--entity-name", prompt="Enter IAM User/Group/Role name", help="IAM User, Group, or Role name.")
@click.option("--entity-type", type=click.Choice(["user", "group", "role"]), prompt="Is this a user, group, or role?", help="Specify whether the entity is an IAM user, group, or role.")
@click.option("--dry-run", is_flag=True, help="Simulate the action without applying changes.")
def create(namespace, entity_name, entity_type, dry_run):
    """Create namespace isolation for an AWS IAM user, group, or role"""
    current_user = get_current_k8s_user()
    current_cluster = get_current_k8s_cluster()

    click.echo(f"🔍 Running as Kubernetes user: {current_user} on cluster: {current_cluster}")

    if not click.confirm(f"⚠️ Confirm adding {entity_type} '{entity_name}' to namespace '{namespace}'?", abort=True):
        click.echo("❌ Action aborted.")
        return

    modify_aws_auth(entity_name, entity_type, remove=False, dry_run=dry_run)
    click.echo(f"✅ {entity_type.capitalize()} '{entity_name}' successfully added to namespace '{namespace}'.")


@click.command()
@click.option("--namespace", required=True, prompt="Enter Kubernetes namespace", help="Namespace to remove access from.")
@click.option("--entity-name", prompt="Enter IAM User/Group/Role name", help="IAM User, Group, or Role name.")
@click.option("--entity-type", type=click.Choice(["user", "group", "role"]), prompt="Is this a user, group, or role?", help="Specify whether the entity is an IAM user, group, or role.")
@click.option("--dry-run", is_flag=True, help="Simulate the action without applying changes.")
def delete(namespace, entity_name, entity_type, dry_run):
    """Remove IAM user, group, or role from Kubernetes"""
    modify_aws_auth(entity_name, entity_type, remove=True, dry_run=dry_run)
    click.echo(f"✅ {entity_type.capitalize()} '{entity_name}' access removed from namespace '{namespace}'.")