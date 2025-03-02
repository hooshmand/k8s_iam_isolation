
import click
import yaml
import logging
from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from InquirerPy.validator import EmptyInputValidator
from kubernetes import client, config
from k8s_iam_isolation.main import cli
from k8s_iam_isolation.aws import list_iam_users, list_iam_roles


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


def modify_aws_auth(entity, entity_type, remove=False, dry_run=False):
    """Update aws-auth ConfigMap to add/remove IAM users, groups, or roles."""
    action = "Removing" if remove else "Adding"

    if dry_run:
        logging.info(f"📝 [Dry Run] {action} {entity_type} '{entity.name}' to aws-auth ConfigMap.")
        return

    try:
        aws_auth_cm = k8s_api.read_namespaced_config_map("aws-auth", "kube-system")
        map_key = "mapUsers" if entity_type == "user" else "mapRoles"

        new_entry = {
            "userarn" if entity_type != "role" else "rolearn": f"{entity.arn}",
            "username": entity.name,
            "groups": [f"{entity.name}-group"]
        }

        existing_entries = yaml.safe_load(aws_auth_cm.data.get(map_key, "[]"))

        if remove:
            existing_entries = [entry for entry in existing_entries if entry.get("userarn", entry.get("rolearn")) != new_entry.get("userarn", new_entry.get("rolearn"))]
            logging.info(f"✅ Removed {entity_type} '{entity.name}' from aws-auth ConfigMap.")
        else:
            if new_entry not in existing_entries:
                existing_entries.append(new_entry)
                logging.info(f"✅ Added {entity_type} '{entity.name}' to aws-auth ConfigMap.")

        aws_auth_cm.data[map_key] = yaml.dump(existing_entries)
        k8s_api.patch_namespaced_config_map(name="aws-auth", namespace="kube-system", body=aws_auth_cm)

    except Exception as e:
        logging.error(f"Failed to update aws-auth ConfigMap: {e}")


@click.command()
@click.option("--entity-type", type=click.Choice(["user", "role"]), prompt="Is this a user or role?", help="Specify whether the entity is an IAM user or role.")
@click.option("--dry-run", is_flag=True, help="Simulate the action without applying changes.")
def create(entity_type, dry_run):
    """Create namespace isolation for an AWS IAM user, group, or role"""
    current_user = get_current_k8s_user()
    current_cluster = get_current_k8s_cluster()

    click.echo(f"🔍 Running as Kubernetes user: {current_user} on cluster: {current_cluster}")

    entities = list_iam_users() if entity_type == "user" else list_iam_roles()
    entity = inquirer.fuzzy(
        message="Select IAM User/Role:",
        choices=[Choice(name=entity.name, value=entity) for entity in entities],
        max_height="50%",
    ).execute()
    click.echo(f"Selected {entity.name} with ARN: {entity.arn}")

    namespace = inquirer.text(
        message="Enter Kubernetes namespace:",
        validate=EmptyInputValidator("Namespace should not be empty")
    ).execute()

    if not click.confirm(f"⚠️ Confirm adding {entity_type} '{entity.name}' access to namespace '{namespace}'?", abort=True):
        click.echo("❌ Action aborted.")
        return

    modify_aws_auth(entity, entity_type, remove=False, dry_run=dry_run)
    click.echo(f"✅ {entity_type.capitalize()} '{entity.arn}' successfully added to namespace '{namespace}'.")


@click.command()
@click.option("--entity-type", type=click.Choice(["user", "role"]), prompt="Is this a user or role?", help="Specify whether the entity is an IAM user or role.")
@click.option("--dry-run", is_flag=True, help="Simulate the action without applying changes.")
def delete(entity_type, dry_run):
    """Remove IAM user, group, or role from Kubernetes"""
    current_user = get_current_k8s_user()
    current_cluster = get_current_k8s_cluster()

    click.echo(f"🔍 Running as Kubernetes user: {current_user} on cluster: {current_cluster}")

    entities = list_iam_users() if entity_type == "user" else list_iam_roles()
    entity = inquirer.fuzzy(
        message="Select IAM User/Role:",
        choices=[Choice(name=entity.name, value=entity) for entity in entities],
        max_height="50%",
    ).execute()
    click.echo(f"Selected {entity.name} with ARN: {entity.arn}")

    namespace = inquirer.text(
        message="Enter Kubernetes namespace:",
        validate=EmptyInputValidator("Namespace should not be empty")
    ).execute()

    if not click.confirm(f"⚠️ Confirm deleting {entity_type} '{entity.name}' access to namespace '{namespace}'?", abort=True):
        click.echo("❌ Action aborted.")
        return

    modify_aws_auth(entity, entity_type, remove=True, dry_run=dry_run)
    click.echo(f"✅ {entity_type.capitalize()} '{entity.name}' access removed from namespace '{namespace}'.")


cli.add_command(create)
cli.add_command(delete)
