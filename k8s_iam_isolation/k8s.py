
import click
import yaml
import logging
from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from InquirerPy.validator import EmptyInputValidator
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from k8s_iam_isolation.main import cli
from k8s_iam_isolation.aws import list_iam_users, list_iam_roles
from k8s_iam_isolation.utils.prompt import PromptData, PromptField
from typing import Dict, List


def _k8s_contexts():
    """Fetch the Kubernetes contexts from the kubeconfig"""
    context_choices = []
    contexts = config.list_kube_config_contexts()
    context_choices = [Choice(name=context.get("name"), value=context) for context in contexts]
    return context_choices


class K8sClient(PromptData):
    context = PromptField(
        prompt_type="select",
        message="Choose the correct context:",
        choices=_k8s_contexts
    )

    def __init__(self, dry_run: bool=False):
        self.from_prompt()
        config.load_kube_config(context=self.context)
        self.dry_run = dry_run
        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()
        self.batch_v1 = client.BatchV1Api()
        self.network_v1beta1 = client.NetworkingV1beta1Api()
        self.network_v1 = client.NetworkingV1Api()
        self.storage_v1 = client.StorageV1Api()

    def _read_aws_auth(self):
        try:
            aws_auth_cm = self.core_v1.read_namespaced_config_map("aws-auth", "kube-system")
            return aws_auth_cm
        except client.exceptions.ApiException as e:
            if e.status == 404:
                logging.warning("aws-auth ConfigMap not found. Create a new one.")
                return None
            else:
                logging.error(f"Failed to read aws-auth ConfigMap: {e}")
                raise e

    def _create_aws_auth(self, users: List[Dict]=[], roles: List[Dict]=[]):
        try:
            body = client.V1ConfigMap(
                api_version="v1",
                kind="ConfigMap",
                metadata=client.V1ObjectMeta(
                    name="aws-auth",
                    namespace="kube-system"),
                data={}
            )

            body.data = {
                "mapRoles": yaml.dump(roles),
                "mapUsers": yaml.dump(users)
            }

            aws_auth_cm = self.core_v1.create_namespaced_config_map(
                namespace="kube-system",
                body=body
            )
            return aws_auth_cm
        except client.exceptions.ApiException as e:
            logging.error(f"Failed to create aws-auth ConfigMap: {e}")
            raise e

    def modify_aws_auth(self, entity, entity_type, remove=False):
        """Update aws-auth ConfigMap to add/remove IAM users, groups, or roles."""
        action = "Removing" if remove else "Adding"

        if self.dry_run:
            logging.info(f"📝 [Dry Run] {action} {entity_type} '{entity.name}' to aws-auth ConfigMap.")
            return

        try:
            aws_auth_cm = self._read_aws_auth()
            if aws_auth_cm is None:
                # Create new ConfigMap if it doesn't exist
                aws_auth_cm = self._create_aws_auth()

            map_key = "mapUsers" if entity_type == "user" else "mapRoles"

            new_entry = {
                "userarn" if entity_type != "role" else "rolearn": f"{entity.arn}",
                "username": entity.name,
                "groups": ["system:authenticated"]
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
            self.core_v1.patch_namespaced_config_map(name="aws-auth", namespace="kube-system", body=aws_auth_cm)

        except Exception as e:
            logging.error(f"Failed to update aws-auth ConfigMap: {e}")

    def upsert_custom_role(
            self,
            name: str,
            namespace: str,
            rules: List[client.V1PolicyRule]) -> client.V1Role:
        """
        Update or Create a custom Role with specific permissions in a namespace.

        Args:
            name: Name of the Role
            namespace: Namespace to create the Role in
            rules: List of PolicyRules for the Role

        Returns:
            The created V1Role object
        """
        role_body = client.V1Role(
            metadata=client.V1ObjectMeta(
                name=name,
                namespace=namespace),
            rules=[client.V1PolicyRule(**rule) for rule in rules]
        )

        try:
            current_role = self.rbac_v1.read_namespaced_role(name=name, namespace=namespace)
            updated_role = self.rbac_v1.replace_namespaced_role(name=name, namespace=namespace, body=role_body)
            logging.info(f"Updated Role {name} in namespace {namespace}")
            return updated_role
        except ApiException as e:
            if e.status == 404:
                logging.info(f"Role {name} in namespace {namespace} doesn't exit.")
                created_role = self.rbac_v1.create_namespaced_role(namespace=namespace, body=role_body)
                logging.info(f"Created Role {name} in namespace {namespace}")
                return created_role
            else:
                raise e


@click.command()
@click.option("--entity-type", type=click.Choice(["user", "role"]), prompt="Is this a user or role?", help="Specify whether the entity is an IAM user or role.")
@click.option("--dry-run", is_flag=True, help="Simulate the action without applying changes.")
def create(entity_type, dry_run):
    """Create namespace isolation for an AWS IAM user, group, or role"""
    k8c = K8sClient(dry_run=dry_run)

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

    k8c.modify_aws_auth(entity, entity_type, remove=False)
    click.echo(f"✅ {entity_type.capitalize()} '{entity.arn}' successfully added to namespace '{namespace}'.")


@click.command()
@click.option("--entity-type", type=click.Choice(["user", "role"]), prompt="Is this a user or role?", help="Specify whether the entity is an IAM user or role.")
@click.option("--dry-run", is_flag=True, help="Simulate the action without applying changes.")
def delete(entity_type, dry_run):
    """Remove IAM user, group, or role from Kubernetes"""
    k8c = K8sClient(dry_run=dry_run)

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

    k8c.modify_aws_auth(entity, entity_type, remove=True)
    click.echo(f"✅ {entity_type.capitalize()} '{entity.name}' access removed from namespace '{namespace}'.")


cli.add_command(create)
cli.add_command(delete)
