
import click
import yaml
import logging
import os
from dataclasses import dataclass, field
from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from InquirerPy.validator import EmptyInputValidator
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from k8s_iam_isolation.main import cli
from k8s_iam_isolation.aws import list_iam_users, list_iam_roles
from k8s_iam_isolation.utils.prompt import PromptField, prompt_factory
from functools import wraps
from typing import Dict, List


def _k8s_contexts():
    """Fetch the Kubernetes contexts from the kubeconfig"""
    context_choices = []
    contexts, default_context = config.list_kube_config_contexts()
    context_choices = [Choice(context.get("name")) for context in contexts]
    return context_choices


def _default_predefined_rules() -> Dict:
    """Load the default predefined rules from a yaml file."""

    with open(os.path.join(os.path.dirname(__file__), 'predefined_rbac_rules.yaml'), "r") as file:
        predefined_rbac_rules = yaml.safe_load(file)
    return predefined_rbac_rules.get("predefined_rules")


def _get_policy_rules(rule_config: List) -> List:
    # Convert the configuration to V1PolicyRule objects
    policy_rules = []
    for rule in rule_config:
        policy_rule = client.V1PolicyRule(
            api_groups=rule.get('apiGroups', []),
            resources=rule.get('resources', []),
            verbs=rule.get('verbs', []),
            resource_names=rule.get('resourceNames', None)
        )
        policy_rules.append(policy_rule)
    return policy_rules


def dry_run_guard(mock_response=None):
    """Decorator that enables dry-run behavior with dynamic mock responses."""
    def decorator(method):
        @wraps(method)
        def wrapper(self, *args, **kwargs):
            if self.dry_run:
                logging.info(f"[Dry-Run] {method.__name__} called with args={args}, kwargs={kwargs}.")

                # Check if a mock function is provided, else check if `default_mock_response` exists
                if callable(mock_response):
                    response = mock_response(self, *args, **kwargs)
                elif hasattr(self, "_default_mock_response") and callable(getattr(self, "_default_mock_response")):
                    response = self._default_mock_response(method, *args, **kwargs)
                else:
                    response = None

                return response

            return method(self, *args, **kwargs)
        return wrapper
    return decorator


@dataclass
class K8sClient:
    context: Dict = PromptField(
        prompt_type="select",
        message="Choose the correct context:",
        choices=_k8s_contexts
    )
    predefined_rules: Dict
    dry_run: bool = field(default=False)

    def __post_init__(self, **kwargs):
        config.load_kube_config(context=self.context)
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
        except ApiException as e:
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
        except ApiException as e:
            logging.error(f"Failed to create aws-auth ConfigMap: {e}")
            raise e

    @dry_run_guard()
    def modify_aws_auth(self, entity, entity_type, remove=False):
        """Update aws-auth ConfigMap to add/remove IAM users, groups, or roles."""
        action = "Removing" if remove else "Adding"

        if self.dry_run:
            logging.info(f"📝 [Dry Run] {action} {entity_type} '{entity.get("name")}' to aws-auth ConfigMap.")
            return

        try:
            aws_auth_cm = self._read_aws_auth()
            if aws_auth_cm is None:
                # Create new ConfigMap if it doesn't exist
                aws_auth_cm = self._create_aws_auth()

            map_key = "mapUsers" if entity_type == "user" else "mapRoles"

            new_entry = {
                "userarn" if entity_type != "role" else "rolearn": f"{entity.get("arn")}",
                "username": entity.get("name"),
                "groups": ["system:authenticated"]
            }

            existing_entries = yaml.safe_load(aws_auth_cm.data.get(map_key, "[]"))

            if remove:
                existing_entries = [entry for entry in existing_entries if entry.get("userarn", entry.get("rolearn")) != new_entry.get("userarn", new_entry.get("rolearn"))]
                logging.info(f"✅ Removed {entity_type} '{entity.get("name")}' from aws-auth ConfigMap.")
            else:
                if new_entry not in existing_entries:
                    existing_entries.append(new_entry)
                    logging.info(f"✅ Added {entity_type} '{entity.get("name")}' to aws-auth ConfigMap.")

            aws_auth_cm.data[map_key] = yaml.dump(existing_entries)
            self.core_v1.patch_namespaced_config_map(name="aws-auth", namespace="kube-system", body=aws_auth_cm)

        except Exception as e:
            logging.error(f"Failed to update aws-auth ConfigMap: {e}")

    def check_role_exists(self, name: str, namespace: str):
        """Check if a Role exists in the specified namespace."""
        try:
            self.rbac_v1.read_namespaced_role(name=name, namespace=namespace)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise e

    def check_cluster_role_exists(self, name: str):
        """Check if a ClusterRole exists."""
        try:
            self.rbac_v1.read_cluster_role(name=name)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise e

    def check_role_binding_exists(self, name: str, namespace: str):
        """Check if a RoleBinding exists in the specified namespace."""
        try:
            self.rbac_v1.read_namespaced_role_binding(name=name, namespace=namespace)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise e

    def check_cluster_role_binding_exists(self, name: str):
        """Check if a ClusterRoleBinding exists."""
        try:
            self.rbac_v1.read_cluster_role_binding(name=name)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise e

    def _role_body(
            self,
            name: str,
            namespace: str,
            rules: List[client.V1PolicyRule]) -> client.V1Role:
        """
        Create a Role body.

        Args:
            name: Name of the Role
            namespace: Namespace to create the Role in
            rules: List of PolicyRules for the Role

        Returns:
            The created V1Role body
        """
        role_body = client.V1Role(
            api_version="rbac.authorization.k8s.io/v1",
            kind="Role",
            metadata=client.V1ObjectMeta(
                name=name,
                namespace=namespace),
            rules=rules
        )

        return role_body

    @dry_run_guard(_role_body)
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
        role_body = self._role_body(name, namespace, rules)

        try:
            role_exits = self.check_role_exists(name=name, namespace=namespace)

            if role_exits:
                role = self.rbac_v1.replace_namespaced_role(name=name, namespace=namespace, body=role_body)
                logging.info(f"Updated Role {name} in namespace {namespace}")
            else:
                role = self.rbac_v1.create_namespaced_role(namespace=namespace, body=role_body)
                logging.info(f"Created Role {name} in namespace {namespace}")
        except ApiException as e:
            raise e

        return role

    def _cluster_role_body(
            self,
            name: str,
            rules: List[client.V1PolicyRule]) -> client.V1Role:
        """
        Create a Cluster Role body.

        Args:
            name: Name of the Role
            rules: List of PolicyRules for the Role

        Returns:
            The created V1Role body
        """
        role_body = client.V1Role(
            api_version="rbac.authorization.k8s.io/v1",
            kind="ClusterRole",
            metadata=client.V1ObjectMeta(name=name),
            rules=rules
        )

        return role_body

    @dry_run_guard(_cluster_role_body)
    def upsert_custom_cluster_role(
            self,
            name: str,
            rules: List[client.V1PolicyRule]) -> client.V1Role:
        """
        Update or Create a custom Cluster Role with specific permissions.

        Args:
            name: Name of the Role
            rules: List of PolicyRules for the Role

        Returns:
            The created V1Role object
        """
        role_body = self._cluster_role_body(name, rules)

        try:
            cluster_role_exits = self.check_cluster_role_exists(name=name)

            if cluster_role_exits:
                cluster_role = self.rbac_v1.replace_cluster_role(name=name, body=role_body)
                logging.info(f"Updated Cluster Role {name}.")
            else:
                created_cluster_role = self.rbac_v1.create_cluster_role(body=role_body)
                logging.info(f"Created Cluster Role {name}.")

        except ApiException as e:
            raise e

        return cluster_role

    def _rolebinding_body(
            self,
            name: str,
            namespace: str,
            role_name: str,
            subject_name: str,
            kind: str = "User") -> client.V1RoleBinding:
        """
        Create a RoleBinding body.

        Args:
            name: Name of the RoleBinding
            namespace: Namespace where the RoleBinding will be created
            role_name: Name of the Role to bind
            subject_name: Name of the subject to bind the Role to
            kind: Subject kind (default: "User", can also be "Group" or "ServiceAccount")

        Returns:
            The created RoleBinding body
        """
        rolebinding_body = client.V1RoleBinding(
            api_version="rbac.authorization.k8s.io/v1",
            kind="RoleBinding",
            metadata=client.V1ObjectMeta(
                name=name,
                namespace=namespace
            ),
            role_ref=client.V1RoleRef(
                api_group="rbac.authorization.k8s.io",
                kind="Role",
                name=role_name
            ),
            subjects=[
                client.V1Subject(
                    kind=kind,
                    name=subject_name,
                    namespace=namespace if kind == "ServiceAccount" else None
                )
            ]
        )
        return rolebinding_body

    @dry_run_guard(_rolebinding_body)
    def upsert_custom_rolebinding(
            self,
            name: str,
            namespace: str,
            role_name: str,
            subject_name: str,
            kind: str = "User") -> client.V1RoleBinding:
        """
        Update or Create a RoleBinding to assign a Role to a specific user.

        Args:
            name: Name of the RoleBinding
            namespace: Namespace where the RoleBinding will be created
            role_name: Name of the Role to bind
            subject_name: Name of the subject to bind the Role to
            kind: Subject kind (default: "User", can also be "Group" or "ServiceAccount")

        Returns:
            The created/updated RoleBinding object
        """
        rolebinding_body = self._rolebinding_body(
            name=name,
            namespace=namespace,
            role_name=role_name,
            subject_name=subject_name,
            kind=kind)

        try:
            role_binding_exits = self.check_role_binding_exists(name, namespace)
            if role_binding_exits:
                # Update the existing Role Binding
                rolebinding = self.rbac_v1.replace_namespaced_role_binding(
                    name=name,
                    namespace=namespace,
                    body=rolebinding_body
                )
                logging.info(f"Updated RoleBinding {name} in namespace {namespace}")
            else:
                # Create a new Role Binding
                rolebinding = self.rbac_v1.create_namespaced_role_binding(
                    namespace=namespace,
                    body=rolebinding_body
                )
                logging.info(f"Created RoleBinding {name} in namespace {namespace}")
        except ApiException as e:
            logging.error(f"Failed to upsert RoleBinding {name} in namespace {namespace}: {e}")
            raise

        return rolebinding

    def _cluster_rolebinding_body(
            self,
            name: str,
            role_name: str,
            subject_name: str,
            kind: str = "User") -> client.V1ClusterRoleBinding:
        """
        Create a ClusterRoleBinding body.

        Args:
            name: Name of the ClusterRoleBinding
            role_name: Name of the ClusterRole to bind
            subject_name: Name of the subject to bind the ClusterRole to
            kind: Subject kind (default: "User", can also be "Group" or "ServiceAccount")

        Returns:
            The created ClusterRoleBinding body
        """
        cluster_rolebinding_body = client.V1ClusterRoleBinding(
            api_version="rbac.authorization.k8s.io/v1",
            kind="ClusterRoleBinding",
            metadata=client.V1ObjectMeta(
                name=name
            ),
            role_ref=client.V1RoleRef(
                api_group="rbac.authorization.k8s.io",
                kind="ClusterRole",
                name=role_name
            ),
            subjects=[
                client.V1Subject(
                    kind=kind,
                    name=subject_name,
                    namespace=None if kind != "ServiceAccount" else "default"
                )
            ]
        )
        return cluster_rolebinding_body

    @dry_run_guard(_cluster_rolebinding_body)
    def upsert_cluster_role_binding(
            self,
            name: str,
            role_name: str,
            subject_name: str,
            kind: str = "User") -> client.V1ClusterRoleBinding:
        """
        Update or Create a ClusterRoleBinding for a subject.

        Args:
            name: Name of the ClusterRoleBinding
            role_name: Name of the ClusterRole to bind
            subject_name: Name of the subject to bind the ClusterRole to
            kind: Subject kind (default: "User", can also be "Group" or "ServiceAccount")

        Returns:
            The created or updated V1ClusterRoleBinding object
        """
        cluster_rolebinding_body = self._cluster_rolebinding_body(name, role_name, subject_name, kind)

        try:
            cluster_role_binding_exists = self.check_cluster_role_binding_exists(name=name)

            if cluster_role_binding_exists:
                # Update the existing Cluster Role Binding
                crb = self.rbac_v1.replace_cluster_role_binding(name=name, body=cluster_rolebinding_body)
                logging.info(f"Updated ClusterRoleBinding {name}.")
            else:
                crb = self.rbac_v1.create_cluster_role_binding(body=cluster_rolebinding_body)
                logging.info(f"Created ClusterRoleBinding {name}.")

            return crb
        except ApiException as e:
            logging.error(f"Failed to upsert ClusterRoleBinding {name}: {e}")
            raise e


@click.command()
@click.pass_obj
@click.option("--entity-type", type=click.Choice(["user", "role"]), prompt="Is this a user or role?", help="Specify whether the entity is an IAM user or role.")
@click.option("--dry-run", is_flag=True, help="Simulate the action without applying changes.")
def create(_obj: dict, entity_type, dry_run):
    """Create namespace isolation for an AWS IAM user or role"""
    predefined_rules: Dict | None = _obj["config"].get("predefined_rules", None)
    if predefined_rules is None:
        predefined_rules = _default_predefined_rules()
        _obj["config"]["predefined_rules"] = predefined_rules
    vars = prompt_factory(K8sClient)
    k8c = K8sClient(predefined_rules=predefined_rules, dry_run=dry_run, **vars)

    entities = list_iam_users() if entity_type == "user" else list_iam_roles()
    entity = inquirer.fuzzy(
        message="Select IAM User/Role:",
        choices=[Choice(name=entity.get("name"), value=entity) for entity in entities],
        max_height="50%",
    ).execute()
    click.echo(f"Selected {entity.get("name")} with ARN: {entity.get("arn")}")

    #ToDo: Select or Create the namespace
    namespace = inquirer.text(
        message="Enter Kubernetes namespace:",
        validate=EmptyInputValidator("Namespace should not be empty")
    ).execute()

    #ToDo: Select a predefined rule
    policy_rule_name = inquirer.fuzzy(
        message="Select the access level:",
        choices=[Choice(rule_name) for rule_name in predefined_rules.keys()],
        max_height="50%",
    ).execute()

    if not click.confirm(f"⚠️ Confirm adding {entity_type} '{entity.get("name")}' with {policy_rule_name} access to namespace '{namespace}'?", abort=True):
        click.echo("❌ Action aborted.")
        return

    k8c.modify_aws_auth(entity, entity_type, remove=False)

    role_name = f"{entity.get("name")}-{policy_rule_name}"
    policy_rules = _get_policy_rules(predefined_rules.get(policy_rule_name))
    new_role = k8c.upsert_custom_role(role_name, namespace, policy_rules)

    role_binding = k8c.upsert_custom_rolebinding(
        name=role_name,
        namespace=namespace,
        role_name=role_name,
        subject_name=entity.get("name"))

    click.echo(f"✅ {entity_type.capitalize()} '{entity.get("arn")}' successfully added to namespace '{namespace}'.")


@click.command()
@click.option("--entity-type", type=click.Choice(["user", "role"]), prompt="Is this a user or role?", help="Specify whether the entity is an IAM user or role.")
@click.option("--dry-run", is_flag=True, help="Simulate the action without applying changes.")
def delete(entity_type, dry_run):
    """Remove IAM user, group, or role from Kubernetes"""
    k8c = K8sClient(dry_run=dry_run)

    entities = list_iam_users() if entity_type == "user" else list_iam_roles()
    entity = inquirer.fuzzy(
        message="Select IAM User/Role:",
        choices=[Choice(name=entity.get("name"), value=entity) for entity in entities],
        max_height="50%",
    ).execute()
    click.echo(f"Selected {entity.get("name")} with ARN: {entity.get("arn")}")

    namespace = inquirer.text(
        message="Enter Kubernetes namespace:",
        validate=EmptyInputValidator("Namespace should not be empty")
    ).execute()

    if not click.confirm(f"⚠️ Confirm deleting {entity_type} '{entity.get("name")}' access to namespace '{namespace}'?", abort=True):
        click.echo("❌ Action aborted.")
        return

    k8c.modify_aws_auth(entity, entity_type, remove=True)
    click.echo(f"✅ {entity_type.capitalize()} '{entity.get("name")}' access removed from namespace '{namespace}'.")


cli.add_command(create)
cli.add_command(delete)
