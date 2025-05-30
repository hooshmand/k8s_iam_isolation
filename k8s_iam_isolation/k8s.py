import logging
import os
from dataclasses import dataclass, field
from functools import wraps

import boto3
import click
import yaml
from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from InquirerPy.validator import EmptyInputValidator
from kubernetes import client, config
from kubernetes.client.rest import ApiException

from k8s_iam_isolation.aws import list_iam_roles, list_iam_users
from k8s_iam_isolation.main import cli
from k8s_iam_isolation.utils.prompt import PromptField, prompt_factory

logger = logging.getLogger("k8s_isolation")


def _k8s_contexts() -> list[Choice]:
    """Fetch the Kubernetes contexts from the kubeconfig"""
    context_choices = []
    contexts, default_context = config.list_kube_config_contexts()
    context_choices = [Choice(context.get("name")) for context in contexts]
    return context_choices


def _default_predefined_rules() -> dict:
    """Load the default predefined rules from a yaml file."""

    with open(
        os.path.join(os.path.dirname(__file__), "predefined_rbac_rules.yaml")
    ) as file:
        predefined_rbac_rules = yaml.safe_load(file)
    return predefined_rbac_rules.get("predefined_rules", {})


def _get_policy_rules(rule_config: list) -> list:
    # Convert the configuration to V1PolicyRule objects
    policy_rules = []
    for rule in rule_config:
        policy_rule = client.V1PolicyRule(
            api_groups=rule.get("apiGroups", []),
            resources=rule.get("resources", []),
            verbs=rule.get("verbs", []),
            resource_names=rule.get("resourceNames"),
        )
        policy_rules.append(policy_rule)
    return policy_rules


def dry_run_guard(mock_response=None):
    """Decorator that enables dry-run behavior with dynamic mock responses."""

    def decorator(method):
        @wraps(method)
        def wrapper(self, *args, **kwargs):
            if self.dry_run:
                logger.info(
                    f"[Dry-Run] {method.__name__} called with args={args}, kwargs={kwargs}."
                )

                # Check if a mock function is provided, else check if `default_mock_response` exists
                if callable(mock_response):
                    response = mock_response(self, *args, **kwargs)
                elif hasattr(self, "_default_mock_response") and callable(
                    self._default_mock_response
                ):
                    response = self._default_mock_response(
                        method, *args, **kwargs
                    )
                else:
                    response = None

                return response

            return method(self, *args, **kwargs)

        return wrapper

    return decorator


@dataclass
class K8sClient:

    predefined_rules: dict
    context: dict = PromptField(
        prompt_type="select",
        message="Choose the correct context:",
        choices=_k8s_contexts,
    )
    dry_run: bool = field(default=False)

    def __post_init__(self, **kwargs):
        if not hasattr(self, "_kube_config_loaded"):
            config.load_kube_config(context=self.context)
            self._kube_config_loaded = True
        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()
        self.batch_v1 = client.BatchV1Api()
        self.network_v1beta1 = client.NetworkingV1beta1Api()
        self.network_v1 = client.NetworkingV1Api()
        self.storage_v1 = client.StorageV1Api()

    def _read_aws_auth(self):
        try:
            aws_auth_cm = self.core_v1.read_namespaced_config_map(
                "aws-auth", "kube-system"
            )
            return aws_auth_cm
        except ApiException as e:
            if e.status == 404:
                logger.warning(
                    "aws-auth ConfigMap not found. Create a new one."
                )
                return None
            else:
                logger.error(f"Failed to read aws-auth ConfigMap: {e}")
                raise e

    def _create_aws_auth(self, users=None, roles=None):
        if users is None:
            users = []
        if roles is None:
            roles = []

        try:
            body = client.V1ConfigMap(
                api_version="v1",
                kind="ConfigMap",
                metadata=client.V1ObjectMeta(
                    name="aws-auth", namespace="kube-system"
                ),
                data={},
            )

            body.data = {
                "mapRoles": yaml.dump(roles),
                "mapUsers": yaml.dump(users),
            }

            aws_auth_cm = self.core_v1.create_namespaced_config_map(
                namespace="kube-system", body=body
            )
            return aws_auth_cm
        except ApiException as e:
            logger.error(f"Failed to create aws-auth ConfigMap: {e}")
            raise e

    @dry_run_guard()
    def modify_aws_auth(self, entity, entity_type, remove=False):
        """Update aws-auth ConfigMap to add/remove IAM users, groups, or roles."""
        action = "Removing" if remove else "Adding"

        if self.dry_run:
            logger.info(
                f"📝 [Dry Run] {action} {entity_type} '{entity.get("name")}' to aws-auth ConfigMap."
            )
            return

        try:
            aws_auth_cm = self._read_aws_auth()
            if aws_auth_cm is None:
                # Create new ConfigMap if it doesn't exist
                aws_auth_cm = self._create_aws_auth()

            map_key = "mapUsers" if entity_type == "user" else "mapRoles"

            new_entry = {
                (
                    "userarn" if entity_type != "role" else "rolearn"
                ): f"{entity.get("arn")}",
                "username": entity.get("name"),
                "groups": ["system:authenticated"],
            }

            arn_key = "userarn" if entity_type == "user" else "rolearn"
            entity_arn = entity.get("arn")

            existing_entries = yaml.safe_load(
                aws_auth_cm.data.get(map_key, "[]")
            )

            # Find existing entry by ARN (more reliable than dict comparison)
            existing_entry_idx = None
            for i, entry in enumerate(existing_entries):
                if entry.get(arn_key) == entity_arn:
                    existing_entry_idx = i
                    break

            if remove:
                if existing_entry_idx is not None:
                    existing_entries.pop(existing_entry_idx)
                    logger.info(
                        f"✅ Removed {entity_type} '{entity.get("name")}' from aws-auth ConfigMap."
                    )
            else:
                if existing_entry_idx is None:
                    existing_entries.append(new_entry)
                    logger.info(
                        f"✅ Added {entity_type} '{entity.get('name')}' to aws-auth ConfigMap."
                    )
                else:
                    logger.info(
                        f"ℹ️ {entity_type} '{entity.get('name')}' already exists in aws-auth ConfigMap."
                    )

            aws_auth_cm.data[map_key] = yaml.dump(existing_entries)
            self.core_v1.patch_namespaced_config_map(
                name="aws-auth", namespace="kube-system", body=aws_auth_cm
            )

        except Exception as e:
            logger.error(f"Failed to update aws-auth ConfigMap: {e}")

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
            self.rbac_v1.read_namespaced_role_binding(
                name=name, namespace=namespace
            )
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
        self, name: str, namespace: str, rules: list[client.V1PolicyRule]
    ) -> client.V1Role:
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
            metadata=client.V1ObjectMeta(name=name, namespace=namespace),
            rules=rules,
        )

        return role_body

    @dry_run_guard(_role_body)
    def upsert_custom_role(
        self, name: str, namespace: str, rules: list[client.V1PolicyRule]
    ) -> client.V1Role:
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
            role_exists = self.check_role_exists(
                name=name, namespace=namespace
            )

            if role_exists:
                role = self.rbac_v1.replace_namespaced_role(
                    name=name, namespace=namespace, body=role_body
                )
                logger.info(f"Updated Role {name} in namespace {namespace}")
            else:
                role = self.rbac_v1.create_namespaced_role(
                    namespace=namespace, body=role_body
                )
                logger.info(f"Created Role {name} in namespace {namespace}")
            return role
        except ApiException as e:
            raise e

    def _cluster_role_body(
        self, name: str, rules: list[client.V1PolicyRule]
    ) -> client.V1ClusterRole:
        """
        Create a Cluster Role body.

        Args:
            name: Name of the Role
            rules: List of PolicyRules for the Role

        Returns:
            The created V1Role body
        """
        role_body = client.V1ClusterRole(
            api_version="rbac.authorization.k8s.io/v1",
            kind="ClusterRole",
            metadata=client.V1ObjectMeta(name=name),
            rules=rules,
        )

        return role_body

    @dry_run_guard(_cluster_role_body)
    def upsert_custom_cluster_role(
        self, name: str, rules: list[client.V1PolicyRule]
    ) -> client.V1ClusterRole:
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
            cluster_role_exists = self.check_cluster_role_exists(name=name)

            if cluster_role_exists:
                cluster_role = self.rbac_v1.replace_cluster_role(
                    name=name, body=role_body
                )
                logger.info(f"Updated Cluster Role {name}.")
            else:
                cluster_role = self.rbac_v1.create_cluster_role(body=role_body)
                logger.info(f"Created Cluster Role {name}.")

            return cluster_role
        except ApiException as e:
            logger.error(f"Failed to upsert Cluster Role {name}: {e}")
            raise e

    def _rolebinding_body(
        self,
        name: str,
        namespace: str,
        role_name: str,
        subject_name: str,
        kind: str = "User",
    ) -> client.V1RoleBinding:
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
            metadata=client.V1ObjectMeta(name=name, namespace=namespace),
            role_ref=client.V1RoleRef(
                api_group="rbac.authorization.k8s.io",
                kind="Role",
                name=role_name,
            ),
            subjects=[
                client.RbacV1Subject(
                    kind=kind,
                    name=subject_name,
                    namespace=namespace if kind == "ServiceAccount" else None,
                )
            ],
        )
        return rolebinding_body

    @dry_run_guard(_rolebinding_body)
    def upsert_custom_rolebinding(
        self,
        name: str,
        namespace: str,
        role_name: str,
        subject_name: str,
        kind: str = "User",
    ) -> client.V1RoleBinding:
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
            kind=kind,
        )

        try:
            role_binding_exits = self.check_role_binding_exists(
                name, namespace
            )
            if role_binding_exits:
                # Update the existing Role Binding
                rolebinding = self.rbac_v1.replace_namespaced_role_binding(
                    name=name, namespace=namespace, body=rolebinding_body
                )
                logger.info(
                    f"Updated RoleBinding {name} in namespace {namespace}"
                )
            else:
                # Create a new Role Binding
                rolebinding = self.rbac_v1.create_namespaced_role_binding(
                    namespace=namespace, body=rolebinding_body
                )
                logger.info(
                    f"Created RoleBinding {name} in namespace {namespace}"
                )
        except ApiException as e:
            logger.error(
                f"Failed to upsert RoleBinding {name} in namespace {namespace}: {e}"
            )
            raise

        return rolebinding

    def _cluster_rolebinding_body(
        self, name: str, role_name: str, subject_name: str, kind: str = "User"
    ) -> client.V1ClusterRoleBinding:
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
            metadata=client.V1ObjectMeta(name=name),
            role_ref=client.V1RoleRef(
                api_group="rbac.authorization.k8s.io",
                kind="ClusterRole",
                name=role_name,
            ),
            subjects=[
                client.RbacV1Subject(
                    kind=kind,
                    name=subject_name,
                    namespace=None if kind != "ServiceAccount" else "default",
                )
            ],
        )
        return cluster_rolebinding_body

    @dry_run_guard(_cluster_rolebinding_body)
    def upsert_cluster_role_binding(
        self, name: str, role_name: str, subject_name: str, kind: str = "User"
    ) -> client.V1ClusterRoleBinding:
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
        cluster_rolebinding_body = self._cluster_rolebinding_body(
            name, role_name, subject_name, kind
        )

        try:
            cluster_role_binding_exists = (
                self.check_cluster_role_binding_exists(name=name)
            )

            if cluster_role_binding_exists:
                # Update the existing Cluster Role Binding
                crb = self.rbac_v1.replace_cluster_role_binding(
                    name=name, body=cluster_rolebinding_body
                )
                logger.info(f"Updated ClusterRoleBinding {name}.")
            else:
                crb = self.rbac_v1.create_cluster_role_binding(
                    body=cluster_rolebinding_body
                )
                logger.info(f"Created ClusterRoleBinding {name}.")

            return crb
        except ApiException as e:
            logger.error(f"Failed to upsert ClusterRoleBinding {name}: {e}")
            raise e

    @dry_run_guard(
        mock_response=lambda self, *args, **kwargs: None
    )  # Basic mock for dry run
    def delete_namespaced_role_binding(self, name: str, namespace: str):
        try:
            self.rbac_v1.delete_namespaced_role_binding(
                name=name, namespace=namespace
            )
            logging.info(
                f"RoleBinding '{name}' deleted from namespace '{namespace}'."
            )
        except ApiException as e:
            if e.status == 404:
                logging.info(
                    f"RoleBinding '{name}' not found in namespace '{namespace}'."
                )
            else:
                logging.error(
                    f"Failed to delete RoleBinding '{name}' in namespace '{namespace}': {e}"
                )
                raise

    @dry_run_guard(
        mock_response=lambda self, *args, **kwargs: None
    )  # Basic mock for dry run
    def delete_namespaced_role(self, name: str, namespace: str):
        try:
            self.rbac_v1.delete_namespaced_role(name=name, namespace=namespace)
            logging.info(
                f"Role '{name}' deleted from namespace '{namespace}'."
            )
        except ApiException as e:
            if e.status == 404:
                logging.info(
                    f"Role '{name}' not found in namespace '{namespace}'."
                )
            else:
                logging.error(
                    f"Failed to delete Role '{name}' in namespace '{namespace}': {e}"
                )
                raise

    def cleanup_orphaned_resources(self, entity_name: str, namespace: str):
        """Clean up any orphaned roles/rolebindings for an entity."""
        try:
            # List all roles in namespace that match the entity pattern
            roles = self.rbac_v1.list_namespaced_role(namespace=namespace)
            for role in roles.items:
                if role.metadata.name.startswith(f"{entity_name}-"):
                    # Check if there's a corresponding rolebinding
                    try:
                        self.rbac_v1.read_namespaced_role_binding(
                            name=role.metadata.name, namespace=namespace
                        )
                    except ApiException as e:
                        if e.status == 404:
                            # Orphaned role found, clean it up
                            logger.warning(
                                f"Cleaning up orphaned role: {role.metadata.name}"
                            )
                            self.delete_namespaced_role(
                                role.metadata.name, namespace
                            )
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    def validate_namespace(self, namespace: str) -> bool:
        """Check if namespace exists, offer to create if not."""
        try:
            self.core_v1.read_namespace(name=namespace)
            return True
        except ApiException as e:
            if e.status == 404:
                if click.confirm(
                    f"Namespace '{namespace}' doesn't exist. Create it?"
                ):
                    self.create_namespace(namespace)
                    return True
                return False
            raise e

    @dry_run_guard()
    def create_namespace(self, namespace: str):
        """Create a new namespace."""
        ns_body = client.V1Namespace(
            metadata=client.V1ObjectMeta(name=namespace)
        )
        self.core_v1.create_namespace(body=ns_body)
        logger.info(f"Created namespace: {namespace}")

    def _extract_rule_dict(self, rule):
        """
        Extract rule attributes into a standardized dictionary format.
        Handles both object attributes and dictionary keys.

        Args:
            rule: RBAC rule (object or dict)

        Returns:
            dict: Standardized rule dictionary
        """
        if isinstance(rule, dict):
            # Rule is already a dictionary
            return {
                "resources": rule.get("resources", []) or [],
                "verbs": rule.get("verbs", []) or [],
                "api_groups": rule.get("api_groups", []) or [],
            }
        else:
            # Rule is an object with attributes
            return {
                "resources": getattr(rule, "resources", None) or [],
                "verbs": getattr(rule, "verbs", None) or [],
                "api_groups": getattr(rule, "api_groups", None) or [],
            }

    def _matches_combination(self, rule, dangerous_combo):
        """
        Check if an RBAC rule matches a dangerous combination pattern.

        Args:
            rule: RBAC rule object with attributes like resources, verbs, api_groups
            dangerous_combo: Dictionary containing the dangerous pattern

        Returns:
            bool: True if the rule contains all permissions from the dangerous pattern
        """
        try:
            rule_dict = self._extract_rule_dict(rule)

            # Log the comparison for debugging
            logger.debug(
                f"Checking rule {rule_dict} against pattern {dangerous_combo.get('name', 'unnamed')}"
            )

            # Check each attribute in the dangerous combination
            for key in ["resources", "verbs", "api_groups"]:
                if key not in dangerous_combo:
                    continue

                dangerous_values = set(dangerous_combo[key])
                rule_values = set(rule_dict.get(key, []))

                # Skip empty dangerous patterns
                if not dangerous_values:
                    continue

                # Check if dangerous pattern is subset of rule permissions
                if not dangerous_values.issubset(rule_values):
                    logger.debug(
                        f"Pattern mismatch on {key}: {dangerous_values} not subset of {rule_values}"
                    )
                    return False

            logger.debug(
                f"Rule matches dangerous pattern: {dangerous_combo.get('name', 'unnamed')}"
            )
            return True

        except Exception as e:
            logger.error(f"Error matching rule against pattern: {e}")
            return False

    def validate_rbac_rules(
        self,
        rules: list,
        config_file: str = "dangerous_rbac_combinations.yaml",
    ) -> bool:
        """Validate RBAC rules don't grant excessive permissions."""

        try:
            with open(config_file) as f:
                config = yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Configuration file {config_file} not found")
            return True
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML configuration: {e}")
            return True

        for rule in rules:
            for combo in config["dangerous_combinations"]:
                if self._matches_combination(rule, combo):
                    severity = combo.get("severity", "medium")
                    name = combo.get("name", "unnamed_pattern")
                    description = combo.get(
                        "description", "No description available"
                    )

                    # Handle different severity levels
                    if severity == "critical":
                        logger.error(f"🚨 CRITICAL SECURITY RISK: {name}")
                        logger.error(f"   Description: {description}")
                        logger.error(
                            f"   Rule: {self._extract_rule_dict(rule)}"
                        )
                        if not click.confirm(
                            "⚠️  This poses an EXTREME security risk! Continue anyway?",
                            abort=True,
                        ):
                            return False

                    elif severity == "high":
                        logger.warning(f"⚠️  HIGH SECURITY RISK: {name}")
                        logger.warning(f"   Description: {description}")
                        logger.warning(
                            f"   Rule: {self._extract_rule_dict(rule)}"
                        )
                        if not click.confirm(
                            "Continue with this high-risk permission?"
                        ):
                            return False

                    elif severity == "medium":
                        logger.info(f"ℹ️  MEDIUM SECURITY RISK: {name}")
                        logger.info(f"   Description: {description}")
                        # Continue without prompting for medium risk

                    elif severity == "low":
                        logger.debug(f"Low risk pattern detected: {name}")

        return True


@click.command()
@click.pass_obj
@click.option(
    "--entity-type",
    type=click.Choice(["user", "role"]),
    prompt="Is this a user or role?",
    help="Specify whether the entity is an IAM user or role.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Simulate the action without applying changes.",
)
def create(_obj: dict, entity_type, dry_run):
    """Create namespace isolation for an AWS IAM user or role"""
    iam_client = boto3.client("iam")
    predefined_rules: dict | None = _obj["config"].get("predefined_rules")
    if predefined_rules is None:
        predefined_rules = _default_predefined_rules()
        _obj["config"]["predefined_rules"] = predefined_rules
    vars = prompt_factory(K8sClient)
    k8c = K8sClient(predefined_rules=predefined_rules, dry_run=dry_run, **vars)

    try:
        entities = (
            list_iam_users(iam_client)
            if entity_type == "user"
            else list_iam_roles(iam_client)
        )
    except Exception as e:
        logger.error(f"Could not list the entities: {e}")
        entities = []

    if not entities:
        click.echo(
            click.style(
                f"No IAM {entity_type}s found, or an error occurred during listing from AWS.",
                fg="red",
            ),
            err=True,
        )
        click.echo(
            "Please ensure the AWS credentials are correct and have necessary IAM list permissions.",
            err=True,
        )
        raise click.Abort()

    entity = inquirer.fuzzy(
        message=f"Select IAM {entity_type.capitalize()}:",
        choices=[
            Choice(name=entity.get("name"), value=entity)
            for entity in entities
        ],
        max_height="50%",
    ).execute()
    click.echo(f"Selected {entity.get("name")} with ARN: {entity.get("arn")}")

    # ToDo: Select or Create the namespace
    namespace = inquirer.text(
        message="Enter Kubernetes namespace:",
        validate=EmptyInputValidator("Namespace should not be empty"),
    ).execute()

    # ToDo: Select a predefined rule
    policy_rule_name = inquirer.fuzzy(
        message="Select the access level:",
        choices=[Choice(rule_name) for rule_name in predefined_rules.keys()],
        max_height="50%",
    ).execute()

    if not click.confirm(
        f"⚠️ Confirm adding {entity_type} '{entity.get("name")}' with {policy_rule_name} access to namespace '{namespace}'?",
        abort=True,
    ):
        click.echo("❌ Action aborted.")
        return

    try:
        if not k8c.validate_namespace(namespace):
            raise click.Abort()

        k8c.modify_aws_auth(entity, entity_type, remove=False)

        role_name = f"{entity.get("name")}-{policy_rule_name}"
        policy_rules = _get_policy_rules(
            predefined_rules.get(policy_rule_name)
        )

        if not k8c.validate_rbac_rules(policy_rules):
            raise click.Abort()

        k8c.upsert_custom_role(role_name, namespace, policy_rules)

        k8c.upsert_custom_rolebinding(
            name=role_name,
            namespace=namespace,
            role_name=role_name,
            subject_name=entity.get("name"),
        )
    except click.Abort:
        raise
    except Exception as e:
        logger.error(f"Failed to create isolation for {entity_type}: {e}")
        click.echo(click.style(f"❌ Error: {e}", fg="red"), err=True)
        raise click.ClickException("Operation failed. Check logs for details.")

    click.echo(
        f"✅ {entity_type.capitalize()} '{entity.get("arn")}' successfully added to namespace '{namespace}'."
    )


@click.command()
@click.pass_obj
@click.option(
    "--entity-type",
    type=click.Choice(["user", "role"]),
    prompt="Is this a user or role?",
    help="Specify whether the entity is an IAM user or role.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Simulate the action without applying changes.",
)
def delete(_obj: dict, entity_type, dry_run):
    """Remove IAM user, group, or role from Kubernetes"""
    _config = _obj["config"]  # Get config from context
    predefined_rules: dict | None = _config.get("predefined_rules")
    if predefined_rules is None:
        predefined_rules = _default_predefined_rules()
        # _config["predefined_rules"] = predefined_rules # Not strictly necessary for delete

    vars_for_k8s_client = prompt_factory(
        K8sClient,
    )
    k8c = K8sClient(
        predefined_rules=predefined_rules,
        dry_run=dry_run,
        **vars_for_k8s_client,
    )

    iam_client = boto3.client(
        "iam"
    )  # Ensure iam_client is defined, as per previous fix
    entities = (
        list_iam_users(iam_client)
        if entity_type == "user"
        else list_iam_roles(iam_client)
    )
    if not entities:
        click.echo(
            click.style(
                f"No IAM {entity_type}s found, or an error occurred during listing from AWS.",
                fg="red",
            ),
            err=True,
        )
        click.echo(
            "Please ensure the AWS credentials are correct and have necessary IAM list permissions.",
            err=True,
        )
        raise click.Abort()

    entity = inquirer.fuzzy(
        message=f"Select IAM {entity_type.capitalize()} to delete access for:",
        choices=[
            Choice(name=entity.get("name"), value=entity)
            for entity in entities
        ],
        max_height="50%",
    ).execute()
    click.echo(f"Selected {entity.get("name")} with ARN: {entity.get("arn")}")

    namespace = inquirer.text(
        message="Enter Kubernetes namespace:",
        validate=EmptyInputValidator("Namespace should not be empty"),
    ).execute()

    policy_rule_name = inquirer.fuzzy(
        message="Select the policy rule name that was used for creation:",
        choices=[Choice(rule_name) for rule_name in predefined_rules.keys()],
        max_height="50%",
    ).execute()

    role_name = f"{entity.get("name")}-{policy_rule_name}"

    if not click.confirm(
        f"⚠️ Confirm deleting {entity_type} '{entity.get("name")}' access to namespace '{namespace}', including associated Role '{role_name}' and RoleBinding '{role_name}'?",
        abort=True,
    ):
        click.echo("❌ Action aborted.")
        return

    # Remove from aws-auth ConfigMap
    k8c.modify_aws_auth(entity, entity_type, remove=True)

    # Delete RoleBinding
    logging.info(
        f"Attempting to delete RoleBinding '{role_name}' in namespace '{namespace}'."
    )
    k8c.delete_namespaced_role_binding(name=role_name, namespace=namespace)

    # Delete Role
    logging.info(
        f"Attempting to delete Role '{role_name}' in namespace '{namespace}'."
    )
    k8c.delete_namespaced_role(name=role_name, namespace=namespace)

    click.echo(
        f"✅ {entity_type.capitalize()} '{entity.get("name")}' access, Role, and RoleBinding removed from namespace '{namespace}'."
    )


cli.add_command(create)
cli.add_command(delete)
