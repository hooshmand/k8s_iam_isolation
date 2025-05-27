# k8s_iam_isolation

A CLI tool to restrict AWS IAM users and roles to specific Kubernetes namespaces by managing entries in the `aws-auth` ConfigMap and creating corresponding RBAC Roles and RoleBindings.

## Prerequisites

Before using this tool, please ensure you have:

1. **AWS Credentials:**
    * Configured AWS credentials (e.g., via `~/.aws/credentials`, environment variables, or IAM roles for EC2/ECS).
    * The credentials must have IAM permissions to:
        * `iam:ListUsers`
        * `iam:ListRoles`
        * (Note: `iam:ListGroups` might be required if group functionality is expanded in the future).
2. **Kubernetes Configuration:**
    * A valid `kubeconfig` file pointing to your Kubernetes cluster (typically an EKS cluster if using `aws-auth`).
    * Permissions to:
        * Read and write to the `aws-auth` ConfigMap in the `kube-system` namespace.
        * Create, read, and delete namespaced `Role` and `RoleBinding` resources in the target namespaces.
3. **Python Environment:**
    * Python 3.x
    * `pip` for installation.

## Installation

```bash
# For developers (from the repository root)
pip install --editable .

# ToDo: Add installation instructions once published to PyPI
```

## Usage

### General Options

* `--version`: Show the version of the tool.
* `--help`: Show help messages for commands.

### Listing IAM Entities

```bash
k8s-iam list-entities
```

This command lists available IAM users and roles from your AWS account that can be targeted for namespace isolation.

### Creating Namespace Isolation

```bash
k8s-iam create
```

This command will guide you through:

1. Selecting the Kubernetes context.
2. Choosing an AWS IAM User or Role.
3. Specifying the Kubernetes namespace to grant access to.
4. Selecting a predefined access role (e.g., `viewer`, `editor`, `admin`).

It then:

* Adds (or updates) a mapping for the IAM entity in the `aws-auth` ConfigMap in `kube-system`.
* Creates a namespaced `Role` with the chosen permissions in the target namespace.
* Creates a namespaced `RoleBinding` linking the IAM entity (as a Kubernetes user) to this Role.

### Deleting Namespace Isolation

```bash
k8s-iam delete
```

This command will guide you through:

1. Selecting the Kubernetes context.
2. Choosing an AWS IAM User or Role whose access you want to remove.
3. Specifying the Kubernetes namespace from which to revoke access.
4. Selecting the predefined access role that was originally assigned (this is needed to identify the correct Role/RoleBinding).

It then:

* Removes the IAM entity's mapping from the `aws-auth` ConfigMap.
* Deletes the namespaced `RoleBinding` associated with the entity and role in that namespace.
* Deletes the namespaced `Role` associated with the entity and role in that namespace.

### Important: Dry Run Mode

For both `create` and `delete` commands, you can use the `--dry-run` flag:

```bash
k8s-iam create --dry-run
k8s-iam delete --dry-run
```

This mode simulates the intended operations and prints out what actions would be taken without actually modifying your AWS or Kubernetes resources. **It is highly recommended to use `--dry-run` before applying any changes, especially for the first time.**

## Predefined Access Roles

When using `k8s-iam create`, you'll be prompted to select a predefined role. These roles define the level of access the IAM entity will have within the specified Kubernetes namespace:

* **viewer**: Can view most resources in the namespace (pods, deployments, services, etc.). Cannot make changes.
* **editor**: Can view and modify most resources (create, update, delete pods, deployments, services, configmaps, etc.).
* **admin**: Extensive permissions within the namespace, including managing most resources and also managing RBAC (`Roles`, `RoleBindings`) within that namespace. *(Use with caution)*
* **monitoring**: View access to cluster components (nodes, namespaces) and application workloads, suitable for monitoring systems.
* **deployment-manager**: Permissions to manage deployments, ReplicaSets, and associated ConfigMaps/Services.
* **job-manager**: Permissions to manage Jobs and CronJobs.
* **pod-executor**: Allows creating pods and executing commands within them (`pods/exec`).
* **pod-log-viewer**: Allows viewing logs for pods.
* **config-manager**: Permissions to manage ConfigMaps and Secrets.
* **network-admin**: Permissions to manage NetworkPolicies and Ingresses.
* **storage-admin**: Permissions to manage PersistentVolumeClaims and PersistentVolumes.
* **ci-cd-pipeline**: Broad permissions suitable for CI/CD pipelines to deploy and manage applications.
* **istio-manager**: Permissions to manage Istio custom resources like VirtualServices and DestinationRules.

For the exact permissions, refer to the `k8s_iam_isolation/predefined_rbac_rules.yaml` file in the repository or your custom configuration (see below).

## Configuration

This tool uses a configuration file located at `~/.config/k8s_iam_isolation/config.yaml`.

### Logging Configuration

You can customize logging behavior by setting the following options in the config file:

* `log_level`: The logging verbosity (e.g., `INFO`, `DEBUG`, `WARNING`, `ERROR`). Defaults to `INFO`.
* `log_file`: Path to a file where logs should be written (e.g., `/var/log/k8s_iam_isolation/audit.log`). If not specified, or if the directory cannot be created, logs will go to the console (stderr). The tool will attempt to create the log directory if it doesn't exist.

Example `config.yaml`:

```yaml
log_level: DEBUG
log_file: /tmp/k8s-iam-isolation.log
```

### Customizing Predefined RBAC Rules

You can override the default predefined RBAC rules. To do this:

1. Copy the structure from the default `k8s_iam_isolation/predefined_rbac_rules.yaml` file (found in the installed package or repository).
2. Paste this structure into your `~/.config/k8s_iam_isolation/config.yaml` under a top-level key named `predefined_rules:`.
3. Modify the rules as needed.

The tool will then use your custom rules instead of the defaults.

Example `config.yaml` with custom rules:

```yaml
log_level: INFO
predefined_rules:
  viewer: # Overriding the default viewer
    - apiGroups: [""]
      resources: ["pods", "services"] # Only pods and services
      verbs: ["get", "list", "watch"]
  # ... other custom roles or modifications ...
```

## Security Considerations

* This tool modifies critical Kubernetes resources, including the `aws-auth` ConfigMap (which controls cluster-wide IAM authentication for EKS) and RBAC Roles/RoleBindings.
* Ensure you are authorized to perform these operations on your cluster.
* Always understand the implications of the access levels you are granting. Use the principle of least privilege.
* The `--dry-run` flag is your friend!

## Troubleshooting & Logging

* Logs are generated based on your `config.yaml` settings (see Configuration section). Check the specified `log_file` or your console output for detailed information and errors.
* Ensure your AWS credentials and `kubeconfig` are correctly set up and have the necessary permissions.
