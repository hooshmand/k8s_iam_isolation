# k8s_iam_isolation

A CLI tool to restrict AWS IAM users and roles to Kubernetes namespaces.

## Installation

```bash
# After it's published
# pip install k8s-iam-isolation

# developer mode
pip install --editable .
```

## Usage

### Create Namespace Isolation

```bash
k8s-iam create
```

### Delete Namespace Isolation

```bash
k8s-iam delete
```

### List Entities

```bash
k8s-iam list-entities
```

### Dry Run Mode

Simulates the operation without making changes.

```bash
k8s-iam create --dry-run
```
