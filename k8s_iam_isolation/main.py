import logging

import click

from k8s_iam_isolation.config import get_config, save_config
from k8s_iam_isolation.custom_logging.logger import setup_logging

logger = logging.getLogger("k8s_isolation")


@click.group()
@click.version_option()
@click.pass_context
def cli(ctx: click.Context):
    """Kubernetes Namespace Isolation CLI for AWS IAM Users and Roles.

    This tool helps manage AWS IAM entity access to Kubernetes namespaces
    by modifying the aws-auth ConfigMap and creating relevant RBAC roles.
    """
    config = get_config()

    setup_logging(config.get("log_config"))

    ctx.ensure_object(dict)
    ctx.obj["config"] = config


@cli.group()
def config():
    """Configuration options."""
    pass


@config.command()
@click.pass_obj
def create(_obj: dict):
    """Create a new configuration."""
    save_config(_obj["config"])
    click.echo("Configuration created.")


@config.command()
@click.pass_obj
def show(_obj: dict):
    """Show the current configuration."""

    click.echo(f"Config: {_obj["config"]}")


@config.command()
@click.pass_context
@click.option("--log-config", "-l", type=click.STRING)
def update(ctx: click.Context, log_config):
    """Setup the notes directory."""
    ctx.obj["config"]["log_config"] = log_config

    save_config(ctx.obj["config"])
    click.echo("Config file updated.")
