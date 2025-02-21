import click
import k8s_iam_isolation.k8s as k8s
from k8s_iam_isolation.config import get_config, save_config


@click.group()
@click.version_option()
@click.pass_context
def cli(ctx: click.Context):
    """Kubernetes Namespace Isolation CLI for AWS IAM Users, Groups & Roles"""
    config = get_config()

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
@click.option("--log-file", "-l", type=click.STRING)
def update(ctx: click.Context, log_file):
    """Setup the notes directory."""
    ctx.obj["config"]["log_file"] = log_file

    save_config(ctx.obj["config"])
    click.echo(f"Config file updated.")


if __name__ == "__main__":
    cli()
