from .main import cli


def main():
    from . import aws, config, k8s

    cli()
