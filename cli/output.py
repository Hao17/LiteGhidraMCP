import click


def success(msg: str):
    click.echo(click.style(f"  [OK] {msg}", fg="green"))


def error(msg: str):
    click.echo(click.style(f"  [ERROR] {msg}", fg="red"), err=True)


def info(msg: str):
    click.echo(click.style(f"  {msg}", dim=True))


def header(msg: str):
    click.echo(click.style(msg, bold=True))


def warning(msg: str):
    click.echo(click.style(f"  [WARN] {msg}", fg="yellow"))
