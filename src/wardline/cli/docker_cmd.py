"""``wardline docker`` — build/up/down the scanner sidecar container."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import typer
from rich.console import Console

from wardline.backends.docker import DEFAULT_CONTAINER, DEFAULT_IMAGE
from wardline.core.capability_matrix import write_capability_matrix

docker_app = typer.Typer(
    name="docker",
    help="Manage the Wardline scanner container (build / up / down).",
    no_args_is_help=True,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = REPO_ROOT / "docker" / "Dockerfile"


def _docker_bin() -> str:
    path = shutil.which("docker")
    if not path:
        raise typer.Exit(code=2)
    return path


def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    console = Console()
    console.print(f"[dim]$ {' '.join(cmd)}[/dim]")
    return subprocess.run(cmd, check=check, text=True, capture_output=False)


@docker_app.command("build")
def docker_build(
    tag: str = typer.Option(DEFAULT_IMAGE, "--tag", "-t", help="Image tag."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable build cache."),
) -> None:
    """Build the pinned scanner image from docker/Dockerfile."""
    console = Console()
    docker = shutil.which("docker")
    if not docker:
        console.print("[red]docker not found on PATH[/red]")
        raise typer.Exit(code=2)
    if not DOCKERFILE.is_file():
        console.print(f"[red]missing Dockerfile at {DOCKERFILE}[/red]")
        raise typer.Exit(code=2)
    cmd = [docker, "build", "-f", str(DOCKERFILE), "-t", tag]
    if no_cache:
        cmd.append("--no-cache")
    cmd.append(str(REPO_ROOT))
    try:
        _run(cmd)
    except subprocess.CalledProcessError:
        raise typer.Exit(code=1) from None
    console.print(f"[green]Built[/green] {tag}")


@docker_app.command("up")
def docker_up(
    tag: str = typer.Option(DEFAULT_IMAGE, "--tag", "-t", help="Image tag."),
    name: str = typer.Option(DEFAULT_CONTAINER, "--name", help="Container name."),
    privileged: bool = typer.Option(
        False,
        "--privileged",
        help="Opt-in privileged mode (avoid unless required).",
    ),
) -> None:
    """Start the long-lived scanner sidecar (host root at /host:ro)."""
    console = Console()
    docker = shutil.which("docker")
    if not docker:
        console.print("[red]docker not found on PATH[/red]")
        raise typer.Exit(code=2)

    # Remove a stopped container with the same name.
    inspect = subprocess.run(
        [docker, "inspect", "-f", "{{.State.Running}}", name],
        check=False,
        capture_output=True,
        text=True,
    )
    if inspect.returncode == 0:
        if inspect.stdout.strip().lower() == "true":
            console.print(f"[green]Already running:[/green] {name}")
            return
        _run([docker, "rm", "-f", name], check=False)

    cmd = [
        docker,
        "run",
        "-d",
        "--name",
        name,
        "--network",
        "host",
        "--pid",
        "host",
        "--security-opt",
        "no-new-privileges:true",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_RAW",
        "--cap-add",
        "DAC_READ_SEARCH",
        "-v",
        "/:/host:ro",
        "-v",
        "wardline-trivy:/var/lib/trivy",
        "-v",
        "wardline-clamav:/var/lib/clamav",
    ]
    if privileged:
        cmd.append("--privileged")
    cmd.extend([tag, "sleep", "infinity"])
    try:
        _run(cmd)
    except subprocess.CalledProcessError:
        raise typer.Exit(code=1) from None
    console.print(
        f"[green]Started[/green] {name} (image {tag})\n"
        "Host filesystem mounted read-only at /host · network/pid=host · "
        "caps: NET_RAW,DAC_READ_SEARCH"
    )


@docker_app.command("down")
def docker_down(
    name: str = typer.Option(DEFAULT_CONTAINER, "--name", help="Container name."),
) -> None:
    """Stop and remove the scanner sidecar."""
    console = Console()
    docker = shutil.which("docker")
    if not docker:
        console.print("[red]docker not found on PATH[/red]")
        raise typer.Exit(code=2)
    result = subprocess.run(
        [docker, "rm", "-f", name],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        console.print(f"[yellow]{name} not removed[/yellow]: {result.stderr.strip()}")
        raise typer.Exit(code=1)
    console.print(f"[green]Removed[/green] {name}")


@docker_app.command("status")
def docker_status(
    name: str = typer.Option(DEFAULT_CONTAINER, "--name", help="Container name."),
) -> None:
    """Show whether the scanner container is running."""
    console = Console()
    docker = shutil.which("docker")
    if not docker:
        console.print("[red]docker not found on PATH[/red]")
        raise typer.Exit(code=2)
    result = subprocess.run(
        [docker, "inspect", "-f", "{{.State.Status}}", name],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        console.print(f"[yellow]{name}[/yellow]: not found")
        raise typer.Exit(code=1)
    console.print(f"{name}: {result.stdout.strip()}")


@docker_app.command("matrix")
def docker_matrix(
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write path (default: docs/capability-matrix.md).",
    ),
) -> None:
    """Regenerate docs/capability-matrix.md from plugin metadata."""
    console = Console()
    path = write_capability_matrix(output)
    console.print(f"[green]Wrote[/green] {path}")
