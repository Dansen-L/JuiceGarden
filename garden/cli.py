"""
Juice Garden CLI — garden command
"""
import os
import sys
import time
import json
import subprocess
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

console = Console()

# Project root is the directory containing this package's parent
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def get_compose_cmd():
    """Return the docker compose command array."""
    return ["docker", "compose"]


def run_compose(args, capture=False, cwd=None):
    """Run a docker compose command in the project root."""
    cwd = cwd or PROJECT_ROOT
    cmd = get_compose_cmd() + args
    if capture:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        return result
    else:
        return subprocess.run(cmd, cwd=cwd)


@click.group()
def main():
    """Juice Garden — Moderate-Difficulty Vulnerable Web Lab Platform

    Quick start:
      garden start       Bring up the full stack
      garden status      Check all service health
      garden flags list  List all 23 current flag values (operator use)
    """


@main.command()
@click.option("--build", is_flag=True, help="Force image rebuild before starting.")
def start(build):
    """Bring up all Docker Compose services.

    Streams logs until all health checks pass, then prints service URLs.
    """
    console.print(Panel("[bold amber1]Juice Garden[/bold amber1] — Starting stack...", border_style="yellow"))

    # Ensure .env exists
    env_file = PROJECT_ROOT / ".env"
    env_example = PROJECT_ROOT / ".env.example"
    if not env_file.exists():
        if env_example.exists():
            import shutil
            shutil.copy(env_example, env_file)
            console.print("[yellow]Created .env from .env.example[/yellow]")
        else:
            console.print("[red]Warning: .env file not found[/red]")

    # --profile bots ensures victim-bot starts even if profiles are activated.
    # Harmless when no services carry the 'bots' profile.
    args = ["--profile", "bots", "up", "-d"]
    if build:
        args.append("--build")

    result = run_compose(args)
    if result.returncode != 0:
        console.print("[red]Failed to start services.[/red]")
        sys.exit(1)

    # Wait for health checks
    console.print("\n[yellow]Waiting for all services to become healthy...[/yellow]")
    start_time = time.time()
    timeout = 240  # 4 minutes

    while time.time() - start_time < timeout:
        all_healthy = _check_all_healthy(quiet=True)
        if all_healthy:
            break
        time.sleep(5)
        elapsed = int(time.time() - start_time)
        console.print(f"  [{elapsed}s] Services starting...", end="\r")

    console.print()

    # Print final status
    _print_status()
    _print_urls()

    # Print flag count (feature 1 step 7)
    flags_data = _read_flags_json()
    if flags_data:
        console.print(f"[green]✓ {len(flags_data)} flags loaded from flag-data volume[/green]")
    else:
        console.print("[yellow]Warning: could not verify flag count (flags.json may still be initializing)[/yellow]")


@main.command()
@click.option("--timeout", default=30, help="Timeout in seconds before forceful stop.")
def stop(timeout):
    """Stop and remove containers (volumes preserved)."""
    console.print("[yellow]Stopping Juice Garden stack...[/yellow]")
    result = run_compose(["down", "--timeout", str(timeout)])
    if result.returncode == 0:
        console.print("[green]Stack stopped.[/green]")
    else:
        console.print("[red]Stop command returned non-zero.[/red]")
        sys.exit(result.returncode)


@main.command()
@click.option("--hard", is_flag=True, help="Destroy all volumes and rebuild from scratch.")
def reset(hard):
    """Reset the Juice Garden stack.

    Soft reset (default): regenerate all 23 flags, restart app services.
    Hard reset (--hard): destroy all volumes, rebuild images, regenerate flags.
    """
    if hard:
        if not click.confirm(
            "Hard reset destroys all data volumes and regenerates all 23 flags. "
            "Purge practitioner progress too?",
            default=False,
        ):
            console.print("Aborted.")
            return

        # docker compose down -v removes all compose-declared named volumes using the
        # correct project prefix, regardless of the directory the repo was cloned into.
        # This is the only portable way to remove all compose volumes by declared name.
        console.print("[yellow]Hard reset: stopping stack and removing ALL volumes...[/yellow]")
        run_compose(["down", "-v", "--timeout", "30"])

        console.print("[yellow]Rebuilding images...[/yellow]")
        run_compose(["--profile", "bots", "build"])

        console.print("[yellow]Starting stack (will regenerate flags)...[/yellow]")
        run_compose(["--profile", "bots", "up", "-d"])

    else:
        console.print("[yellow]Soft reset: regenerating flags and restarting app services...[/yellow]")

        # Re-run flag-init
        result = run_compose([
            "run", "--rm", "--no-deps",
            "flag-init"
        ])
        if result.returncode != 0:
            console.print("[red]flag-init failed.[/red]")
            sys.exit(1)

        # Restart node-app and flask-platform to re-seed from new flags
        console.print("[yellow]Restarting node-app and flask-platform...[/yellow]")
        run_compose(["restart", "node-app", "flask-platform"])

    console.print("[green]Reset complete. All 23 flags regenerated.[/green]")

    # Brief wait then show status
    time.sleep(5)
    _print_status()


@main.command()
def status():
    """Health check 7 persistent services + flag-init (one-shot, exited 0).

    Exits non-zero if any persistent service is unhealthy.
    """
    all_healthy = _print_status()
    _print_urls()
    if not all_healthy:
        sys.exit(1)


@main.group()
def flags():
    """Flag management commands."""


@flags.command(name="list")
def flags_list():
    """List all 23 current flag values with challenge codes (operator use)."""
    console.print(Panel(
        "[bold yellow]OPERATOR WARNING:[/bold yellow] This command reveals all flag values. "
        "Do not run with practitioners present.",
        border_style="red"
    ))

    flags_data = _read_flags_json()
    if not flags_data:
        console.print("[red]Could not read flags.json. Is the stack running?[/red]")
        sys.exit(1)

    table = Table(title="Juice Garden — Flag Inventory (23 flags)", show_header=True)
    table.add_column("Code", style="cyan", no_wrap=True)
    table.add_column("Flag Value", style="green", no_wrap=True)

    CODE_LABELS = {
        "auth01": "AUTH-01", "auth02": "AUTH-02", "auth03": "AUTH-03", "auth04": "AUTH-04",
        "inj01":  "INJ-01",  "inj02":  "INJ-02",  "inj03":  "INJ-03",  "inj04":  "INJ-04",
        "bac01":  "BAC-01",  "bac02":  "BAC-02",  "bac03":  "BAC-03",  "bac04":  "BAC-04",
        "cs01":   "CS-01",   "cs02":   "CS-02",   "cs03":   "CS-03",
        "ss01":   "SS-01",   "ss02":   "SS-02",   "ss03":   "SS-03",
        "bl01":   "BL-01",   "bl02":   "BL-02",   "bl03":   "BL-03",
        "mission_alpha": "MISSION-ALPHA",
        "bonus":  "BONUS",
    }

    for code, flag in sorted(flags_data.items(), key=lambda x: CODE_LABELS.get(x[0], x[0])):
        label = CODE_LABELS.get(code, code.upper())
        table.add_row(label, flag)

    console.print(table)
    console.print(f"\n[dim]Total: {len(flags_data)} flags[/dim]")


@flags.command(name="verify")
@click.argument("flag_string")
def flags_verify(flag_string):
    """Check if a flag string is valid.

    Returns challenge code and title if valid, error if not.
    """
    flags_data = _read_flags_json()
    if not flags_data:
        console.print("[red]Could not read flags.json.[/red]")
        sys.exit(1)

    CODE_TITLES = {
        "auth01": "AUTH-01: JWT kid Path Traversal",
        "auth02": "AUTH-02: JWT RS256→HS256 Algorithm Confusion",
        "auth03": "AUTH-03: Password Reset Token Predictability",
        "auth04": "AUTH-04: Login Rate-Limit Bypass",
        "inj01":  "INJ-01: Second-Order SQL Injection",
        "inj02":  "INJ-02: SQLi UNION SELECT WAF bypass (order-search)",
        "inj03":  "INJ-03: EJS Server-Side Template Injection",
        "inj04":  "INJ-04: Command Injection in Thumbnail Generator",
        "bac01":  "BAC-01: IDOR via UUID v1 Timestamp Prediction",
        "bac02":  "BAC-02: Mass Assignment (Role Elevation)",
        "bac03":  "BAC-03: BOLA in GraphQL Resolver",
        "bac04":  "BAC-04: Path Traversal via Double URL Encoding",
        "cs01":   "CS-01: Stored XSS with CSP Bypass via JSONP",
        "cs02":   "CS-02: DOM XSS via window.postMessage",
        "cs03":   "CS-03: CSRF on Account Email Change",
        "ss01":   "SS-01: Blind SSRF via Webhook URL",
        "ss02":   "SS-02: XXE via File URI Entity",
        "ss03":   "SS-03: File Upload Bypass to EJS Template Execution",
        "bl01":   "BL-01: Negative Quantity Order",
        "bl02":   "BL-02: Coupon Race Condition",
        "bl03":   "BL-03: Loyalty Points Integer Overflow",
        "mission_alpha": "MISSION-ALPHA: Garden Takeover (Admin Takeover Chain)",
        "bonus":  "BONUS: Hidden Debug Endpoint",
    }

    for code, flag in flags_data.items():
        if flag == flag_string.strip():
            title = CODE_TITLES.get(code, code.upper())
            console.print(f"[green]Valid flag![/green] Challenge: [bold]{title}[/bold]")
            return

    console.print("[red]Invalid flag.[/red]")
    sys.exit(1)


@main.command()
@click.option("--service", default="node-app",
              help="Service name to restart (default: node-app).")
def restart(service):
    """Soft restart of one or more app services without destroying volumes.

    Used to apply .env changes (e.g. SESSION_SAMESITE=strict for CS-03).
    """
    console.print(f"[yellow]Restarting service: {service}[/yellow]")
    result = run_compose(["restart", service])
    if result.returncode == 0:
        console.print(f"[green]{service} restarted.[/green]")
    else:
        sys.exit(result.returncode)


@main.command(name="hosts")
@click.argument("action", default="check")
def hosts(action):
    """Verify or add /etc/hosts entries for garden.lab and attacker.lab.

    'garden hosts check' reads /etc/hosts and reports whether the required
    entries are present. It does NOT modify /etc/hosts (operator action
    required to add missing entries).

    'garden hosts add' attempts to append the required entries to /etc/hosts
    automatically (requires write permission, typically via sudo).
    """
    if action not in ("check", "add"):
        console.print(f"[red]Unknown action: {action}. Use: garden hosts check  OR  garden hosts add[/red]")
        sys.exit(1)

    hosts_file = Path("/etc/hosts")
    if not hosts_file.exists():
        console.print("[red]/etc/hosts not found.[/red]")
        sys.exit(1)

    content = hosts_file.read_text()
    lines = content.splitlines()

    garden_ok = any("garden.lab" in line and not line.strip().startswith("#") for line in lines)
    attacker_ok = any("attacker.lab" in line and not line.strip().startswith("#") for line in lines)

    if action == "add":
        if garden_ok and attacker_ok:
            console.print("[green]Host entries already present — nothing to add.[/green]")
            return
        try:
            with open(str(hosts_file), "a") as fh:
                fh.write("\n# Added by garden hosts add\n")
                fh.write("127.0.0.1  garden.lab  attacker.lab\n")
            console.print("[green]Host entries added successfully.[/green]")
            return
        except PermissionError:
            console.print("[red]Permission denied: cannot write /etc/hosts.[/red]")
            console.print("[dim]Run with sudo: sudo garden hosts add[/dim]")
            sys.exit(1)

    # action == "check": report-only, no modification
    table = Table(title="Host Entries Check", show_header=True)
    table.add_column("Entry", style="cyan")
    table.add_column("Status")

    present_label = "[green]PRESENT[/green]"
    missing_label = "[red]MISSING[/red]"

    table.add_row("127.0.0.1 garden.lab",   present_label if garden_ok   else missing_label)
    table.add_row("127.0.0.1 attacker.lab", present_label if attacker_ok else missing_label)

    console.print(table)

    if garden_ok and attacker_ok:
        console.print("[green]All required host entries are present.[/green]")
    else:
        console.print("\n[yellow]Add the following line to /etc/hosts (requires root):[/yellow]")
        console.print("  127.0.0.1  garden.lab  attacker.lab")
        console.print("[dim]Options:[/dim]")
        console.print("[dim]  sudo garden hosts add[/dim]")
        console.print("[dim]  sudo sh -c 'echo \"127.0.0.1 garden.lab attacker.lab\" >> /etc/hosts'[/dim]")
        sys.exit(1)


# ──────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────

def _read_flags_json():
    """Read flags.json from the flag-data volume via a temporary container.

    Uses docker compose run against the flag-init service so that compose
    supplies the correct project prefix and volume mount — no hardcoded prefix.
    """
    # flag-init has flag-data:/flag-data in its volumes declaration; compose
    # mounts it correctly regardless of the project name / directory.
    result = run_compose([
        "run", "--rm", "--no-deps",
        "flag-init", "cat", "/flag-data/flags.json"
    ], capture=True)

    if result.returncode != 0:
        # Alternate: override entrypoint explicitly (some images have non-cat default)
        result = run_compose([
            "run", "--rm", "--no-deps",
            "--entrypoint", "sh",
            "flag-init", "-c", "cat /flag-data/flags.json"
        ], capture=True)

    if result.returncode == 0 and result.stdout.strip():
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            pass

    # Fallback: try reading directly if we have a local path
    local_path = PROJECT_ROOT / "flag-data" / "flags.json"
    if local_path.exists():
        with open(local_path) as f:
            return json.load(f)

    return None


def _get_service_states():
    """Return dict of service_name -> state info."""
    result = run_compose(["ps", "--format", "json"], capture=True)
    if result.returncode != 0:
        return {}

    services = {}
    try:
        # Docker compose ps --format json outputs one JSON object per line
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            svc = json.loads(line)
            name = svc.get("Service", svc.get("Name", ""))
            # Normalize the service name
            for k in ("Service", "Name"):
                if k in svc:
                    name = svc[k]
                    break
            services[name] = svc
    except (json.JSONDecodeError, KeyError):
        # Fallback: parse tabular output
        pass

    return services


def _check_all_healthy(quiet=False):
    """Return True if all persistent services are healthy."""
    result = run_compose(["ps", "--format", "json"], capture=True)
    if result.returncode != 0:
        return False

    persistent = {"nginx", "node-app", "flask-platform", "victim-bot",
                  "postgres", "redis", "redis-commander"}
    healthy_set = set()

    try:
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            svc = json.loads(line)
            name = svc.get("Service", "")
            state = svc.get("State", "").lower()
            health = svc.get("Health", "").lower()

            if name in persistent:
                if state == "running" and health in ("healthy", ""):
                    healthy_set.add(name)
    except (json.JSONDecodeError, KeyError):
        pass

    return persistent.issubset(healthy_set)


def _print_status():
    """Print service status table. Returns True if all persistent services healthy."""
    result = run_compose(["ps", "--format", "json"], capture=True)

    persistent_services = {
        "nginx", "node-app", "flask-platform", "victim-bot",
        "postgres", "redis", "redis-commander"
    }

    # Public URL for each service (empty string = internal only)
    SERVICE_URLS = {
        "nginx":          "http://garden.lab:80",
        "flask-platform": "http://garden.lab/platform/",
        "node-app":       "http://garden.lab:80 (via nginx)",
        "victim-bot":     "(internal)",
        "postgres":       "(internal)",
        "redis":          "(internal)",
        "redis-commander":"(internal, app-internal only)",
        "flag-init":      "(one-shot)",
    }

    table = Table(title="Juice Garden — Service Status", show_header=True, border_style="dim")
    table.add_column("Service", style="cyan", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Health", no_wrap=True)
    table.add_column("Port", style="dim")
    table.add_column("URL", style="dim")

    all_healthy = True
    seen = set()

    if result.returncode == 0:
        try:
            rows = []
            for line in result.stdout.strip().splitlines():
                if not line.strip():
                    continue
                svc = json.loads(line)
                name = svc.get("Service", "")
                state = svc.get("State", "unknown")
                health = svc.get("Health", "")
                ports = svc.get("Publishers", [])
                port_str = ", ".join(
                    f"{p.get('PublishedPort', '')}" for p in ports if p.get("PublishedPort")
                ) if isinstance(ports, list) else ""

                rows.append((name, state, health, port_str))
                seen.add(name)

            # Add flag-init manually
            fi_result = run_compose(["ps", "-a", "--format", "json", "flag-init"], capture=True)
            try:
                for line in fi_result.stdout.strip().splitlines():
                    if not line.strip():
                        continue
                    svc = json.loads(line)
                    if svc.get("Service") == "flag-init":
                        rows.append(("flag-init", svc.get("State", ""), "", ""))
            except Exception:
                rows.append(("flag-init", "unknown", "", ""))

            for name, state, health, ports in rows:
                url = SERVICE_URLS.get(name, "")
                if name == "flag-init":
                    if "exit" in state.lower():
                        status_str = "[green]exited 0[/green]"
                        health_str = "[green]✓[/green]"
                    else:
                        status_str = state
                        health_str = ""
                else:
                    if state.lower() == "running":
                        status_str = "[green]running[/green]"
                    else:
                        status_str = f"[red]{state}[/red]"
                        if name in persistent_services:
                            all_healthy = False

                    if health.lower() == "healthy":
                        health_str = "[green]healthy[/green]"
                    elif health.lower() == "unhealthy":
                        health_str = "[red]unhealthy[/red]"
                        if name in persistent_services:
                            all_healthy = False
                    else:
                        health_str = health or "[dim]—[/dim]"

                table.add_row(name, status_str, health_str, ports, url)

        except Exception as e:
            console.print(f"[red]Error parsing status: {e}[/red]")
            all_healthy = False
    else:
        all_healthy = False
        console.print("[red]Could not get service status — is Docker running?[/red]")

    console.print(table)
    return all_healthy


def _print_urls():
    """Print service URLs."""
    console.print("\n[bold]Service URLs:[/bold]")
    console.print("  [cyan]http://garden.lab:80[/cyan]            — Garden Fresh (vulnerable app)")
    console.print("  [cyan]http://garden.lab/platform/[/cyan]     — Challenge Board")
    console.print("  [cyan]http://garden.lab/platform/exploit-server/[/cyan]  — Exploit Server")
    console.print("  [cyan]http://garden.lab:8081[/cyan]          — CS-02 exploit pages (cross-origin/same-site)")
    console.print("  [cyan]http://attacker.lab[/cyan]             — CS-03 exploit pages (cross-site)")
    console.print("  [dim]redis-commander: app-internal only (not host-published)[/dim]")
    console.print()
    console.print("[dim]Hint: Add to /etc/hosts:[/dim]  127.0.0.1  garden.lab  attacker.lab")
    console.print("[dim]Run `garden hosts check` to verify.[/dim]")
