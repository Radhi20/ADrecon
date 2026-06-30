#!/usr/bin/env python3
"""
ADrecon - Active Directory Attack Chain Automation Tool
Target: Windows Active Directory environments
Method: LDAP enumeration + Kerberos attacks + reporting

Author: Hamouda Mohamed Radhi
"""

import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

# Rich UI
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from rich.text import Text
from rich.layout import Layout
from rich.align import Align

# LDAP
import ldap3
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from ldap3.core.exceptions import LDAPException

# Impacket
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5 import constants
from impacket.krb5.types import KerberosTime, Principal
from impacket.krb5.asn1 import TGS_REP
from impacket.ntlm import compute_lmhash, compute_nthash

import socket
import struct
import hashlib
import binascii

console = Console()

# ─── Banner ───────────────────────────────────────────────────────────────────

BANNER = """
[bold red]
    _    ____  ____  _____ ____ ___  _   _ 
   / \  |  _ \|  _ \| ____/ ___/ _ \| \ | |
  / _ \ | | | | |_) |  _|| |  | | | |  \| |
 / ___ \| |_| |  _ <| |__| |__| |_| | |\  |
/_/   \_\____/|_| \_\_____\____\___/|_| \_|
[/bold red]
[dim]Active Directory Attack Chain Automation[/dim]
[dim]Author: Hamouda Mohamed Radhi · M1 SSI · USTHB[/dim]
"""

# ─── Config ───────────────────────────────────────────────────────────────────

class Config:
    def __init__(self):
        self.dc_ip = ""
        self.domain = ""
        self.username = ""
        self.password = ""
        self.base_dn = ""
        self.conn = None
        self.findings = []
        self.report_data = {
            "meta": {},
            "users": [],
            "groups": [],
            "computers": [],
            "kerberoastable": [],
            "asrep_roastable": [],
            "admin_users": [],
            "findings": []
        }

cfg = Config()

# ─── Helpers ──────────────────────────────────────────────────────────────────

def add_finding(severity: str, title: str, description: str, affected: list = []):
    cfg.findings.append({
        "severity": severity,
        "title": title,
        "description": description,
        "affected": affected,
        "timestamp": datetime.now().isoformat()
    })

def section(title: str):
    console.print(f"\n[bold yellow]{'─' * 50}[/bold yellow]")
    console.print(f"[bold white]  {title}[/bold white]")
    console.print(f"[bold yellow]{'─' * 50}[/bold yellow]")

def success(msg): console.print(f"[bold green][+][/bold green] {msg}")
def info(msg):    console.print(f"[bold blue][*][/bold blue] {msg}")
def warn(msg):    console.print(f"[bold yellow][!][/bold yellow] {msg}")
def error(msg):   console.print(f"[bold red][✗][/bold red] {msg}")

# ─── Phase 1: Connection & Auth ───────────────────────────────────────────────

def connect_ldap() -> bool:
    section("Phase 1 — LDAP Connection")
    try:
        server = Server(cfg.dc_ip, get_info=ALL, port=389)
        conn = Connection(
            server,
            user=f"{cfg.domain}\\{cfg.username}",
            password=cfg.password,
            authentication=NTLM,
            auto_bind=True
        )
        cfg.conn = conn
        cfg.base_dn = f"DC={cfg.domain.replace('.', ',DC=')}"
        success(f"Connected to {cfg.dc_ip} as [bold]{cfg.domain}\\{cfg.username}[/bold]")
        success(f"Base DN: {cfg.base_dn}")

        # Get domain info
        conn.search(cfg.base_dn, '(objectClass=domain)',
                    attributes=['name', 'whenCreated', 'msDS-Behavior-Version'])
        if conn.entries:
            info(f"Domain functional level: {conn.entries[0].entry_attributes_as_dict.get('msDS-Behavior-Version', ['Unknown'])[0]}")
        return True
    except LDAPException as e:
        error(f"LDAP connection failed: {e}")
        return False
    except Exception as e:
        error(f"Connection error: {e}")
        return False

# ─── Phase 2: Enumeration ─────────────────────────────────────────────────────

def enum_users():
    section("Phase 2a — User Enumeration")
    cfg.conn.search(
        cfg.base_dn,
        '(objectClass=user)',
        attributes=[
            'sAMAccountName', 'displayName', 'mail',
            'memberOf', 'userAccountControl',
            'pwdLastSet', 'lastLogon', 'description',
            'servicePrincipalName', 'adminCount'
        ],
        search_scope=SUBTREE
    )

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
    table.add_column("Username", style="white")
    table.add_column("Display Name", style="dim")
    table.add_column("UAC Flags", style="yellow")
    table.add_column("Admin", style="red")
    table.add_column("SPN", style="magenta")

    users = []
    for entry in cfg.conn.entries:
        attrs = entry.entry_attributes_as_dict
        sam = str(attrs['sAMAccountName'][0]) if attrs.get('sAMAccountName') else ''
        display = str(attrs['displayName'][0]) if attrs.get('displayName') else ''
        uac = attrs['userAccountControl'][0] if attrs.get('userAccountControl') else 0
        admin_count = attrs['adminCount'][0] if attrs.get('adminCount') else 0
        spns = attrs.get('servicePrincipalName') or []
        description = str(attrs['description'][0]) if attrs.get('description') else ''

        # UAC flag analysis
        flags = []
        if uac and int(uac) & 0x0002:  flags.append("DISABLED")
        if uac and int(uac) & 0x0010:  flags.append("LOCKOUT")
        if uac and int(uac) & 0x10000: flags.append("NO_EXPIRE")
        if uac and int(uac) & 0x400000: flags.append("NO_PREAUTH")

        is_admin = "✓" if admin_count and int(admin_count) > 0 else ""
        has_spn = "✓" if spns else ""
        flags_str = ", ".join(flags) if flags else "normal"

        user_data = {
            "username": sam,
            "display_name": display,
            "uac": int(uac) if uac else 0,
            "uac_flags": flags,
            "admin_count": int(admin_count) if admin_count else 0,
            "spns": list(spns),
            "description": description
        }
        users.append(user_data)
        cfg.report_data["users"].append(user_data)

        # Flag kerberoastable
        if spns and sam != "krbtgt":
            cfg.report_data["kerberoastable"].append(sam)
            add_finding("HIGH", "Kerberoastable Account",
                f"User '{sam}' has SPNs set — vulnerable to Kerberoasting",
                [sam])

        # Flag AS-REP roastable
        if uac and int(uac) & 0x400000:
            cfg.report_data["asrep_roastable"].append(sam)
            add_finding("HIGH", "AS-REP Roastable Account",
                f"User '{sam}' has 'Do not require Kerberos preauthentication' set",
                [sam])

        # Flag admin
        if admin_count and int(admin_count) > 0:
            cfg.report_data["admin_users"].append(sam)

        table.add_row(sam, display, flags_str, is_admin, has_spn)

    console.print(table)
    success(f"Found [bold]{len(users)}[/bold] users")
    return users

def enum_groups():
    section("Phase 2b — Group Enumeration")
    cfg.conn.search(
        cfg.base_dn,
        '(objectClass=group)',
        attributes=['sAMAccountName', 'member', 'description', 'adminCount'],
        search_scope=SUBTREE
    )

    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan")
    table.add_column("Group Name", style="white")
    table.add_column("Members", style="yellow", justify="right")
    table.add_column("Privileged", style="red")

    privileged_groups = ["domain admins", "enterprise admins", "schema admins",
                         "administrators", "account operators", "backup operators",
                         "admins du domaine", "administrateurs"]

    for entry in cfg.conn.entries:
        attrs = entry.entry_attributes_as_dict
        name = str(attrs['sAMAccountName'][0]) if attrs.get('sAMAccountName') else ''
        members = attrs.get('member') or []
        admin_count = attrs['adminCount'][0] if attrs.get('adminCount') else 0
        is_privileged = "⚠ YES" if name.lower() in privileged_groups or (admin_count and int(admin_count) > 0) else ""

        group_data = {
            "name": name,
            "member_count": len(members),
            "members": [str(m) for m in members],
            "privileged": bool(is_privileged)
        }
        cfg.report_data["groups"].append(group_data)

        if is_privileged and members:
            add_finding("MEDIUM", f"Privileged Group: {name}",
                f"Group '{name}' has {len(members)} member(s)",
                [str(m).split(',')[0].replace('CN=','') for m in members])

        table.add_row(name, str(len(members)), is_privileged)

    console.print(table)
    success(f"Found [bold]{len(cfg.report_data['groups'])}[/bold] groups")

def enum_computers():
    section("Phase 2c — Computer Enumeration")
    cfg.conn.search(
        cfg.base_dn,
        '(objectClass=computer)',
        attributes=['sAMAccountName', 'operatingSystem',
                    'operatingSystemVersion', 'lastLogon', 'dNSHostName'],
        search_scope=SUBTREE
    )

    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan")
    table.add_column("Hostname", style="white")
    table.add_column("OS", style="dim")
    table.add_column("DNS", style="blue")

    for entry in cfg.conn.entries:
        attrs = entry.entry_attributes_as_dict
        name = str(attrs['sAMAccountName'][0]) if attrs.get('sAMAccountName') else ''
        os_name = str(attrs['operatingSystem'][0]) if attrs.get('operatingSystem') else 'Unknown'
        dns = str(attrs['dNSHostName'][0]) if attrs.get('dNSHostName') else ''

        computer_data = {"name": name, "os": os_name, "dns": dns}
        cfg.report_data["computers"].append(computer_data)

        # Flag old OS
        if any(old in os_name for old in ["2008", "2003", "XP", "Vista", "7"]):
            add_finding("CRITICAL", "Outdated Operating System",
                f"Computer '{name}' runs '{os_name}' — end of life", [name])

        table.add_row(name, os_name, dns)

    console.print(table)
    success(f"Found [bold]{len(cfg.report_data['computers'])}[/bold] computers")

# ─── Phase 3: Attack Simulation ───────────────────────────────────────────────

def check_password_policy():
    section("Phase 3a — Password Policy Analysis")
    cfg.conn.search(
        cfg.base_dn,
        '(objectClass=domain)',
        attributes=['minPwdLength', 'pwdHistoryLength',
                    'maxPwdAge', 'lockoutThreshold', 'lockoutDuration']
    )

    if cfg.conn.entries:
        attrs = cfg.conn.entries[0].entry_attributes_as_dict
        min_len = attrs['minPwdLength'][0] if attrs.get('minPwdLength') else 0
        history = attrs['pwdHistoryLength'][0] if attrs.get('pwdHistoryLength') else 0
        lockout = attrs['lockoutThreshold'][0] if attrs.get('lockoutThreshold') else 0

        table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan")
        table.add_column("Policy", style="white")
        table.add_column("Value", style="yellow")
        table.add_column("Risk", style="red")

        rows = [
            ("Min Password Length", str(min_len), "⚠ WEAK" if int(min_len or 0) < 12 else "OK"),
            ("Password History", str(history), "⚠ WEAK" if int(history or 0) < 10 else "OK"),
            ("Lockout Threshold", str(lockout), "⚠ NO LOCKOUT" if int(lockout or 0) == 0 else "OK"),
        ]

        for row in rows:
            table.add_row(*row)
            if "WEAK" in row[2] or "NO" in row[2]:
                add_finding("MEDIUM", f"Weak Password Policy: {row[0]}",
                    f"{row[0]} is set to {row[1]}", [])

        console.print(table)

def simulate_kerberoasting():
    section("Phase 3b — Kerberoasting Simulation")
    if not cfg.report_data["kerberoastable"]:
        info("No Kerberoastable accounts found.")
        return

    warn(f"Found [bold]{len(cfg.report_data['kerberoastable'])}[/bold] Kerberoastable account(s):")
    for user in cfg.report_data["kerberoastable"]:
        console.print(f"  [red]→[/red] {user}")

    console.print("""
[dim]In a real attack, this would be exploited with:
  impacket-GetUserSPNs {domain}/{user}:{password} -dc-ip {dc_ip} -request
  hashcat -m 13100 hashes.txt rockyou.txt[/dim]
""".format(domain=cfg.domain, user=cfg.username,
           password="***", dc_ip=cfg.dc_ip))

def simulate_asrep_roasting():
    section("Phase 3c — AS-REP Roasting Simulation")
    if not cfg.report_data["asrep_roastable"]:
        info("No AS-REP Roastable accounts found.")
        return

    warn(f"Found [bold]{len(cfg.report_data['asrep_roastable'])}[/bold] AS-REP Roastable account(s):")
    for user in cfg.report_data["asrep_roastable"]:
        console.print(f"  [red]→[/red] {user}")

    console.print("""
[dim]In a real attack, this would be exploited with:
  impacket-GetNPUsers {domain}/ -usersfile users.txt -dc-ip {dc_ip} -no-pass
  hashcat -m 18200 hashes.txt rockyou.txt[/dim]
""".format(domain=cfg.domain, dc_ip=cfg.dc_ip))

def check_admin_shares():
    section("Phase 3d — Admin Share Access Check")
    info(f"Checking SMB admin share access on WIN10 (192.168.100.20)...")

    console.print("""
[dim]In a real attack, this would be checked with:
  crackmapexec smb 192.168.100.0/24 -u {user} -p {password}
  impacket-smbclient {domain}/{user}:{password}@192.168.100.20[/dim]
""".format(domain=cfg.domain, user=cfg.username, password="***"))

    add_finding("INFO", "Admin Share Check",
        "Manual verification recommended with crackmapexec or smbclient", [])

# ─── Phase 4: Report Generation ───────────────────────────────────────────────

def generate_report():
    section("Phase 4 — Report Generation")

    cfg.report_data["findings"] = cfg.findings
    cfg.report_data["meta"] = {
        "target_dc": cfg.dc_ip,
        "domain": cfg.domain,
        "operator": cfg.username,
        "timestamp": datetime.now().isoformat(),
        "total_users": len(cfg.report_data["users"]),
        "total_groups": len(cfg.report_data["groups"]),
        "total_computers": len(cfg.report_data["computers"]),
        "total_findings": len(cfg.findings),
        "kerberoastable": len(cfg.report_data["kerberoastable"]),
        "asrep_roastable": len(cfg.report_data["asrep_roastable"]),
    }

    # Save JSON
    Path("reports").mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"reports/adrecon_{ts}.json"
    with open(json_path, "w") as f:
        json.dump(cfg.report_data, f, indent=2, default=str)

    # Generate HTML
    html_path = f"reports/adrecon_{ts}.html"
    generate_html_report(html_path)

    success(f"JSON report: {json_path}")
    success(f"HTML report: {html_path}")

def generate_html_report(path: str):
    severity_color = {"CRITICAL": "#ff4444", "HIGH": "#e8673a",
                      "MEDIUM": "#f0c040", "INFO": "#4a9eff", "LOW": "#3dd68c"}

    findings_html = ""
    for f in cfg.findings:
        color = severity_color.get(f["severity"], "#888")
        affected = ", ".join(f["affected"]) if f["affected"] else "—"
        findings_html += f"""
        <div class="finding">
          <div class="finding-sev" style="background:{color}">{f['severity']}</div>
          <div class="finding-content">
            <div class="finding-title">{f['title']}</div>
            <div class="finding-desc">{f['description']}</div>
            <div class="finding-affected">Affected: {affected}</div>
          </div>
        </div>"""

    users_html = ""
    for u in cfg.report_data["users"]:
        flags = ", ".join(u["uac_flags"]) or "normal"
        spns = len(u["spns"])
        users_html += f"<tr><td>{u['username']}</td><td>{u['display_name']}</td><td>{flags}</td><td>{'✓' if u['admin_count'] else ''}</td><td>{spns}</td></tr>"

    meta = cfg.report_data["meta"]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ADrecon Report — {meta['domain']}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;500;600&display=swap');
  :root {{
    --bg:#0d0f14; --surface:#13161d; --border:#1e2330;
    --accent:#e8673a; --ok:#3dd68c; --text:#c8cdd8;
    --text-hi:#eef0f5; --muted:#5a6070; --mono:'JetBrains Mono',monospace;
    --sans:'Inter',sans-serif;
  }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--bg); color:var(--text); font-family:var(--sans); font-size:14px; }}
  header {{ border-bottom:1px solid var(--border); padding:40px 60px 32px; display:flex; justify-content:space-between; align-items:flex-end; }}
  .logo {{ font-family:var(--mono); font-size:11px; letter-spacing:.15em; color:var(--accent); text-transform:uppercase; margin-bottom:8px; }}
  h1 {{ font-size:28px; font-weight:600; color:var(--text-hi); }}
  .meta {{ font-family:var(--mono); font-size:11px; color:var(--muted); text-align:right; line-height:1.8; }}
  .stats {{ display:grid; grid-template-columns:repeat(5,1fr); border-bottom:1px solid var(--border); }}
  .stat {{ padding:24px 32px; border-right:1px solid var(--border); }}
  .stat:last-child {{ border-right:none; }}
  .stat-value {{ font-family:var(--mono); font-size:32px; font-weight:700; color:var(--text-hi); }}
  .stat-value.danger {{ color:var(--accent); }}
  .stat-label {{ font-size:10px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); margin-top:4px; }}
  main {{ padding:40px 60px; }}
  h2 {{ font-size:16px; font-weight:600; color:var(--text-hi); margin:32px 0 16px; padding-bottom:8px; border-bottom:1px solid var(--border); }}
  .finding {{ display:flex; gap:16px; background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:16px; margin-bottom:8px; }}
  .finding-sev {{ font-family:var(--mono); font-size:10px; font-weight:700; padding:4px 10px; border-radius:3px; color:#000; height:fit-content; white-space:nowrap; }}
  .finding-title {{ font-weight:600; color:var(--text-hi); margin-bottom:4px; }}
  .finding-desc {{ font-size:13px; color:var(--text); margin-bottom:4px; }}
  .finding-affected {{ font-family:var(--mono); font-size:11px; color:var(--muted); }}
  table {{ width:100%; border-collapse:collapse; background:var(--surface); border-radius:6px; overflow:hidden; }}
  th {{ background:var(--border); padding:10px 16px; text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); }}
  td {{ padding:10px 16px; border-bottom:1px solid var(--border); font-size:13px; }}
  tr:last-child td {{ border-bottom:none; }}
  footer {{ border-top:1px solid var(--border); padding:24px 60px; font-family:var(--mono); font-size:11px; color:var(--muted); display:flex; justify-content:space-between; margin-top:40px; }}
</style>
</head>
<body>
<header>
  <div>
    <div class="logo">ADrecon // Security Research</div>
    <h1>Active Directory Audit Report</h1>
  </div>
  <div class="meta">
    <div>Domain: {meta['domain']}</div>
    <div>DC: {meta['target_dc']}</div>
    <div>Generated: {meta['timestamp'][:19].replace('T',' ')}</div>
  </div>
</header>
<div class="stats">
  <div class="stat"><div class="stat-value">{meta['total_users']}</div><div class="stat-label">Users</div></div>
  <div class="stat"><div class="stat-value">{meta['total_groups']}</div><div class="stat-label">Groups</div></div>
  <div class="stat"><div class="stat-value">{meta['total_computers']}</div><div class="stat-label">Computers</div></div>
  <div class="stat"><div class="stat-value danger">{meta['total_findings']}</div><div class="stat-label">Findings</div></div>
  <div class="stat"><div class="stat-value danger">{meta['kerberoastable']}</div><div class="stat-label">Kerberoastable</div></div>
</div>
<main>
  <h2>Security Findings</h2>
  {findings_html if findings_html else '<p style="color:var(--muted)">No findings.</p>'}
  <h2>Users ({meta['total_users']})</h2>
  <table>
    <thead><tr><th>Username</th><th>Display Name</th><th>UAC Flags</th><th>Admin</th><th>SPNs</th></tr></thead>
    <tbody>{users_html}</tbody>
  </table>
</main>
<footer>
  <span>ADrecon — Active Directory Attack Chain Tool</span>
  <span>Hamouda Mohamed Radhi · M1 SSI · USTHB</span>
</footer>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)

# ─── Interactive Menu ──────────────────────────────────────────────────────────

def interactive_menu():
    while True:
        console.print("\n[bold cyan]┌─ MENU ──────────────────────────────┐[/bold cyan]")
        console.print("[bold cyan]│[/bold cyan]  [white]1.[/white] Full Auto Scan (all phases)      [bold cyan]│[/bold cyan]")
        console.print("[bold cyan]│[/bold cyan]  [white]2.[/white] Enumerate Users                  [bold cyan]│[/bold cyan]")
        console.print("[bold cyan]│[/bold cyan]  [white]3.[/white] Enumerate Groups                 [bold cyan]│[/bold cyan]")
        console.print("[bold cyan]│[/bold cyan]  [white]4.[/white] Enumerate Computers              [bold cyan]│[/bold cyan]")
        console.print("[bold cyan]│[/bold cyan]  [white]5.[/white] Password Policy Analysis         [bold cyan]│[/bold cyan]")
        console.print("[bold cyan]│[/bold cyan]  [white]6.[/white] Kerberoasting Check              [bold cyan]│[/bold cyan]")
        console.print("[bold cyan]│[/bold cyan]  [white]7.[/white] AS-REP Roasting Check            [bold cyan]│[/bold cyan]")
        console.print("[bold cyan]│[/bold cyan]  [white]8.[/white] Generate Report                  [bold cyan]│[/bold cyan]")
        console.print("[bold cyan]│[/bold cyan]  [white]0.[/white] Exit                             [bold cyan]│[/bold cyan]")
        console.print("[bold cyan]└─────────────────────────────────────┘[/bold cyan]")

        choice = Prompt.ask("\n[bold yellow]Select option[/bold yellow]")

        if choice == "1":
            enum_users()
            enum_groups()
            enum_computers()
            check_password_policy()
            simulate_kerberoasting()
            simulate_asrep_roasting()
            check_admin_shares()
            generate_report()
        elif choice == "2": enum_users()
        elif choice == "3": enum_groups()
        elif choice == "4": enum_computers()
        elif choice == "5": check_password_policy()
        elif choice == "6": simulate_kerberoasting()
        elif choice == "7": simulate_asrep_roasting()
        elif choice == "8": generate_report()
        elif choice == "0":
            console.print("\n[dim]Goodbye.[/dim]")
            sys.exit(0)
        else:
            warn("Invalid option.")

# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    console.print(BANNER)

    parser = argparse.ArgumentParser(description="ADrecon - AD Attack Chain Tool")
    parser.add_argument("--dc-ip",   help="Domain Controller IP")
    parser.add_argument("--domain",  help="Domain name (e.g. corp.local)")
    parser.add_argument("--user",    help="Username")
    parser.add_argument("--password",help="Password")
    parser.add_argument("--auto",    action="store_true", help="Run full scan without menu")
    args = parser.parse_args()

    # Get credentials
    cfg.dc_ip   = args.dc_ip   or Prompt.ask("[bold]DC IP[/bold]")
    cfg.domain  = args.domain  or Prompt.ask("[bold]Domain[/bold]", default="corp.local")
    cfg.username = args.user   or Prompt.ask("[bold]Username[/bold]")
    cfg.password = args.password or Prompt.ask("[bold]Password[/bold]", password=True)

    if not connect_ldap():
        sys.exit(1)

    if args.auto:
        enum_users()
        enum_groups()
        enum_computers()
        check_password_policy()
        simulate_kerberoasting()
        simulate_asrep_roasting()
        check_admin_shares()
        generate_report()
    else:
        interactive_menu()

if __name__ == "__main__":
    main()
