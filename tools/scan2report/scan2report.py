#!/usr/bin/env python3
"""
scan2report. Turn messy Nmap XML output into a clean, prioritized report.

Nmap gives you results, not a report. When you finish a scan you still have to
read through raw output, remember which services matter, and rewrite it all by
hand before it's useful in a pentest note or a ticket. scan2report does that
last mile. It parses the XML, flags the services worth looking at first, and
writes a tidy Markdown and/or HTML report you can drop straight into a writeup.

Usage:
    nmap -sV -sC -oX scan.xml <target>
    python3 scan2report.py scan.xml
    python3 scan2report.py scan.xml -o report --format both

Author: Allan Vitor  ·  https://witorss.github.io
"""

import argparse
import html
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime


# ---------------------------------------------------------------------------
# Domain knowledge: which services deserve attention first.
#
# This table is the part that turns a parser into something useful. Anyone can
# print a list of open ports; the value is in knowing which ones a pentester
# looks at first and why. Each entry is a short, honest note, not a
# vulnerability claim, just why the service is worth a first look.
# ---------------------------------------------------------------------------
NOTABLE_SERVICES = {
    "ftp":           ("high",   "Clear-text protocol; check for anonymous login and known vsftpd/proftpd CVEs."),
    "telnet":        ("high",   "Clear-text remote access; credentials travel unencrypted."),
    "microsoft-ds":  ("high",   "SMB. Classic target for enumeration, null sessions and EternalBlue-era CVEs."),
    "netbios-ssn":   ("high",   "SMB/NetBIOS. Enumerate shares and users; often paired with 445."),
    "smb":           ("high",   "SMB. Enumerate shares, users and known CVEs."),
    "ms-wbt-server": ("high",   "RDP exposed. Check for weak creds, NLA, and BlueKeep-era CVEs."),
    "mysql":         ("high",   "Database exposed to the network; test default/weak creds and version CVEs."),
    "ms-sql-s":      ("high",   "MSSQL exposed; test weak creds, xp_cmdshell, version CVEs."),
    "postgresql":    ("high",   "Database exposed; test default creds and version CVEs."),
    "mongodb":       ("high",   "NoSQL DB. Historically ships with no auth; check for open access."),
    "redis":         ("high",   "Often unauthenticated; can lead to RCE via config write."),
    "vnc":           ("high",   "Remote desktop; frequently weak or no authentication."),
    "rlogin":        ("high",   "Legacy trust-based remote access; insecure by design."),
    "http":          ("medium", "Web surface. Enumerate directories, tech stack and app-level issues."),
    "https":         ("medium", "Web surface over TLS. Enumerate the app; also review the certificate."),
    "http-proxy":    ("medium", "Proxy or alt web port. Enumerate as a web app, check for SSRF pivots."),
    "ssh":           ("medium", "Remote access. Note the version, check weak creds and key auth policy."),
    "smtp":          ("medium", "Mail. Test user enumeration (VRFY/EXPN) and open relay."),
    "dns":           ("medium", "Check for zone transfers (AXFR) and version disclosure."),
    "rpcbind":       ("medium", "RPC. Enumerate exposed services via rpcinfo."),
    "snmp":          ("medium", "Often uses default community strings ('public'); enumerate device info."),
    "ldap":          ("medium", "Directory service. Enumerate naming contexts and users."),
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEVERITY_LABEL = {
    "high": "High interest",
    "medium": "Worth a look",
    "low": "Low interest",
    "info": "Informational",
}


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra: str = ""
    scripts: dict = field(default_factory=dict)

    @property
    def severity(self) -> str:
        if self.state != "open":
            return "info"
        sev, _ = NOTABLE_SERVICES.get(self.service, ("low", ""))
        return sev

    @property
    def note(self) -> str:
        _, note = NOTABLE_SERVICES.get(self.service, ("", ""))
        return note

    @property
    def version_string(self) -> str:
        parts = [p for p in (self.product, self.version, self.extra) if p]
        return " ".join(parts).strip()


@dataclass
class Host:
    address: str
    hostname: str = ""
    state: str = "unknown"
    ports: list = field(default_factory=list)

    @property
    def open_ports(self):
        return [p for p in self.ports if p.state == "open"]


def parse_nmap_xml(path: str) -> tuple:
    """Parse an Nmap XML file into a list of Host objects and scan metadata."""
    try:
        tree = ET.parse(path)
    except FileNotFoundError:
        sys.exit(f"[!] File not found: {path}")
    except ET.ParseError as e:
        sys.exit(f"[!] Not valid XML (did you use nmap -oX?): {e}")

    root = tree.getroot()
    if root.tag != "nmaprun":
        sys.exit("[!] This doesn't look like Nmap XML output. Use: nmap -oX scan.xml <target>")

    meta = {
        "args": root.get("args", ""),
        "started": root.get("startstr", ""),
        "version": root.get("version", ""),
    }

    hosts = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = status_el.get("state", "unknown") if status_el is not None else "unknown"

        addr = ""
        for a in host_el.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break

        hostname = ""
        hn = host_el.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")

        host = Host(address=addr, hostname=hostname, state=state)

        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            svc_el = port_el.find("service")
            port = Port(
                number=int(port_el.get("portid")),
                protocol=port_el.get("protocol", "tcp"),
                state=state_el.get("state", "unknown") if state_el is not None else "unknown",
            )
            if svc_el is not None:
                port.service = svc_el.get("name", "")
                port.product = svc_el.get("product", "")
                port.version = svc_el.get("version", "")
                port.extra = svc_el.get("extrainfo", "")
            for script_el in port_el.findall("script"):
                port.scripts[script_el.get("id", "")] = script_el.get("output", "")
            host.ports.append(port)

        host.ports.sort(key=lambda p: p.number)
        hosts.append(host)

    return hosts, meta


def summarize(hosts: list) -> dict:
    """Build the numbers that go at the top of the report."""
    hosts_up = [h for h in hosts if h.state == "up"]
    all_open = [p for h in hosts_up for p in h.open_ports]
    by_sev = {}
    for p in all_open:
        by_sev.setdefault(p.severity, []).append(p)
    return {
        "hosts_total": len(hosts),
        "hosts_up": len(hosts_up),
        "open_ports": len(all_open),
        "high": len(by_sev.get("high", [])),
        "medium": len(by_sev.get("medium", [])),
    }


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------
def render_markdown(hosts: list, meta: dict) -> str:
    s = summarize(hosts)
    out = []
    out.append("# Scan Report\n")
    out.append(f"*Generated by scan2report on {datetime.now():%Y-%m-%d %H:%M}*\n")
    if meta.get("args"):
        out.append(f"**Command:** `{meta['args']}`  ")
    if meta.get("started"):
        out.append(f"**Started:** {meta['started']}  ")
    out.append("")
    out.append("## Summary\n")
    out.append(f"- **Hosts up:** {s['hosts_up']} / {s['hosts_total']}")
    out.append(f"- **Open ports:** {s['open_ports']}")
    out.append(f"- **High interest:** {s['high']}")
    out.append(f"- **Worth a look:** {s['medium']}")
    out.append("")

    for host in hosts:
        if host.state != "up":
            continue
        title = host.address + (f" ({host.hostname})" if host.hostname else "")
        out.append(f"## {title}\n")
        open_ports = host.open_ports
        if not open_ports:
            out.append("_No open ports._\n")
            continue

        # sort by severity so the interesting stuff is at the top
        open_ports.sort(key=lambda p: (SEVERITY_ORDER[p.severity], p.number))

        out.append("| Port | Service | Version | Interest |")
        out.append("|------|---------|---------|----------|")
        for p in open_ports:
            interest = SEVERITY_LABEL[p.severity]
            out.append(
                f"| {p.number}/{p.protocol} | {p.service or '-'} "
                f"| {p.version_string or '-'} | {interest} |"
            )
        out.append("")

        # call-outs: only for the ports that actually deserve a note
        notable = [p for p in open_ports if p.severity in ("high", "medium") and p.note]
        if notable:
            out.append("**Where to look first:**\n")
            for p in notable:
                out.append(f"- **{p.number}/{p.service}**: {p.note}")
            out.append("")

        # any nmap script output we captured, since it's often the useful part
        scripted = [p for p in open_ports if p.scripts]
        if scripted:
            out.append("**Script output:**\n")
            for p in scripted:
                for sid, output in p.scripts.items():
                    clean = output.strip().replace("\n", " ")
                    out.append(f"- `{p.number}` `{sid}`: {clean}")
            out.append("")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# HTML output. Self-contained, no external assets, dark theme.
# ---------------------------------------------------------------------------
def render_html(hosts: list, meta: dict) -> str:
    s = summarize(hosts)
    sev_color = {"high": "#e5534b", "medium": "#d9a441", "low": "#5a6472", "info": "#404855"}

    rows_html = []
    for host in hosts:
        if host.state != "up":
            continue
        title = html.escape(host.address + (f" ({host.hostname})" if host.hostname else ""))
        rows_html.append(f'<h2>{title}</h2>')
        open_ports = host.open_ports
        if not open_ports:
            rows_html.append('<p class="muted">No open ports.</p>')
            continue
        open_ports.sort(key=lambda p: (SEVERITY_ORDER[p.severity], p.number))
        rows_html.append('<table><thead><tr><th>Port</th><th>Service</th><th>Version</th><th>Interest</th></tr></thead><tbody>')
        for p in open_ports:
            c = sev_color[p.severity]
            rows_html.append(
                f'<tr><td><code>{p.number}/{p.protocol}</code></td>'
                f'<td>{html.escape(p.service or "-")}</td>'
                f'<td>{html.escape(p.version_string or "-")}</td>'
                f'<td><span class="pill" style="background:{c}">{SEVERITY_LABEL[p.severity]}</span></td></tr>'
            )
        rows_html.append('</tbody></table>')
        notable = [p for p in open_ports if p.severity in ("high", "medium") and p.note]
        if notable:
            rows_html.append('<p class="lead">Where to look first:</p><ul>')
            for p in notable:
                rows_html.append(f'<li><b>{p.number}/{html.escape(p.service)}</b>: {html.escape(p.note)}</li>')
            rows_html.append('</ul>')

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan Report</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#1b1f24;
         color:#c9d1d9; max-width:900px; margin:0 auto; padding:2rem 1.2rem; line-height:1.5; }}
  h1 {{ margin-bottom:.2rem; }}
  h2 {{ margin-top:2rem; border-bottom:1px solid #30363d; padding-bottom:.3rem; }}
  .meta {{ color:#8b949e; font-size:.9rem; margin-bottom:1.5rem; }}
  .meta code {{ color:#79c0ff; }}
  .cards {{ display:flex; gap:1rem; flex-wrap:wrap; margin:1.5rem 0; }}
  .card {{ background:#22272e; border:1px solid #30363d; border-radius:10px;
          padding:1rem 1.3rem; min-width:120px; }}
  .card .n {{ font-size:1.8rem; font-weight:700; }}
  .card .l {{ color:#8b949e; font-size:.85rem; }}
  table {{ width:100%; border-collapse:collapse; margin:.5rem 0 1rem; }}
  th, td {{ text-align:left; padding:.5rem .6rem; border-bottom:1px solid #30363d; }}
  th {{ color:#8b949e; font-weight:600; font-size:.85rem; text-transform:uppercase; letter-spacing:.03em; }}
  code {{ background:#2d333b; padding:.1rem .4rem; border-radius:4px; color:#79c0ff; }}
  .pill {{ color:#fff; padding:.15rem .55rem; border-radius:20px; font-size:.78rem; white-space:nowrap; }}
  .lead {{ font-weight:600; margin-bottom:.3rem; }}
  .muted {{ color:#8b949e; }}
  footer {{ margin-top:3rem; color:#8b949e; font-size:.85rem; border-top:1px solid #30363d; padding-top:1rem; }}
  footer a {{ color:#79c0ff; text-decoration:none; }}
</style></head><body>
<h1>Scan Report</h1>
<div class="meta">
  Generated by scan2report on {datetime.now():%Y-%m-%d %H:%M}<br>
  {"<b>Command:</b> <code>" + html.escape(meta['args']) + "</code><br>" if meta.get('args') else ""}
  {"<b>Started:</b> " + html.escape(meta['started']) if meta.get('started') else ""}
</div>
<div class="cards">
  <div class="card"><div class="n">{s['hosts_up']}/{s['hosts_total']}</div><div class="l">Hosts up</div></div>
  <div class="card"><div class="n">{s['open_ports']}</div><div class="l">Open ports</div></div>
  <div class="card"><div class="n" style="color:#e5534b">{s['high']}</div><div class="l">High interest</div></div>
  <div class="card"><div class="n" style="color:#d9a441">{s['medium']}</div><div class="l">Worth a look</div></div>
</div>
{''.join(rows_html)}
<footer>Generated by <b>scan2report</b> · <a href="https://witorss.github.io">witorss.github.io</a></footer>
</body></html>"""


def main():
    parser = argparse.ArgumentParser(
        description="Turn Nmap XML output into a clean, prioritized report.",
        epilog="Example: nmap -sV -sC -oX scan.xml 10.10.10.5 && python3 scan2report.py scan.xml",
    )
    parser.add_argument("xml", help="Nmap XML file (produced with: nmap -oX file.xml <target>)")
    parser.add_argument("-o", "--output", default="report",
                        help="Output basename without extension (default: report)")
    parser.add_argument("-f", "--format", choices=["md", "html", "both"], default="both",
                        help="Output format (default: both)")
    args = parser.parse_args()

    hosts, meta = parse_nmap_xml(args.xml)
    if not hosts:
        sys.exit("[!] No hosts found in the scan.")

    s = summarize(hosts)

    if args.format in ("md", "both"):
        md = render_markdown(hosts, meta)
        with open(f"{args.output}.md", "w") as f:
            f.write(md)
        print(f"[+] Markdown written to {args.output}.md")

    if args.format in ("html", "both"):
        html_out = render_html(hosts, meta)
        with open(f"{args.output}.html", "w") as f:
            f.write(html_out)
        print(f"[+] HTML written to {args.output}.html")

    print(f"[+] {s['hosts_up']} host(s) up, {s['open_ports']} open port(s), "
          f"{s['high']} high-interest.")


if __name__ == "__main__":
    main()
