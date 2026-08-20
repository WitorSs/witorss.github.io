#!/usr/bin/env python3
"""
logsentry. Find the attacks hiding in your auth logs.

A Linux auth log is thousands of lines where a handful matter. logsentry reads
an SSH auth log, groups events by source IP, and surfaces the things a defender
cares about: brute-force sources, and (most important) any brute force that
ended in a successful login. It writes the same clean Markdown and HTML report
as its sibling tool scan2report, so findings are ready to paste into a ticket.

Usage:
    python3 logsentry.py /var/log/auth.log
    python3 logsentry.py auth.log -o incident --format both --threshold 15

Author: Allan Vitor  ·  https://witorss.github.io
"""

import argparse
import html
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime


# ---------------------------------------------------------------------------
# Log line patterns.
#
# This dict is the extensible part. Each analyzer is just a set of regexes plus
# a way to read the events it produces. Today there's one analyzer (SSH auth);
# adding a web-access-log analyzer later means adding another entry here, not
# rewriting the tool. The report layer downstream doesn't care where events
# came from.
# ---------------------------------------------------------------------------
SSH_PATTERNS = {
    "failed": re.compile(
        r"^(?P<ts>\w{3}\s+\d+\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Failed password for (?:invalid user )?(?P<user>\S+)\s+"
        r"from (?P<ip>[\d.]+)\s+port\s+\d+"
    ),
    "accepted": re.compile(
        r"^(?P<ts>\w{3}\s+\d+\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Accepted (?:password|publickey) for (?P<user>\S+)\s+"
        r"from (?P<ip>[\d.]+)\s+port\s+\d+"
    ),
}


@dataclass
class IPActivity:
    ip: str
    failed: int = 0
    accepted: int = 0
    users_failed: set = field(default_factory=set)
    users_accepted: set = field(default_factory=set)
    first_seen: str = ""
    last_seen: str = ""

    @property
    def total(self) -> int:
        return self.failed + self.accepted


@dataclass
class Finding:
    severity: str        # "critical" | "high" | "info"
    ip: str
    title: str
    detail: str


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}
SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "Brute force",
    "medium": "Suspicious",
    "info": "Informational",
}


def parse_auth_log(path: str) -> dict:
    """Read an SSH auth log and aggregate activity per source IP."""
    try:
        fh = open(path, "r", errors="replace")
    except FileNotFoundError:
        sys.exit(f"[!] File not found: {path}")

    activity = {}
    matched = 0
    with fh:
        for line in fh:
            for kind, pattern in SSH_PATTERNS.items():
                m = pattern.search(line)
                if not m:
                    continue
                matched += 1
                ip = m.group("ip")
                user = m.group("user")
                ts = m.group("ts")
                act = activity.setdefault(ip, IPActivity(ip=ip))
                if not act.first_seen:
                    act.first_seen = ts
                act.last_seen = ts
                if kind == "failed":
                    act.failed += 1
                    act.users_failed.add(user)
                else:
                    act.accepted += 1
                    act.users_accepted.add(user)
                break

    if matched == 0:
        sys.exit("[!] No SSH auth events found. Is this an sshd auth log "
                 "(e.g. /var/log/auth.log)?")
    return activity


def analyze(activity: dict, threshold: int) -> tuple:
    """Turn raw per-IP activity into prioritized findings."""
    findings = []
    for ip, act in activity.items():
        # The finding that matters most: many failures then a success from the
        # same IP. That's a brute force that likely worked.
        if act.failed >= threshold and act.accepted > 0:
            users = ", ".join(sorted(act.users_accepted)) or "unknown"
            findings.append(Finding(
                "critical", ip,
                "Successful login after repeated failures",
                f"{act.failed} failed attempts followed by a successful login "
                f"as [{users}]. Treat this host as potentially compromised: "
                f"review the session, rotate the account's credentials, and "
                f"check for persistence."
            ))
        # Clear brute force with no (recorded) success.
        elif act.failed >= threshold:
            findings.append(Finding(
                "high", ip,
                "Brute-force source",
                f"{act.failed} failed logins across {len(act.users_failed)} "
                f"username(s). No successful login recorded. Consider blocking "
                f"this IP and enabling rate-limiting (fail2ban) if not already."
            ))
        # Below threshold but still worth a note if it targeted several users.
        elif act.failed >= 3 and len(act.users_failed) >= 3:
            findings.append(Finding(
                "medium", ip,
                "Low-volume user enumeration",
                f"{act.failed} failed attempts across {len(act.users_failed)} "
                f"usernames. Below the brute-force threshold but the spread of "
                f"usernames suggests probing."
            ))

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.ip))
    stats = {
        "ips": len(activity),
        "total_failed": sum(a.failed for a in activity.values()),
        "total_accepted": sum(a.accepted for a in activity.values()),
        "critical": sum(1 for f in findings if f.severity == "critical"),
        "high": sum(1 for f in findings if f.severity == "high"),
    }
    return findings, stats


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------
def render_markdown(findings, stats, activity, threshold) -> str:
    out = []
    out.append("# Auth Log Analysis\n")
    out.append(f"*Generated by logsentry on {datetime.now():%Y-%m-%d %H:%M}*  ")
    out.append(f"*Brute-force threshold: {threshold} failed attempts*\n")

    out.append("## Summary\n")
    out.append(f"- **Source IPs seen:** {stats['ips']}")
    out.append(f"- **Failed logins:** {stats['total_failed']}")
    out.append(f"- **Accepted logins:** {stats['total_accepted']}")
    out.append(f"- **Critical findings:** {stats['critical']}")
    out.append(f"- **Brute-force sources:** {stats['high']}")
    out.append("")

    if findings:
        out.append("## Findings\n")
        for f in findings:
            out.append(f"### [{SEVERITY_LABEL[f.severity]}] {f.ip} — {f.title}\n")
            out.append(f"{f.detail}\n")
    else:
        out.append("## Findings\n")
        out.append("_No brute-force activity above the threshold. Nothing stood out._\n")

    # full table for context, sorted by failures
    out.append("## All source IPs\n")
    out.append("| IP | Failed | Accepted | Usernames tried |")
    out.append("|----|--------|----------|-----------------|")
    for ip, act in sorted(activity.items(), key=lambda kv: kv[1].failed, reverse=True):
        users = len(act.users_failed | act.users_accepted)
        out.append(f"| {ip} | {act.failed} | {act.accepted} | {users} |")
    out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# HTML output. Matches scan2report's look so the Tools page stays consistent.
# ---------------------------------------------------------------------------
def render_html(findings, stats, activity, threshold) -> str:
    sev_color = {"critical": "#e5534b", "high": "#d9a441", "medium": "#8957e5", "info": "#404855"}

    cards = f"""
<div class="cards">
  <div class="card"><div class="n">{stats['ips']}</div><div class="l">Source IPs</div></div>
  <div class="card"><div class="n">{stats['total_failed']}</div><div class="l">Failed logins</div></div>
  <div class="card"><div class="n" style="color:#e5534b">{stats['critical']}</div><div class="l">Critical</div></div>
  <div class="card"><div class="n" style="color:#d9a441">{stats['high']}</div><div class="l">Brute-force</div></div>
</div>"""

    find_html = []
    if findings:
        find_html.append("<h2>Findings</h2>")
        for f in findings:
            c = sev_color[f.severity]
            find_html.append(
                f'<div class="finding" style="border-left-color:{c}">'
                f'<div class="finding-head"><span class="pill" style="background:{c}">'
                f'{SEVERITY_LABEL[f.severity]}</span> <code>{html.escape(f.ip)}</code> '
                f'<b>{html.escape(f.title)}</b></div>'
                f'<p>{html.escape(f.detail)}</p></div>'
            )
    else:
        find_html.append("<h2>Findings</h2><p class='muted'>No brute-force activity above the threshold.</p>")

    table_rows = []
    for ip, act in sorted(activity.items(), key=lambda kv: kv[1].failed, reverse=True):
        users = len(act.users_failed | act.users_accepted)
        table_rows.append(
            f"<tr><td><code>{html.escape(ip)}</code></td><td>{act.failed}</td>"
            f"<td>{act.accepted}</td><td>{users}</td></tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Auth Log Analysis</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#1b1f24;
         color:#c9d1d9; max-width:900px; margin:0 auto; padding:2rem 1.2rem; line-height:1.5; }}
  h1 {{ margin-bottom:.2rem; }}
  h2 {{ margin-top:2rem; border-bottom:1px solid #30363d; padding-bottom:.3rem; }}
  .meta {{ color:#8b949e; font-size:.9rem; margin-bottom:1.5rem; }}
  .cards {{ display:flex; gap:1rem; flex-wrap:wrap; margin:1.5rem 0; }}
  .card {{ background:#22272e; border:1px solid #30363d; border-radius:10px;
          padding:1rem 1.3rem; min-width:120px; }}
  .card .n {{ font-size:1.8rem; font-weight:700; }}
  .card .l {{ color:#8b949e; font-size:.85rem; }}
  .finding {{ background:#22272e; border:1px solid #30363d; border-left:4px solid #888;
             border-radius:8px; padding:.9rem 1.1rem; margin:.8rem 0; }}
  .finding-head {{ margin-bottom:.4rem; }}
  .finding p {{ margin:.3rem 0 0; color:#c9d1d9; }}
  table {{ width:100%; border-collapse:collapse; margin:.5rem 0 1rem; }}
  th, td {{ text-align:left; padding:.5rem .6rem; border-bottom:1px solid #30363d; }}
  th {{ color:#8b949e; font-weight:600; font-size:.85rem; text-transform:uppercase; letter-spacing:.03em; }}
  code {{ background:#2d333b; padding:.1rem .4rem; border-radius:4px; color:#79c0ff; }}
  .pill {{ color:#fff; padding:.15rem .55rem; border-radius:20px; font-size:.78rem; white-space:nowrap; }}
  .muted {{ color:#8b949e; }}
  footer {{ margin-top:3rem; color:#8b949e; font-size:.85rem; border-top:1px solid #30363d; padding-top:1rem; }}
  footer a {{ color:#79c0ff; text-decoration:none; }}
</style></head><body>
<h1>Auth Log Analysis</h1>
<div class="meta">Generated by logsentry on {datetime.now():%Y-%m-%d %H:%M} · brute-force threshold: {threshold} failed attempts</div>
{cards}
{''.join(find_html)}
<h2>All source IPs</h2>
<table><thead><tr><th>IP</th><th>Failed</th><th>Accepted</th><th>Usernames</th></tr></thead>
<tbody>{''.join(table_rows)}</tbody></table>
<footer>Generated by <b>logsentry</b> · <a href="https://witorss.github.io">witorss.github.io</a></footer>
</body></html>"""


def main():
    parser = argparse.ArgumentParser(
        description="Find brute-force attacks and successful compromises in SSH auth logs.",
        epilog="Example: python3 logsentry.py /var/log/auth.log -o report -f both",
    )
    parser.add_argument("logfile", help="Path to an SSH auth log (e.g. /var/log/auth.log)")
    parser.add_argument("-o", "--output", default="report",
                        help="Output basename without extension (default: report)")
    parser.add_argument("-f", "--format", choices=["md", "html", "both"], default="both",
                        help="Output format (default: both)")
    parser.add_argument("-t", "--threshold", type=int, default=10,
                        help="Failed attempts before an IP is flagged as brute force (default: 10)")
    args = parser.parse_args()

    activity = parse_auth_log(args.logfile)
    findings, stats = analyze(activity, args.threshold)

    if args.format in ("md", "both"):
        with open(f"{args.output}.md", "w") as f:
            f.write(render_markdown(findings, stats, activity, args.threshold))
        print(f"[+] Markdown written to {args.output}.md")
    if args.format in ("html", "both"):
        with open(f"{args.output}.html", "w") as f:
            f.write(render_html(findings, stats, activity, args.threshold))
        print(f"[+] HTML written to {args.output}.html")

    print(f"[+] {stats['ips']} IP(s), {stats['total_failed']} failed login(s), "
          f"{stats['critical']} critical, {stats['high']} brute-force source(s).")
    if stats["critical"]:
        print("[!] Critical: at least one brute force ended in a successful login. Review now.")


if __name__ == "__main__":
    main()
