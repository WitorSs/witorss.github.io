# scan2report

Turn messy Nmap XML output into a clean, prioritized report, in Markdown and HTML.

Nmap gives you *results*, not a *report*. After a scan you still have to read
through raw output, remember which services matter, and rewrite everything by
hand before it's useful in a pentest note or a ticket. `scan2report` does that
last mile. It parses the XML, flags the services worth looking at first, and
writes a tidy report you can drop straight into a writeup.

## Why

A raw Nmap scan of a couple of hosts is a wall of ports in numeric order: 21,
22, 80, 139, 445, 3306, 3389. Numeric order is not *useful* order. What a
pentester actually wants is to know which of these to touch first, and why.

`scan2report` reorders open ports by how interesting they are (a database or an
exposed SMB share outranks a plain web port), attaches a short note explaining
why each notable service is worth a first look, and keeps any NSE script output
that came with the scan. The result is something you can read in ten seconds
and paste into a report.

## Install

No dependencies beyond the Python standard library.

```bash
git clone https://github.com/WitorSs/witorss.github.io.git
cd witorss.github.io/tools/scan2report
```

Requires Python 3.8+.

## Usage

```bash
# 1. run nmap with XML output (-oX)
nmap -sV -sC -oX scan.xml 10.10.10.5

# 2. turn it into a report
python3 scan2report.py scan.xml

# outputs report.md and report.html
```

Options:

```
python3 scan2report.py scan.xml -o myreport -f both
```

| Flag | Meaning | Default |
|------|---------|---------|
| `-o, --output` | Output basename (no extension) | `report` |
| `-f, --format` | `md`, `html`, or `both` | `both` |

## How it decides what's "interesting"

The priority table lives at the top of `scan2report.py` (`NOTABLE_SERVICES`).
Each service maps to a severity (`high` or `medium`) and a one-line note. It's
deliberately simple and easy to read. The goal isn't to be a vulnerability
scanner, it's to surface the services a human should look at first. Edit the
table to match how *you* triage.

`high` covers clear-text protocols (FTP, Telnet), exposed databases (MySQL,
Postgres, Redis, Mongo), remote-access services (RDP, VNC) and SMB. `medium`
covers web surfaces, SSH, SMTP, DNS and similar: worth enumerating, rarely the
first thing you break.

## Note

Built as a learning project. It reads Nmap's XML (`-oX`) output only, not the
grepable or normal text formats, because XML is the one structured format Nmap
guarantees. See the full write-up on
[witorss.github.io](https://witorss.github.io).

---
Author: **Allan Vitor** · [witorss.github.io](https://witorss.github.io)
