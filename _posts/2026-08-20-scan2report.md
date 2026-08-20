---
title: "Turning Nmap noise into a report worth reading""
author: allanvitor
categories: [Personal Projects]
tags: [Python, Nmap, Tooling, Automation, Reconnaissance, Reporting]
render_with_liquid: false
permalink: /posts/scan2report/
img_path: /images/scan2report/
image:
  path: /images/scan2report/card.jpg
---

Nmap gives you **results**, not a **report**. Every time I finished a scan I
found myself doing the same manual chore: reading through a wall of open ports,
mentally sorting the interesting ones from the noise, and then rewriting it all
into something presentable before it was any use in a note or a writeup. That
gap between what Nmap outputs and what a human actually wants to read is exactly
the kind of repetitive task worth automating. So I built a small tool to close
it: **scan2report**.

This post is less about the code and more about the *decisions* behind it,
because that's where the interesting part of tooling lives.

## The problem, concretely

Here's what a scan of two hosts looks like in raw form: a list of ports in
numeric order, 21, 22, 80, 139, 445, 3306, 3389, 8080. Numeric order is the
order Nmap happens to print in. It is **not** the order you care about.

When I look at that list as an attacker, my eyes jump straight to `21` (FTP,
clear-text), `445` (SMB), and `3306` (a database sitting on the network). The
web ports and SSH can wait. But nothing in the raw output reflects that
priority, so I have to impose it in my head, every single time. The tool's whole
job is to move that triage out of my head and onto the page.

## Decision 1: parse the XML, not the text

Nmap can output in three formats: normal (`-oN`), grepable (`-oG`), and XML
(`-oX`). It's tempting to just scrape the normal text output, since it's what
you already see on screen. I didn't, and the reason matters.

The normal output is meant for *humans*, and human-facing formats are unstable:
spacing changes, fields shift, script output wraps unpredictably. Parsing it
with string splitting or regex is fragile, working until Nmap tweaks a label and
silently breaks. The XML output exists precisely because it's the **structured,
guaranteed contract**. Every port is an element with typed attributes; there's
no guessing.

```python
tree = ET.parse(path)
root = tree.getroot()
for host_el in root.findall("host"):
    for port_el in host_el.findall("ports/port"):
        number = int(port_el.get("portid"))
        state  = port_el.find("state").get("state")
```

Choosing the structured input over the convenient one is the kind of decision
that separates a script that works on your machine today from a tool that keeps
working. Python's built-in `xml.etree.ElementTree` handles it with no external
dependencies, which also means anyone can run this without a `pip install`.

## Decision 2: the priority table is the actual product

Anyone can print a list of open ports. The value isn't in *listing* them, it's
in knowing **which ones a pentester looks at first, and why**. That knowledge is
the tool's brain, and I made it an explicit, readable table rather than burying
it in logic:

```python
NOTABLE_SERVICES = {
    "ftp":          ("high",   "Clear-text protocol; check anonymous login and vsftpd/proftpd CVEs."),
    "microsoft-ds": ("high",   "SMB. Enumeration, null sessions, EternalBlue-era CVEs."),
    "mysql":        ("high",   "Database exposed to the network; test default/weak creds."),
    "http":         ("medium", "Web surface. Enumerate directories, tech stack, app issues."),
    "ssh":          ("medium", "Remote access. Note version, check weak creds and key policy."),
    # ...
}
```

Two design choices here. First, the notes are deliberately **honest**: they say
*where to look*, not *"VULNERABLE"*. The tool doesn't claim to find
vulnerabilities. It points a human at the services worth a first look, which is
a claim it can actually stand behind. Second, the table is trivial to edit. Your
triage isn't my triage; the priorities you care about should be one line away,
not tangled in code.

With the table in place, sorting becomes simple. Open ports get reordered by
severity so the interesting stuff floats to the top:

```python
open_ports.sort(key=lambda p: (SEVERITY_ORDER[p.severity], p.number))
```

That one line is the difference between "a list of ports" and "a report".

## Decision 3: two outputs, one for each job

The tool writes both Markdown and HTML, and that's intentional, because they
serve different moments.

**Markdown** is what goes into the work. It pastes straight into a GitHub repo,
a pentest note, or a writeup like this one, and it renders as a clean table
anywhere Markdown is supported. It's the format you *use*.

**HTML** is what you *show*. It's a self-contained, dark-themed page with
summary cards and colour-coded severity pills, no external assets, so it opens
anywhere and screenshots well. It's the format for a quick visual read or a
report you hand to someone who isn't going to open a terminal.

![The HTML report](/images/scan2report/report-html.png)
_The HTML output: summary cards, severity-sorted table, and a "where to look first" section per host._

## Decision 4: fail like a real tool

A script that crashes with a Python traceback when you feed it the wrong file is
a script. A tool tells you what went wrong in your language:

```python
except ET.ParseError as e:
    sys.exit(f"[!] Not valid XML (did you use nmap -oX?): {e}")
```

Wrong filename, a text file instead of XML, valid XML that isn't from Nmap: each
gets a clear, actionable message instead of a stack trace. It's a small thing
that costs ten minutes and signals that the tool was built to be *used*, not
just to run once for a demo.

## What I'd add next

The tool is intentionally small, but there are natural next steps: diffing two
scans to highlight what changed between runs (great for monitoring), enriching
the notes with live CVE lookups, and grouping findings across many hosts by
service instead of by host. Each is a feature I'd only add if it earned its
place. A tool that does one thing cleanly beats one that does five things
half-way.

## Takeaway

The code here isn't complicated. It's a few hundred lines of standard-library
Python. What I hope comes through is the **thinking**: choosing the structured
input over the convenient one, making the domain knowledge explicit and
editable, matching each output format to how it'll be used, and failing
gracefully. That's the part of tooling that transfers to any security role,
offensive or defensive.

The full source is in the [tools directory of this
site's repo](https://github.com/WitorSs/witorss.github.io/tree/main/tools/scan2report).
Clone it, edit the priority table to match how you triage, and point it at your
next scan.
