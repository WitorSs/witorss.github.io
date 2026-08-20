# logsentry

Find the attacks hiding in your SSH auth logs, in Markdown and HTML.

A Linux auth log is thousands of lines where a handful matter. `logsentry`
reads an SSH auth log, groups events by source IP, and surfaces what a defender
actually cares about: brute-force sources, and (most important) any brute force
that ended in a **successful login**, the sign of a likely compromise.

It writes the same clean report format as its sibling tool
[scan2report](https://witorss.github.io/posts/scan2report/), so findings are
ready to drop into a ticket or a writeup.

## Why

Reading auth logs by hand doesn't scale. A single exposed host can rack up
thousands of failed SSH attempts in a night, and the one line that matters, a
successful login *after* those failures, is buried in the noise. `logsentry`
does the triage a SOC analyst would do: aggregate by IP, flag the brute-force
sources, and raise a critical alert when a brute force appears to have worked.

## Install

No dependencies beyond the Python standard library. Requires Python 3.8+.

```bash
git clone https://github.com/WitorSs/witorss.github.io.git
cd witorss.github.io/tools/logsentry
```

## Usage

```bash
python3 logsentry.py /var/log/auth.log

# custom brute-force threshold and output name
python3 logsentry.py auth.log -o incident -t 15 -f both
```

| Flag | Meaning | Default |
|------|---------|---------|
| `-o, --output` | Output basename (no extension) | `report` |
| `-f, --format` | `md`, `html`, or `both` | `both` |
| `-t, --threshold` | Failed attempts before an IP is flagged | `10` |

A sample log (`sample_auth.log`) is included so you can try it immediately:

```bash
python3 logsentry.py sample_auth.log
```

## How it decides what matters

Three levels of finding, in priority order:

- **Critical**: many failures *then* a success from the same IP. A brute force
  that likely worked; the host should be treated as potentially compromised.
- **Brute force**: failures above the threshold with no recorded success.
  A source worth blocking.
- **Suspicious**: below the threshold, but spread across several usernames,
  which looks like user enumeration.

The thresholds are deliberately simple and tunable with `-t`. The goal isn't to
replace a SIEM, it's to turn a raw log into a short list a human can act on.

## Extensible by design

The log patterns live in one place (`SSH_PATTERNS`). Adding support for another
log type later (web access logs, for example) means adding another analyzer,
not rewriting the tool. The report layer doesn't care where the events came
from.

---
Author: **Allan Vitor** · [witorss.github.io](https://witorss.github.io)
