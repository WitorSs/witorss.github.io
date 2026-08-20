---
title: "Building logsentry: finding the compromise hiding in an auth log"
author: allanvitor
categories: [Personal Projects]
tags: [Python, Blue Team, Log Analysis, Detection, SSH, Brute Force, Tooling]
render_with_liquid: false
permalink: /posts/logsentry/
img_path: /images/logsentry/
image:
  path: /images/logsentry/report-html.png
---

My first tool, [scan2report](/posts/scan2report/), was offensive: it takes the
output of a recon scan and makes it useful. This one looks at the same problem
from the other side of the fence. `logsentry` reads an SSH auth log and finds
the attacks buried in it, the way a SOC analyst would.

I built it for a simple reason: defenders drown in logs. A single internet-facing
host can log thousands of failed SSH attempts overnight. Somewhere in that flood
might be the one line that actually matters, a *successful* login right after a
burst of failures. That's not noise. That's a break-in. The whole point of the
tool is to pull that line out of the pile.

As before, this post is about the decisions, not the syntax.

## Decision 1: aggregate by IP, because that's how attacks cluster

A raw auth log is ordered by time, one line per event. But an attack isn't a
line, it's a *pattern*: the same source hammering the same host. So the first
thing the tool does is throw away the line-by-line view and rebuild the data
grouped by source IP:

```python
act = activity.setdefault(ip, IPActivity(ip=ip))
if kind == "failed":
    act.failed += 1
    act.users_failed.add(user)
else:
    act.accepted += 1
    act.users_accepted.add(user)
```

Once the data is shaped per IP, the questions a defender asks become trivial to
answer: how many times did this source fail? Did it ever succeed? How many
different usernames did it try? The raw log can't answer those; the aggregated
view answers all three at a glance.

## Decision 2: the finding that matters is "failure then success"

Anyone can count failed logins. The insight, the thing that turns a counter into
a detector, is recognising that **a lot of failures followed by a success from
the same IP is a brute force that probably worked**:

```python
if act.failed >= threshold and act.accepted > 0:
    # brute force that likely succeeded: treat as compromise
```

That single condition is the heart of the tool. A hundred failed logins with no
success is an attacker who *didn't* get in, annoying but not urgent. Eighteen
failures followed by one `Accepted password` is an attacker who very possibly
*did*, and that host needs eyes on it now. The tool escalates the second case to
**Critical** and spells out the response: review the session, rotate the
account's credentials, check for persistence. That's the difference between
reporting data and reporting a finding.

![The HTML report](/images/logsentry/report-html.png)
_The critical finding sits at the top, with the raw per-IP table underneath for context._

## Decision 3: earn the alert, avoid the false positive

A detector that cries wolf gets ignored, so the tool is deliberately careful
about what it flags. There are three tiers, and the boundaries matter:

- **Critical**: failures above the threshold *and* a success. Likely compromise.
- **Brute force**: failures above the threshold, no success. Worth blocking.
- **Suspicious**: below the threshold, but spread across several usernames,
  which reads like user enumeration rather than a typo.

Three failed logins from one IP for one user? That's someone fat-fingering their
password, and the tool stays quiet about it, on purpose. I tested this against a
log that deliberately mixed real attacks with that kind of benign noise, and
confirmed the benign IP produced no finding. A tool that flags everything is as
useless as one that flags nothing.

## Decision 4: build it to grow

The log-line patterns live in one dictionary at the top of the file:

```python
SSH_PATTERNS = {
    "failed":   re.compile(r"... Failed password for ..."),
    "accepted": re.compile(r"... Accepted (?:password|publickey) for ..."),
}
```

That's intentional. Right now the tool understands SSH auth logs. When I add web
access logs (spotting scanners, path-traversal probes, and the like), that's a
*new analyzer* plugged into the same reporting pipeline, not a rewrite. The part
that turns events into a report doesn't care whether the events came from sshd
or nginx. Designing that seam now is cheaper than retrofitting it later, and it's
the kind of structural decision that separates a throwaway script from something
you can actually extend.

## Takeaway

`logsentry` is the defensive half of a pair. Where `scan2report` helps you
*attack* efficiently, this helps you *notice* when you're being attacked. Both
share the same philosophy: take a raw, noisy source, apply a bit of real domain
knowledge, and produce something a human can act on in seconds. That skill,
turning data into decisions, is what security work is actually made of, on
either side of the line.

Source is in the
[tools directory](https://github.com/WitorSs/witorss.github.io/tree/main/tools/logsentry)
of this site's repo, with a sample log so you can run it in ten seconds.
