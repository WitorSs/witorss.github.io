# gofuzz

A small, fast web content discovery tool written in Go. Point it at a URL and a
wordlist, and it finds paths that exist on the server by making many requests
concurrently. Think of a stripped-down `ffuf` or `gobuster`, built to learn Go's
concurrency model properly.

```
$ ./gofuzz -u http://target.local -w wordlist.txt -x php -t 30

[200]  /admin                           (len: 42)
[200]  /robots.txt                      (len: 42)
[403]  /private                         (len: 42)
[301]  /uploads                         (len: ?)
[200]  /.git/config                     (len: 42)
[*] Done: 8 paths found in 1.443s (20 requests)
```

## Why this exists

Directory discovery is the first step of almost every web assessment, and the
tools that do it (ffuf, gobuster) are fast because of one thing: concurrency. I
built gofuzz to understand that properly, by implementing the pattern myself
rather than reading about it. It's a real tool I use in my own labs, and the
concurrency underneath is the point.

## Why Go

This is the kind of tool Go was made for. A single `go build` produces a
dependency-free static binary, and it cross-compiles to any platform from one
machine:

```bash
GOOS=linux   GOARCH=amd64 go build -o gofuzz .
GOOS=windows GOARCH=amd64 go build -o gofuzz.exe .
GOOS=darwin  GOARCH=arm64 go build -o gofuzz .   # Apple Silicon
```

No interpreter, no dependencies to ship. And goroutines make firing hundreds of
concurrent requests natural instead of painful.

## Build

Requires Go 1.20+.

```bash
git clone https://github.com/WitorSs/witorss.github.io.git
cd witorss.github.io/tools/gofuzz
go build -o gofuzz .
```

## Usage

```bash
./gofuzz -u http://localhost:8080 -w common.txt
```

| Flag | Meaning | Default |
|------|---------|---------|
| `-u` | Target base URL (required) | |
| `-w` | Wordlist file (required) | |
| `-t` | Concurrent workers | 40 |
| `-r` | Max requests per second (0 = unlimited) | 0 |
| `-x` | Extensions to try, e.g. `php,html,txt` | |
| `-hide` | Status codes to hide from output | 404 |
| `-timeout` | Per-request timeout (seconds) | 8 |

A small `common.txt` wordlist is included to get started.

## How the concurrency works

The design is a classic Go pipeline:

- A **jobs channel** feeds paths to a pool of **worker goroutines** (fan-out).
- Workers send hits to a **results channel**, drained by a single printer
  goroutine (fan-in), so there's no shared mutable state and no locks.
- An optional **rate limiter** (a shared `time.Ticker`) paces the whole pool, so
  `-r 50` means 50 requests/second total, not 50 per worker.

A `sync.WaitGroup` tracks the workers so the program knows when every job is
done and it's safe to close the results channel. This is idiomatic Go, and it's
the reason the tool stays fast without hammering the target uncontrollably.

## Responsible use

Only run this against targets you own or are explicitly authorised to test
(your own labs, deliberately vulnerable apps like DVWA, or systems you have
written permission for). Unauthorised scanning is illegal. It was built and
tested entirely against local targets.

---
Author: **Allan Vitor** · [witorss.github.io](https://witorss.github.io)
