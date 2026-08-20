// gofuzz is a small, fast web content discovery tool: it takes a target URL and
// a wordlist, and finds paths that exist on the server by making many requests
// concurrently. Think of a stripped-down ffuf or gobuster, built to learn Go's
// concurrency model properly rather than to replace those tools.
//
// The interesting part isn't the HTTP requests, it's the concurrency: a bounded
// pool of workers pulls words off a channel, a rate limiter keeps us from
// hammering the target, and results come back over another channel to a single
// printer. That shape (fan-out workers, fan-in results, no shared mutable state)
// is idiomatic Go and the reason this kind of tool is fast.
//
// Use it ONLY against targets you own or are explicitly allowed to test.
//
// Author: Allan Vitor  ·  https://witorss.github.io
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// result is what a worker reports back for a path that's worth showing.
type result struct {
	path   string
	status int
	length int64
}

// config holds the parsed command-line options.
type config struct {
	baseURL   string
	wordlist  string
	workers   int
	rateLimit int // requests per second across all workers; 0 = unlimited
	timeout   time.Duration
	extensions []string
	hideCodes  map[int]bool
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}

	words, err := loadWordlist(cfg.wordlist)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}

	// Expand words with extensions (e.g. "admin" -> "admin", "admin.php").
	tasks := expandTasks(words, cfg.extensions)

	fmt.Printf("[*] Target:     %s\n", cfg.baseURL)
	fmt.Printf("[*] Wordlist:   %s (%d words, %d requests with extensions)\n",
		cfg.wordlist, len(words), len(tasks))
	fmt.Printf("[*] Workers:    %d\n", cfg.workers)
	if cfg.rateLimit > 0 {
		fmt.Printf("[*] Rate limit: %d req/s\n", cfg.rateLimit)
	}
	fmt.Println(strings.Repeat("-", 50))

	start := time.Now()
	found := run(cfg, tasks)
	elapsed := time.Since(start)

	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("[*] Done: %d paths found in %s (%d requests)\n",
		found, elapsed.Round(time.Millisecond), len(tasks))
}

// run wires up the concurrency: a jobs channel feeds a pool of workers, workers
// send hits to a results channel, and a single goroutine prints them. This is
// the heart of the tool.
func run(cfg config, tasks []string) int {
	jobs := make(chan string, cfg.workers)
	results := make(chan result, cfg.workers)

	// One shared HTTP client. It's safe for concurrent use and pools
	// connections, which matters a lot when you're firing thousands of requests.
	client := &http.Client{
		Timeout: cfg.timeout,
		// Don't follow redirects: a 301/302 is itself a meaningful signal
		// (the path exists and points somewhere), so we want to see it.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Optional rate limiter shared by all workers. A ticker paces the whole
	// pool, so "50 req/s" means 50 total, not 50 per worker.
	var ticker *time.Ticker
	if cfg.rateLimit > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(cfg.rateLimit))
		defer ticker.Stop()
	}

	// Fan-out: start the worker pool.
	var wg sync.WaitGroup
	for i := 0; i < cfg.workers; i++ {
		wg.Add(1)
		go worker(&wg, cfg, client, ticker, jobs, results)
	}

	// Fan-in: one goroutine drains results and prints them, counting hits.
	var found int
	done := make(chan struct{})
	go func() {
		for r := range results {
			printHit(r)
			found++
		}
		close(done)
	}()

	// Feed the jobs, then close so workers know to stop.
	for _, t := range tasks {
		jobs <- t
	}
	close(jobs)

	wg.Wait()      // wait for all workers to finish
	close(results) // now safe to close results: no worker will send again
	<-done         // wait for the printer to drain

	return found
}

// worker pulls paths off the jobs channel, requests each one, and reports any
// that look like they exist. It respects the shared rate limiter if present.
func worker(wg *sync.WaitGroup, cfg config, client *http.Client,
	ticker *time.Ticker, jobs <-chan string, results chan<- result) {
	defer wg.Done()

	for path := range jobs {
		if ticker != nil {
			<-ticker.C // block until the rate limiter allows the next request
		}

		url := cfg.baseURL + "/" + path
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "gofuzz/1.0 (+https://witorss.github.io)")

		resp, err := client.Do(req)
		if err != nil {
			continue // timeout, connection refused, etc: treat as "not found"
		}
		length := resp.ContentLength
		status := resp.StatusCode
		resp.Body.Close()

		// A path is "interesting" if the server didn't say 404 (or whatever the
		// user chose to hide). 200, 301, 403 all tell you something exists.
		if !cfg.hideCodes[status] {
			results <- result{path: path, status: status, length: length}
		}
	}
}

func printHit(r result) {
	// Colour by status class so hits are easy to scan by eye.
	colour := "\033[32m" // green: 2xx
	switch {
	case r.status >= 300 && r.status < 400:
		colour = "\033[36m" // cyan: redirects
	case r.status >= 400:
		colour = "\033[33m" // yellow: 403 and friends
	}
	reset := "\033[0m"
	lenStr := "?"
	if r.length >= 0 {
		lenStr = fmt.Sprintf("%d", r.length)
	}
	fmt.Printf("%s[%d]%s  /%-30s  (len: %s)\n", colour, r.status, reset, r.path, lenStr)
}
