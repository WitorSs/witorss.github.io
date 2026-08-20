package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// parseFlags reads command-line options into a config, validating as it goes.
func parseFlags() (config, error) {
	var (
		url      = flag.String("u", "", "Target base URL, e.g. http://localhost:8080 (required)")
		wordlist = flag.String("w", "", "Path to wordlist file (required)")
		workers  = flag.Int("t", 40, "Number of concurrent workers")
		rate     = flag.Int("r", 0, "Max requests per second (0 = unlimited)")
		timeout  = flag.Int("timeout", 8, "Per-request timeout in seconds")
		exts     = flag.String("x", "", "Comma-separated extensions to try, e.g. php,html,txt")
		hide     = flag.String("hide", "404", "Comma-separated status codes to hide from output")
	)
	flag.Parse()

	if *url == "" || *wordlist == "" {
		flag.Usage()
		return config{}, fmt.Errorf("both -u (target) and -w (wordlist) are required")
	}

	cfg := config{
		baseURL:   strings.TrimRight(*url, "/"),
		wordlist:  *wordlist,
		workers:   *workers,
		rateLimit: *rate,
		timeout:   time.Duration(*timeout) * time.Second,
		hideCodes: map[int]bool{},
	}

	if cfg.workers < 1 {
		return config{}, fmt.Errorf("workers (-t) must be at least 1")
	}

	// extensions: "php,html" -> [".php", ".html"], stored without the dot here
	if *exts != "" {
		for _, e := range strings.Split(*exts, ",") {
			e = strings.TrimSpace(strings.TrimPrefix(e, "."))
			if e != "" {
				cfg.extensions = append(cfg.extensions, e)
			}
		}
	}

	// hide codes: "404,400" -> {404:true, 400:true}
	for _, c := range strings.Split(*hide, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		n, err := strconv.Atoi(c)
		if err != nil {
			return config{}, fmt.Errorf("invalid status code in -hide: %q", c)
		}
		cfg.hideCodes[n] = true
	}

	return cfg, nil
}

// loadWordlist reads a file into a slice of words, skipping blanks and comments.
func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open wordlist: %w", err)
	}
	defer f.Close()

	var words []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// normalise: strip a leading slash so "/admin" and "admin" behave the same
		words = append(words, strings.TrimPrefix(line, "/"))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist: %w", err)
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("wordlist is empty")
	}
	return words, nil
}

// expandTasks turns each word into one or more actual paths to request: the bare
// word, plus one per extension (so "admin" with -x php gives "admin" and
// "admin.php").
func expandTasks(words, extensions []string) []string {
	if len(extensions) == 0 {
		return words
	}
	tasks := make([]string, 0, len(words)*(len(extensions)+1))
	for _, w := range words {
		tasks = append(tasks, w)
		for _, e := range extensions {
			tasks = append(tasks, w+"."+e)
		}
	}
	return tasks
}
