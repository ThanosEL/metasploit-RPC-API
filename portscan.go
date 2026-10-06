package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Tuning constants — chosen to balance speed and reliability.
const (
	workers     = 150                     // parallel probes; a bit gentler on old hosts
	dialTimeout = 1000 * time.Millisecond // per-attempt connect timeout
	retries     = 2                       // extra attempts for a port that looks closed
)

// tryConnect attempts one TCP connect. Returns true if the port is open.
func tryConnect(target string, port int) bool {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, dialTimeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// worker probes each port from the jobs channel. A port that looks closed is
// retried a few times before being given up, which catches transient failures
// (dropped packets, momentary overload) and cuts down false negatives — the
// reason a single-probe scan can miss an open port on a slow/old target.
func worker(target string, jobs <-chan int, results chan<- int, wg *sync.WaitGroup) {
	defer wg.Done()
	for p := range jobs {
		for attempt := 0; attempt <= retries; attempt++ {
			if tryConnect(target, p) {
				results <- p
				break // open — no need to retry
			}
		}
	}
}

func main() {
	// --- Parse arguments ---
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: portscan <target> [start_port] [end_port]")
		os.Exit(1)
	}
	target := os.Args[1]

	start, end := 1, 65535 // defaults
	if len(os.Args) >= 3 {
		start, _ = strconv.Atoi(os.Args[2])
	}
	if len(os.Args) >= 4 {
		end, _ = strconv.Atoi(os.Args[3])
	}
	if start < 1 || end > 65535 || start > end {
		fmt.Fprintln(os.Stderr, "[!] Invalid port range.")
		os.Exit(1)
	}

	// Progress goes to stderr so it doesn't pollute the port list on stdout.
	fmt.Fprintf(os.Stderr, "[*] Scanning %s ports %d-%d ...\n", target, start, end)

	jobs := make(chan int, 1000)
	results := make(chan int)
	var openPorts []int

	// --- Start workers ---
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(target, jobs, results, &wg)
	}

	// --- Feed jobs ---
	go func() {
		for p := start; p <= end; p++ {
			jobs <- p
		}
		close(jobs)
	}()

	// --- Close results once all workers are done ---
	go func() {
		wg.Wait()
		close(results)
	}()

	// --- Collect open ports ---
	for p := range results {
		openPorts = append(openPorts, p)
	}

	sort.Ints(openPorts)

	// --- Output: comma-separated on stdout (the part other tools read) ---
	if len(openPorts) == 0 {
		fmt.Fprintln(os.Stderr, "[!] No open ports found.")
		return
	}

	strs := make([]string, len(openPorts))
	for i, p := range openPorts {
		strs[i] = strconv.Itoa(p)
	}
	fmt.Fprintf(os.Stderr, "[+] Found %d open port(s).\n", len(openPorts))
	fmt.Println(strings.Join(strs, ",")) // stdout: e.g. 22,80,443
}