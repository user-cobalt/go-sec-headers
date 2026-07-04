package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"flag"
	"golang.org/x/time/rate"
)

// --- Models ---

type HeaderDetail struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Tip         string `json:"tip,omitempty"`
	Description string `json:"description"`
}

type ScanResult struct {
	Url           string         `json:"url"`
	FinalURL      string         `json:"finalUrl,omitempty"`
	StatusCode    int            `json:"statusCode,omitempty"`
	UsesHTTPS     bool           `json:"usesHttps"`
	Score         float64        `json:"score"`
	IsSecure      bool           `json:"isSecure"`
	Error         string         `json:"error,omitempty"`
	HeaderDetails []HeaderDetail `json:"headerDetails"`
	ScannedAt     time.Time      `json:"scannedAt"`
}

// --- Global Flags ---

var allowLocalTargets bool
var requireAPIKey bool

// --- CLI Helpers ---

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if text := strings.TrimSpace(scanner.Text()); text != "" {
			lines = append(lines, text)
		}
	}
	return lines, scanner.Err()
}

func deduplicate(urls []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

func printCLIResult(res ScanResult) {
	grade := getLetterGrade(res.Score)
	secure := "✗ Action Required"
	if res.IsSecure {
		secure = "✓ Secure"
	}

	fmt.Printf("\n┌─ %s\n", res.Url)
	fmt.Printf("│  Grade: %-4s  Score: %5.1f%%  Status: %s\n", grade, res.Score, secure)
	fmt.Println("│")

	for _, h := range res.HeaderDetails {
		icon := "✓"
		switch h.Status {
		case "MISSING":
			icon = "✗"
		case "WEAK":
			icon = "⚠"
		}
		fmt.Printf("│  %s %-35s [%s]\n", icon, h.Name, h.Status)
		if h.Tip != "" {
			fmt.Printf("│      → %s\n", h.Tip)
		}
	}
	fmt.Println("└────────────────────────────────────────────────────────────")
}

func getLetterGrade(score float64) string {
	switch {
	case score >= 90:
		return "A+"
	case score >= 80:
		return "A"
	case score >= 70:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

// --- Entry Point ---

func main() {
	urlPtr        := flag.String("url", "", "Scan a single URL")
	filePtr       := flag.String("file", "", "Scan a file of URLs (one per line)")
	serverPtr     := flag.Bool("server", false, "Start the API server")
	workersPtr    := flag.Int("workers", 5, "Number of concurrent scans (CLI mode)")
	historyPtr    := flag.String("history-file", "scan_history.json", "Path to history JSON file")
	flag.Parse()

	// ── SERVER MODE ──────────────────────────────────────────────────────────
	if *serverPtr {
		requireAPIKey = os.Getenv("REQUIRE_API_KEY") != "false"
		scannerKey   := os.Getenv("SCANNER_API_KEY")
		allowLocalTargets = os.Getenv("ALLOW_LOCAL_TARGETS") == "true"

		if requireAPIKey && scannerKey == "" {
			log.Fatal("SCANNER_API_KEY is required but not set")
		}

		store   := NewHistoryStore(*historyPtr)
		limiter := NewIPRateLimiter(rate.Every(time.Second), 10)

		protected := func(h http.HandlerFunc) http.HandlerFunc {
			return chain(h,
				jsonMiddleware,
				func(next http.HandlerFunc) http.HandlerFunc { return rateLimitMiddleware(limiter, next) },
				func(next http.HandlerFunc) http.HandlerFunc { return authMiddleware(scannerKey, next) },
			)
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/scan",          protected(scanHandler(store)))
		mux.HandleFunc("/history",       protected(historyGetHandler(store)))
		mux.HandleFunc("/history/clear", protected(historyDeleteHandler(store)))
		mux.HandleFunc("/_health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ok")
		})

		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}

		server := &http.Server{
			Addr:         ":" + port,
			Handler:      corsMiddleware(mux),
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}

		done := make(chan os.Signal, 1)
		signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			fmt.Printf("Server starting on port %s\n", port)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("server error: %s\n", err)
			}
		}()

		<-done
		log.Printf("Server stopping...")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Fatalf("Server shutdown failed: %+v", err)
		}
		log.Print("Server exited properly.")
		return
	}

	// ── CLI MODE ─────────────────────────────────────────────────────────────
	var rawTargets []string
	if *urlPtr != "" {
		rawTargets = append(rawTargets, *urlPtr)
	}
	if *filePtr != "" {
		lines, err := readLines(*filePtr)
		if err != nil {
			log.Fatalf("Error reading file: %v", err)
		}
		rawTargets = append(rawTargets, lines...)
	}

	targets := deduplicate(rawTargets)
	if len(targets) == 0 {
		fmt.Println("HeaderScan — HTTP Security Header Analyzer")
		fmt.Println("")
		fmt.Println("Usage:")
		fmt.Println("  --server                  Start the API server")
		fmt.Println("  --url <url>               Scan a single site")
		fmt.Println("  --file <path>             Scan a list of sites (one per line)")
		fmt.Println("  --workers <n>             Concurrent workers (default: 5)")
		fmt.Println("  --history-file <path>     History file path (default: scan_history.json)")
		return
	}

	fmt.Printf("🔎 Scanning %d target(s) with %d workers...\n", len(targets), *workersPtr)

	var wg sync.WaitGroup
	sem := make(chan struct{}, *workersPtr)
	var mu sync.Mutex

	for _, t := range targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			sem <- struct{}{}
			res := analyzePage(target)
			<-sem
			mu.Lock()
			printCLIResult(res)
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	fmt.Println("\n🏁 All scans complete.")
}




// package main

// import (
// 	"slices"
// 	"bufio"
// 	"context"
// 	"encoding/json"
// 	"flag"
// 	"fmt"
// 	"log"
// 	"net"
// 	"net/http"
// 	"net/url"
// 	"os"
// 	"os/signal"
// 	"strings"
// 	"sync"
// 	"syscall"
// 	"time"
// )

// // --- Models ---

// type HeaderDetail struct {
// 	Name   string `json:"name"`
// 	Status string `json:"status"` // "FOUND", "WEAK", or "MISSING"
// 	Tip    string `json:"tip"`
// }

// type ScanResult struct {
// 	Url           string         `json:"url"`
// 	FinalURL      string         `json:"finalUrl,omitempty"`
// 	StatusCode    int            `json:"statusCode,omitempty"`
// 	UsesHTTPS     bool           `json:"usesHttps"`
// 	Score         float64        `json:"score"`
// 	IsSecure      bool           `json:"isSecure"`
// 	Error         string         `json:"error,omitempty"`
// 	HeaderDetails []HeaderDetail `json:"headerDetails"`
// }

// // --- Validation Engine ---

// type validationRule struct {
// 	weight   int
// 	validate func(string) (string, string)
// }

// var scannerKey string
// var allowLocalTargets bool
// var requireAPIKey bool

// var httpClient = &http.Client{
// 	Timeout: 10 * time.Second,
// }

// var headerRules = map[string]validationRule{
// 	"Strict-Transport-Security": {25, func(v string) (string, string) {
// 		if v == "" {
// 			return "MISSING", "Enforce HTTPS to prevent Man-in-the-Middle attacks."
// 		}
// 		if strings.Contains(v, "max-age=0") {
// 			return "WEAK", "HSTS is disabled (max-age=0). Use a long duration."
// 		}
// 		return "FOUND", ""
// 	}},
// 	"Content-Security-Policy": {25, func(v string) (string, string) {
// 		if v == "" {
// 			return "MISSING", "Define trusted sources to prevent XSS."
// 		}
// 		if strings.Contains(v, "unsafe-inline") || strings.Contains(v, "unsafe-eval") {
// 			return "WEAK", "CSP allows 'unsafe' scripts, weakening protection."
// 		}
// 		return "FOUND", ""
// 	}},
// 	"X-Frame-Options": {15, func(v string) (string, string) {
// 		v = strings.ToUpper(v)
// 		if v == "DENY" || v == "SAMEORIGIN" {
// 			return "FOUND", ""
// 		}
// 		if v != "" {
// 			return "WEAK", "Value should be DENY or SAMEORIGIN."
// 		}
// 		return "MISSING", "Prevent Clickjacking by restricting framing."
// 	}},
// 	"X-Content-Type-Options": {10, func(v string) (string, string) {
// 		if strings.EqualFold(v, "nosniff") {
// 			return "FOUND", ""
// 		}
// 		return "MISSING", "Prevent the browser from sniffing MIME types."
// 	}},
// 	"Permissions-Policy": {15, func(v string) (string, string) {
// 		if v != "" {
// 			return "FOUND", ""
// 		}
// 		return "MISSING", "Consider restricting camera, mic, or geolocation."
// 	}},
// 	"Referrer-Policy": {10, func(v string) (string, string) {
// 		if v != "" && v != "unsafe-url" {
// 			return "FOUND", ""
// 		}
// 		return "MISSING", "Protect user privacy during navigation."
// 	}},
// }

// var headerOrder = []string{
// 	"Strict-Transport-Security",
// 	"Content-Security-Policy",
// 	"X-Frame-Options",
// 	"X-Content-Type-Options",
// 	"Permissions-Policy",
// 	"Referrer-Policy",
// }

// // --- Core Logic ---
// // TODO: This analyzes headers only, fix this name to say what it does
// func analyzePage(rawURL string) ScanResult {
// 	rawURL = strings.TrimSpace(rawURL)
// 	if rawURL == "" {
// 		return ScanResult{
// 			Url:       rawURL,
// 			UsesHTTPS: false,
// 			Score:     0,
// 			IsSecure:  false,
// 			Error:     "empty target",
// 		}
// 	}

// 	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
// 		rawURL = "https://" + rawURL
// 	}

// 	parsedURL, err := url.Parse(rawURL)
// 	if err != nil || parsedURL.Host == "" {
// 		return ScanResult{
// 			Url:       rawURL,
// 			UsesHTTPS: false,
// 			Score:     0,
// 			IsSecure:  false,
// 			Error:     "invalid URL",
// 		}
// 	}

// 	req, err := http.NewRequest(http.MethodGet, parsedURL.String(), nil)
// 	if err != nil {
// 		return ScanResult{
// 			Url:       parsedURL.String(),
// 			UsesHTTPS: parsedURL.Scheme == "https",
// 			Score:     0,
// 			IsSecure:  false,
// 			Error:     err.Error(),
// 		}
// 	}

// 	req.Header.Set("User-Agent", "HTTP-Security-Scanner/1.0")

// 	resp, err := httpClient.Do(req)
// 	if err != nil {
// 		return ScanResult{
// 			Url:       parsedURL.String(),
// 			UsesHTTPS: parsedURL.Scheme == "https",
// 			Score:     0,
// 			IsSecure:  false,
// 			Error:     err.Error(),
// 		}
// 	}
// 	defer resp.Body.Close()

// 	finalURL := ""
// 	usesHTTPS := false
// 	statusCode := 0

// 	if resp.Request != nil && resp.Request.URL != nil {
// 		finalURL = resp.Request.URL.String()
// 		usesHTTPS = resp.Request.URL.Scheme == "https"
// 	}

// 	statusCode = resp.StatusCode

// 	var details []HeaderDetail
// 	earned := 0
// 	total := 0

// 	for _, name := range headerOrder {
// 		rule, exists := headerRules[name]
// 		if !exists {
// 			continue
// 		}

// 		total += rule.weight

// 		status, tip := rule.validate(resp.Header.Get(name))
// 		switch status {
// 		case "FOUND":
// 			earned += rule.weight
// 		case "WEAK":
// 			earned += rule.weight / 2
// 		}

// 		details = append(details, HeaderDetail{
// 			Name:   name,
// 			Status: status,
// 			Tip:    tip,
// 		})
// 	}

// 	score := 0.0
// 	if total > 0 {
// 		score = (float64(earned) / float64(total)) * 100
// 	}

// 	return ScanResult{
// 		Url:           parsedURL.String(),
// 		FinalURL:      finalURL,
// 		StatusCode:    statusCode,
// 		UsesHTTPS:     usesHTTPS,
// 		Score:         score,
// 		IsSecure:      score >= 75,
// 		HeaderDetails: details,
// 	}
// }


// // --- CLI Helpers ---

// func readLines(path string) ([]string, error) {
// 	file, err := os.Open(path)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer file.Close()

// 	var lines []string
// 	scanner := bufio.NewScanner(file)
// 	for scanner.Scan() {
// 		if text := strings.TrimSpace(scanner.Text()); text != "" {
// 			lines = append(lines, text)
// 		}
// 	}
// 	return lines, scanner.Err()
// }

// func deduplicate(urls []string) []string {
// 	uniqueMap := make(map[string]bool)
// 	var cleanList []string
// 	for _, u := range urls {
// 		if !uniqueMap[u] {
// 			uniqueMap[u] = true
// 			cleanList = append(cleanList, u)
// 		}
// 	}
// 	return cleanList
// }

// func isPrivateIP(ip net.IP) bool {
// 	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
// 		return true
// 	}

// 	privateCIDRs := []string{
// 		"10.0.0.0/8",
// 		"172.16.0.0/12",
// 		"192.168.0.0/16",
// 		"127.0.0.0/8",
// 		"169.254.0.0/16",
// 		"::1/128",
// 		"fc00::/7",
// 		"fe80::/10",
// 	}

// 	for _, cidr := range privateCIDRs {
// 		_, block, err := net.ParseCIDR(cidr)
// 		if err != nil {
// 			continue
// 		}
// 		if block.Contains(ip) {
// 			return true
// 		}
// 	}

// 	return false
// }


// //TODO: Strengthen SSRF Protection with DNS Resolution
// func validateScanTarget(rawTarget string) error {
// 	rawTarget = strings.TrimSpace(rawTarget)
// 	if rawTarget == "" {
// 		return fmt.Errorf("target is required")
// 	}

// 	if !strings.HasPrefix(rawTarget, "http://") && !strings.HasPrefix(rawTarget, "https://") {
// 		rawTarget = "https://" + rawTarget
// 	}

// 	parsed, err := url.Parse(rawTarget)
// 	if err != nil {
// 		return fmt.Errorf("invalid target")
// 	}

// 	if parsed.Scheme != "http" && parsed.Scheme != "https" {
// 		return fmt.Errorf("unsupported scheme")
// 	}

// 	host := parsed.Hostname()
// 	if host == "" {
// 		return fmt.Errorf("invalid target host")
// 	}

// 	if allowLocalTargets {
// 		return nil
// 	}

// 	lowerHost := strings.ToLower(host)
// 	if lowerHost == "localhost" {
// 		return fmt.Errorf("target not allowed")
// 	}

// 	// If host is already a literal IP, check directly.
// 	if ip := net.ParseIP(host); ip != nil {
// 		if isPrivateIP(ip) {
// 			return fmt.Errorf("target not allowed")
// 		}
// 		return nil
// 	}

// 	// Resolve hostname and block if any resolved IP is private/internal.
// 	ips, err := net.LookupIP(host)
// 	if err != nil {
// 		return fmt.Errorf("target resolution failed")
// 	}

// 	if len(ips) == 0 {
// 		return fmt.Errorf("target resolution failed")
// 	}

// 	if slices.ContainsFunc(ips, isPrivateIP) {
// 			return fmt.Errorf("target not allowed")
// 		}

// 	return nil
// }

// func sanitizeScanError(errMsg string) string {
// 	if errMsg == "" {
// 		return ""
// 	}

// 	lower := strings.ToLower(errMsg)

// 	switch {
// 	case strings.Contains(lower, "timeout"),
// 		strings.Contains(lower, "deadline exceeded"):
// 		return "request timed out"

// 	case strings.Contains(lower, "no such host"),
// 		strings.Contains(lower, "server misbehaving"):
// 		return "host could not be resolved"

// 	case strings.Contains(lower, "connection refused"):
// 		return "connection failed"

// 	case strings.Contains(lower, "tls"),
// 		strings.Contains(lower, "certificate"):
// 		return "tls/ssl connection failed"

// 	default:
// 		return "request failed"
// 	}
// }

// // --- History Store ---

// type HistoryStore struct {
// 	mu   sync.RWMutex
// 	path string
// }

// func NewHistoryStore(path string) *HistoryStore {
// 	return &HistoryStore{path: path}
// }

// func (s *HistoryStore) Load() ([]ScanResult, error) {
// 	s.mu.RLock()
// 	defer s.mu.RUnlock()

// 	data, err := os.ReadFile(s.path)
// 	if os.IsNotExist(err) {
// 		return []ScanResult{}, nil
// 	}
// 	if err != nil {
// 		return nil, err
// 	}

// 	var results []ScanResult
// 	if err := json.Unmarshal(data, &results); err != nil {
// 		return nil, err
// 	}
// 	return results, nil
// }

// func (s *HistoryStore) Append(result ScanResult) error {
// 	s.mu.Lock()
// 	defer s.mu.Unlock()

// 	var results []ScanResult
// 	data, err := os.ReadFile(s.path)
// 	if err == nil {
// 		_ = json.Unmarshal(data, &results)
// 	}

// 	filtered := make([]ScanResult, 0, len(results))
// 	for _, r := range results {
// 		if r.Url != result.Url {
// 			filtered = append(filtered, r)
// 		}
// 	}

// 	filtered = append([]ScanResult{result}, filtered...)
// 	if len(filtered) > 100 {
// 		filtered = filtered[:100]
// 	}

// 	out, err := json.MarshalIndent(filtered, "", "  ")
// 	if err != nil {
// 		return err
// 	}
// 	return os.WriteFile(s.path, out, 0644)
// }

// // --- History Handlers ---

// func historyGetHandler(store *HistoryStore) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		results, err := store.Load()
// 		if err != nil {
// 			http.Error(w, `{"error":"failed to load history"}`, http.StatusInternalServerError)
// 			return
// 		}
// 		json.NewEncoder(w).Encode(results)
// 	}
// }

// func historyDeleteHandler(store *HistoryStore) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		if err := os.WriteFile(store.path, []byte("[]"), 0644); err != nil {
// 			http.Error(w, `{"error":"failed to clear history"}`, http.StatusInternalServerError)
// 			return
// 		}
// 		w.Write([]byte(`{"ok":true}`))
// 	}
// }



// // --- Web Handlers ---

// func scanHandler(store *HistoryStore) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		target := r.URL.Query().Get("target")
// 		if target == "" {
// 			http.Error(w, `{"error":"target is required"}`, http.StatusBadRequest)
// 			return
// 		}

// 		if err := validateScanTarget(target); err != nil {
// 			http.Error(w, `{"error":"invalid target"}`, http.StatusBadRequest)
// 			return
// 		}

// 		result := analyzePage(target)
// 		if result.Error != "" {
// 			result.Error = sanitizeScanError(result.Error)
// 		}

// 		if err := store.Append(result); err != nil {
// 			log.Printf("failed to save history: %v", err)
// 		}

// 		json.NewEncoder(w).Encode(result)
// 	}
// }





// // func scanHandler(w http.ResponseWriter, r *http.Request) {
// // 	w.Header().Set("Access-Control-Allow-Origin", "*")
// // 	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
// // 	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
// // 	w.Header().Set("Content-Type", "application/json")

// // 	if r.Method == "OPTIONS" {
// // 		w.WriteHeader(http.StatusNoContent)
// // 		return
// // 	}

// // 	if requireAPIKey && r.Header.Get("X-API-Key") != scannerKey {
// // 		http.Error(w, "Unauthorized", http.StatusUnauthorized)
// // 		return
// // 	}

// // 	target := r.URL.Query().Get("target")
// // 	if target == "" {
// // 		http.Error(w, "Target is required", http.StatusBadRequest)
// // 		return
// // 	}

// // 	if err := validateScanTarget(target); err != nil {
// // 		http.Error(w, "invalid target", http.StatusBadRequest)
// // 		return
// // 	}

// // 	result := analyzePage(target)
// // 	if result.Error != "" {
// // 		result.Error = sanitizeScanError(result.Error)
// // }
// // json.NewEncoder(w).Encode(result)
// // }

// // --- Main Entry Point ---


// //TODO: Check redirect/HTTPS Behavior
// func main() {
// 	urlPtr := flag.String("url", "", "CLI: Scan a single URL")
// 	filePtr := flag.String("file", "", "CLI: Scan a file of URLs")
// 	serverPtr := flag.Bool("server", false, "Web: Start API server")
// 	workersPtr := flag.Int("workers", 5, "CLI: Number of concurrent scans")
// 	flag.Parse()

// 	// 1. WEB SERVER MODE
// 	if *serverPtr {
// 		requireAPIKey = os.Getenv("REQUIRE_API_KEY") != "false"
// 		scannerKey = os.Getenv("SCANNER_API_KEY")

// 		if requireAPIKey && scannerKey == "" {
// 			log.Fatal("missing required server configuration")
// 		}

// 		allowLocalTargets = os.Getenv("ALLOW_LOCAL_TARGETS") == "true"

// 		mux := http.NewServeMux()
// 		mux.HandleFunc("/scan", scanHandler)

// 		mux.HandleFunc("/_health", func(w http.ResponseWriter, r *http.Request) {
// 			w.WriteHeader(http.StatusOK)
// 			fmt.Fprint(w, "ok")
// 		})

// 		port := os.Getenv("PORT")
// 		if port == "" {
// 			port = "8080"
// 		}

// 		server := &http.Server{
// 			Addr:    ":" + port,
// 			Handler: mux,
// 		}

// 		done := make(chan os.Signal, 1)
// 		signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

// 		go func() {
// 			fmt.Printf("Server starting on port %s\n", port)
// 			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
// 				log.Fatalf("listen: %s\n", err)
// 			}
// 		}()

// 		<-done
// 		log.Printf("Server stopping...")

// 		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 		defer cancel()

// 		if err := server.Shutdown(ctx); err != nil {
// 			log.Fatalf("Server shutdown failed: %+v", err)
// 		}
// 		log.Print("Server exited properly.")
// 		return
// 	}

// 	// 2. CLI MODE
// 	var rawTargets []string
// 	if *urlPtr != "" {
// 		rawTargets = append(rawTargets, *urlPtr)
// 	}
// 	if *filePtr != "" {
// 		lines, err := readLines(*filePtr)
// 		if err != nil {
// 			log.Fatalf("Error reading file: %v", err)
// 		}
// 		rawTargets = append(rawTargets, lines...)
// 	}

// 	finalTargets := deduplicate(rawTargets)

// 	if len(finalTargets) > 0 {
// 		fmt.Printf("🔎 Scanning %d unique targets with %d workers...\n", len(finalTargets), *workersPtr)

// 		var wg sync.WaitGroup
// 		semaphore := make(chan struct{}, *workersPtr)

// 		for _, target := range finalTargets {
// 			wg.Add(1)
// 			go func(t string) {
// 				defer wg.Done()
// 				semaphore <- struct{}{}
// 				res := analyzePage(t)
// 				<-semaphore

// 				if res.Error != "" {
// 					fmt.Printf("[%s] ERROR: %s\n", res.Url, res.Error)
// 					return
// 				}

// 				fmt.Printf("[%s] Score: %.0f%% | Secure: %v\n", res.Url, res.Score, res.IsSecure)
// 			}(target)
// 		}

// 		wg.Wait()
// 		fmt.Println("🏁 All scans complete.")
// 		return
// 	}

// 	// 3. NO FLAGS PROVIDED
// 	fmt.Println("Please provide a flag:")
// 	fmt.Println("  --server          to start the web backend")
// 	fmt.Println("  --url <link>      to scan one site in terminal")
// 	fmt.Println("  --file <path>     to scan a list in terminal")
// }