package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

func scanHandler(store *HistoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, `{"error":"target is required"}`, http.StatusBadRequest)
			return
		}

		if err := validateScanTarget(target); err != nil {
			http.Error(w, `{"error":"invalid target"}`, http.StatusBadRequest)
			return
		}

		result := analyzePage(target)
		if result.Error != "" {
			result.Error = sanitizeScanError(result.Error)
		}

		if err := store.Append(result); err != nil {
			log.Printf("failed to save history: %v", err)
		}

		json.NewEncoder(w).Encode(result)
	}
}

func validateScanTarget(rawTarget string) error {
	rawTarget = strings.TrimSpace(rawTarget)
	if rawTarget == "" {
		return fmt.Errorf("target is required")
	}

	if !strings.HasPrefix(rawTarget, "http://") && !strings.HasPrefix(rawTarget, "https://") {
		rawTarget = "https://" + rawTarget
	}

	parsed, err := url.Parse(rawTarget)
	if err != nil {
		return fmt.Errorf("invalid target")
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported scheme")
	}

	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("invalid target host")
	}

	if allowLocalTargets {
		return nil
	}

	if strings.ToLower(host) == "localhost" {
		return fmt.Errorf("target not allowed")
	}

	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("target not allowed")
		}
		return nil
	}

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("target resolution failed")
	}

	if slices.ContainsFunc(ips, isPrivateIP) {
		return fmt.Errorf("target not allowed")
	}

	return nil
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	privateCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range privateCIDRs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if block.Contains(ip) {
			return true
		}
	}

	return false
}

func sanitizeScanError(errMsg string) string {
	if errMsg == "" {
		return ""
	}

	lower := strings.ToLower(errMsg)

	switch {
	case strings.Contains(lower, "timeout"),
		strings.Contains(lower, "deadline exceeded"):
		return "request timed out"

	case strings.Contains(lower, "no such host"),
		strings.Contains(lower, "server misbehaving"):
		return "host could not be resolved"

	case strings.Contains(lower, "connection refused"):
		return "connection failed"

	case strings.Contains(lower, "tls"),
		strings.Contains(lower, "certificate"):
		return "tls/ssl connection failed"

	default:
		return "request failed"
	}
}