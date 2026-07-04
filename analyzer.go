package main

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

type validationRule struct {
	weight      int
	description string
	validate    func(string) (string, string)
}

var headerRules = map[string]validationRule{
	"Strict-Transport-Security": {
		weight:      20,
		description: "Forces browsers to use HTTPS, preventing protocol-downgrade attacks.",
		validate: func(v string) (string, string) {
			if v == "" {
				return "MISSING", "Add HSTS to enforce HTTPS. Recommended: max-age=31536000; includeSubDomains; preload"
			}
			if strings.Contains(v, "max-age=0") {
				return "WEAK", "HSTS is explicitly disabled (max-age=0). Set a long duration like max-age=31536000."
			}
			return "FOUND", ""
		},
	},
	"Content-Security-Policy": {
		weight:      20,
		description: "Restricts which resources the browser can load, blocking XSS attacks.",
		validate: func(v string) (string, string) {
			if v == "" {
				return "MISSING", "Define a CSP to restrict resource origins and prevent XSS attacks."
			}
			if strings.Contains(v, "unsafe-inline") || strings.Contains(v, "unsafe-eval") {
				return "WEAK", "CSP contains 'unsafe-inline' or 'unsafe-eval', significantly weakening XSS protection."
			}
			return "FOUND", ""
		},
	},
	"X-Frame-Options": {
		weight:      10,
		description: "Prevents the page from being embedded in an iframe, blocking clickjacking.",
		validate: func(v string) (string, string) {
			up := strings.ToUpper(v)
			if up == "DENY" || up == "SAMEORIGIN" {
				return "FOUND", ""
			}
			if v != "" {
				return "WEAK", "Value should be DENY or SAMEORIGIN. Current value is non-standard."
			}
			return "MISSING", "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking."
		},
	},
	"X-Content-Type-Options": {
		weight:      10,
		description: "Stops browsers from guessing the content type, preventing MIME-sniffing attacks.",
		validate: func(v string) (string, string) {
			if strings.EqualFold(v, "nosniff") {
				return "FOUND", ""
			}
			return "MISSING", "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing."
		},
	},
	"Permissions-Policy": {
		weight:      10,
		description: "Controls access to browser features like camera, microphone, and geolocation.",
		validate: func(v string) (string, string) {
			if v != "" {
				return "FOUND", ""
			}
			return "MISSING", "Add a Permissions-Policy to restrict access to sensitive browser APIs."
		},
	},
	"Referrer-Policy": {
		weight:      5,
		description: "Controls how much referrer information is sent with requests.",
		validate: func(v string) (string, string) {
			if v != "" && !strings.EqualFold(v, "unsafe-url") {
				return "FOUND", ""
			}
			return "MISSING", "Set Referrer-Policy to no-referrer or strict-origin-when-cross-origin."
		},
	},
	"Cross-Origin-Opener-Policy": {
		weight:      5,
		description: "Isolates the browsing context, mitigating cross-origin attacks like Spectre.",
		validate: func(v string) (string, string) {
			if strings.EqualFold(v, "same-origin") || strings.EqualFold(v, "same-origin-allow-popups") {
				return "FOUND", ""
			}
			if v != "" {
				return "WEAK", "Consider using same-origin for the strongest isolation."
			}
			return "MISSING", "Add Cross-Origin-Opener-Policy: same-origin to isolate your browsing context."
		},
	},
	"Cross-Origin-Resource-Policy": {
		weight:      5,
		description: "Prevents other origins from loading your resources, blocking cross-origin data leaks.",
		validate: func(v string) (string, string) {
			v = strings.ToLower(v)
			if v == "same-origin" || v == "same-site" || v == "cross-origin" {
				return "FOUND", ""
			}
			if v != "" {
				return "WEAK", "Value should be same-origin, same-site, or cross-origin."
			}
			return "MISSING", "Add Cross-Origin-Resource-Policy to control who can load your resources."
		},
	},
	"X-XSS-Protection": {
		weight:      5,
		description: "Legacy XSS filter for older browsers. Modern sites use CSP instead.",
		validate: func(v string) (string, string) {
			if v == "0" {
				return "FOUND", ""
			}
			if strings.HasPrefix(v, "1") {
				return "FOUND", ""
			}
			return "MISSING", "Set X-XSS-Protection: 0 (if you have CSP) or 1; mode=block for older browsers."
		},
	},
	"Cache-Control": {
		weight:      5,
		description: "Prevents browsers from caching sensitive responses.",
		validate: func(v string) (string, string) {
			v = strings.ToLower(v)
			if strings.Contains(v, "no-store") || strings.Contains(v, "no-cache") {
				return "FOUND", ""
			}
			if v != "" {
				return "WEAK", "For sensitive pages, ensure Cache-Control includes no-store or no-cache."
			}
			return "MISSING", "Add Cache-Control: no-store for pages with sensitive data."
		},
	},
}

var headerOrder = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Permissions-Policy",
	"Referrer-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Resource-Policy",
	"X-XSS-Protection",
	"Cache-Control",
}

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

func analyzePage(rawURL string) ScanResult {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ScanResult{Url: rawURL, Error: "empty target"}
	}

	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Host == "" {
		return ScanResult{Url: rawURL, Error: "invalid URL"}
	}

	req, err := http.NewRequest(http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return ScanResult{Url: parsedURL.String(), Error: err.Error()}
	}
	req.Header.Set("User-Agent", "HeaderScan/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return ScanResult{Url: parsedURL.String(), Error: err.Error()}
	}
	defer resp.Body.Close()

	finalURL := ""
	usesHTTPS := false
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
		usesHTTPS = resp.Request.URL.Scheme == "https"
	}

	var details []HeaderDetail
	earned := 0
	total := 0

	for _, name := range headerOrder {
		rule, exists := headerRules[name]
		if !exists {
			continue
		}
		total += rule.weight
		status, tip := rule.validate(resp.Header.Get(name))
		switch status {
		case "FOUND":
			earned += rule.weight
		case "WEAK":
			earned += rule.weight / 2
		}
		details = append(details, HeaderDetail{
			Name:        name,
			Status:      status,
			Tip:         tip,
			Description: rule.description,
		})
	}

	score := 0.0
	if total > 0 {
		score = (float64(earned) / float64(total)) * 100
	}

	return ScanResult{
		Url:           parsedURL.String(),
		FinalURL:      finalURL,
		StatusCode:    resp.StatusCode,
		UsesHTTPS:     usesHTTPS,
		Score:         score,
		IsSecure:      score >= 75,
		HeaderDetails: details,
	}
}