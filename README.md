<<<<<<< HEAD
# go-sec-headers
=======
# go-sec-headers





# HeaderScan Backend — Changes from Original v1
==========================================

MODELS
------
- HeaderDetail: added Description string field
- ScanResult: renamed Url -> URL, added ScannedAt time.Time

HEADER RULES
------------
- Added 4 new headers:
    - Cross-Origin-Opener-Policy    (weight 5)
    - Cross-Origin-Resource-Policy  (weight 5)
    - X-XSS-Protection              (weight 5)
    - Cache-Control                 (weight 5)
- All rules now include a description field
- Scoring changed to dynamic percentage of total weight (was hardcoded to 100)

analyzePage()
-------------
- Added 10s timeout via context.WithTimeout
- Replaced http.Get with http.NewRequestWithContext
- Added custom http.Client with 5-redirect limit
- Replaced fmt.Printf / log.Fatal with slog

HISTORY (new)
-------------
- HistoryStore: thread-safe JSON file store (sync.RWMutex)
- Auto-saves every scan, deduplicates by URL, caps at 100 entries
- --history-file flag (default: scan_history.json)
- GET /history          returns all past scans newest-first
- DELETE /history/clear wipes history file

RATE LIMITING (new)
-------------------
- IPRateLimiter using golang.org/x/time/rate (token bucket)
- 10 req/s burst per IP
- Reads real IP from X-Forwarded-For (Cloud Run compatible)

MIDDLEWARE (new)
----------------
- corsMiddleware        wraps entire mux
- authMiddleware        validates X-API-Key header
- rateLimitMiddleware   enforces per-IP rate limit
- jsonMiddleware        sets Content-Type: application/json
- chain()              composes middleware without nesting

SERVER CONFIG
-------------
- Added ReadTimeout: 15s, WriteTimeout: 30s, IdleTimeout: 60s
- slog structured logging throughout (Cloud Run reads stdout as JSON)

CLI OUTPUT
----------
- Replaced single-line output with bordered box format (┌ │ └)
- Per-header checkmark/warning/X icons with inline fix tips

NEW DEPENDENCY
--------------
- golang.org/x/time v0.5.0
- Run: go mod tidy







Refactor Changelog
================================

FILE CHANGES — File Split (was single main.go file)
==========================================

FILES CREATED
-------------
analyzer.go
  - validationRule struct
  - headerRules map (all 10 rules with descriptions)
  - headerOrder slice (consistent ordering)
  - httpClient (shared client with timeout + 5 redirect limit)
  - analyzePage() — core scan logic

history.go
  - HistoryStore struct (thread-safe with sync.RWMutex)
  - NewHistoryStore() — constructor
  - Load() — reads history file, returns empty slice if not found
  - Append() — deduplicates by URL, prepends newest, caps at 100
  - historyGetHandler() — GET /history
  - historyDeleteHandler() — DELETE /history/clear

handlers.go
  - scanHandler() — clean handler, saves to history after scan
  - validateScanTarget() — SSRF protection, blocks private IPs
  - isPrivateIP() — checks IP against private CIDR ranges
  - sanitizeScanError() — strips internal error details from response

middleware.go
  - corsMiddleware — wraps entire mux, handles OPTIONS preflight
  - authMiddleware — validates X-API-Key header
  - rateLimitMiddleware — enforces per-IP rate limit
  - jsonMiddleware — sets Content-Type: application/json
  - chain() — composes middleware without nesting
  - realIP() — reads X-Forwarded-For for Cloud Run compatibility

ratelimiter.go
  - IPRateLimiter struct
  - NewIPRateLimiter() — constructor
  - Allow() — token bucket per IP using golang.org/x/time/rate

main.go (slimmed down, entry point only)
  - HeaderDetail struct — added Description field
  - ScanResult struct — added FinalURL, StatusCode, UsesHTTPS,
                        ScannedAt, Error fields
  - allowLocalTargets, requireAPIKey global flags
  - readLines(), deduplicate() — CLI helpers
  - printCLIResult() — bordered box output with icons
  - getLetterGrade() — grade calculation for CLI
  - main() — server setup with middleware chain + CLI mode


Behavior Changes
==========================
- History now persists to scan_history.json (was in-memory only)
- GET /history endpoint added
- DELETE /history/clear endpoint added
- Rate limiting: 10 req/s per IP (token bucket)
- SSRF protection: blocks localhost, private IPs, internal ranges
- Error messages sanitized before sending to client
- CORS now handles OPTIONS preflight correctly for all endpoints
- Server timeouts: ReadTimeout 15s, WriteTimeout 30s, IdleTimeout 60s
- REQUIRE_API_KEY env flag (default: true)
- ALLOW_LOCAL_TARGETS env flag (default: false)
- 4 new headers checked: Cross-Origin-Opener-Policy,
  Cross-Origin-Resource-Policy, X-XSS-Protection, Cache-Control
- All header rules include a description field
- Scoring is now dynamic percentage of total weight
- Redirect limit: max 5 redirects
>>>>>>> Initial commit
