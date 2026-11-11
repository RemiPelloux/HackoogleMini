// Safe logic PoC: reproduces the client/web request gate for LOGIN/ReadOnly mode
// to show that POST /api/up is accepted with (a) no browser session and (b) no
// Host validation, so a same-origin DNS-rebound page passes the only check.
//
// Logic copied verbatim from client/web/web.go @ v1.104.1:
//   - csrfProtect (web.go:241-299)
//   - authorizeRequest login-mode branch (web.go:507-514: default => return true)
//   - serve(): login mode does NOT call requireTailscaleIP (that is manage-mode only, web.go:335)
//
// Run: go run .
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
)

// --- verbatim from web.go csrfProtect ---
func csrfPasses(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
		// Fallback: Origin host must equal Host host.
		origin := r.Header.Get("Origin")
		if origin == "" {
			return false
		}
		// (web.go parses URLs; simplified: compare raw host authority)
		return originHost(origin) == r.Host
	default:
		return false // cross-site / same-site
	}
}

func originHost(origin string) string {
	// strip scheme:// prefix
	for _, p := range []string{"http://", "https://"} {
		if len(origin) > len(p) && origin[:len(p)] == p {
			return origin[len(p):]
		}
	}
	return origin
}

// --- login-mode authorizeRequest: no tailscale auth, default => true ---
func loginModeAuthorized(r *http.Request) bool { return true }

// login mode does NOT validate Host (no requireTailscaleIP). Full gate for /api/up:
func apiUpAccepted(r *http.Request) bool {
	// serve(): /api/* -> authorizeRequest -> csrfProtect -> handler
	return loginModeAuthorized(r) && csrfPasses(r)
}

func main() {
	cases := []struct {
		name    string
		host    string
		secFetch, origin string
	}{
		{"legit localhost POST (same-origin)", "localhost:8088", "same-origin", ""},
		{"DNS-REBOUND page: evil.com rebinds to 127.0.0.1, fetch('/api/up')", "evil.com:8088", "same-origin", ""},
		{"DNS-REBOUND, no Sec-Fetch, Origin==Host", "evil.com:8088", "", "http://evil.com:8088"},
		{"plain cross-site CSRF (no rebinding)", "localhost:8088", "cross-site", "http://evil.com"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "http://"+c.host+"/api/up", nil)
		r.Host = c.host
		if c.secFetch != "" {
			r.Header.Set("Sec-Fetch-Site", c.secFetch)
		}
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		verdict := "REJECTED"
		if apiUpAccepted(r) {
			verdict = ">>> ACCEPTED (repoint reaches serveTailscaleUp) <<<"
		}
		fmt.Printf("%-55s Host=%-16s -> %s\n", c.name, c.host, verdict)
	}
}
