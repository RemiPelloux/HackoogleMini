# Funnel: Tailscale identity headers stripped only in dash-case — underscore variants reach the backend (internet identity spoofing)

**Component:** `client/web` serve/Funnel reverse proxy — `ipn/ipnlocal/serve.go`
**Affected version:** Tailscale v1.104.1 (confirmed; present on current `main`)
**Reporter:** (your name / HackerOne handle)
**Severity:** High (unauthenticated internet client spoofs a trusted Tailscale
identity to a serve/Funnel backend). Exploitability is backend-dependent — see
*Preconditions*. CVSS:3.1 ~ `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N`.

## Summary

When a node uses `tailscale serve`/Funnel to reverse-proxy to a backend,
tailscaled injects/strips `Tailscale-User-Login` and friends so the backend can
trust them (documented at tailscale.com/s/serve-headers: absence ⇒
unauthenticated/Funnel). On the **Funnel** path tailscaled deliberately sets
**no** `Tailscale-User-*` identity headers and strips any the client sent — but
it strips them only by their exact **dash-case** names. Go's header
canonicalization treats `_` as a non-separator, so an **underscore** variant
such as `Tailscale_User_Login` is a *different* header key, is never stripped,
and is forwarded verbatim to the backend. Backends that fold `-` and `_` into
the same variable (CGI/FastCGI/PHP/WSGI, and gateways configured with
`underscores_in_headers on`) then read the attacker's value as the trusted
identity. Because the legitimate dash header is absent on Funnel, the attacker's
underscore header is the *sole* source — a clean identity spoof from the
internet.

## Affected code (`ipn/ipnlocal/serve.go`)

```go
func (b *LocalBackend) addTailscaleIdentityHeaders(r *httputil.ProxyRequest) {
	// Clear any incoming values squatting in the headers.
	r.Out.Header.Del("Tailscale-User-Login")        // dash-case only
	r.Out.Header.Del("Tailscale-User-Name")
	r.Out.Header.Del("Tailscale-User-Profile-Pic")
	r.Out.Header.Del("Tailscale-Funnel-Request")
	r.Out.Header.Del("Tailscale-Headers-Info")
	c, ok := serveHTTPContextKey.ValueOk(r.Out.Context())
	if !ok { return }
	if c.Funnel != nil {
		r.Out.Header.Set("Tailscale-Funnel-Request", "?1")
		return                                        // <-- no Tailscale-User-* set on Funnel
	}
	... // (tailnet path sets identity after WhoIs)
}
// addAppCapabilitiesHeader likewise Del's only the exact dash-case
// "Tailscale-App-Capabilities".
```

`http.Header.Del` keys on `textproto.CanonicalMIMEHeaderKey`, which only treats
`-` as a word separator. `Tailscale_User_Login` canonicalizes to
`Tailscale_user_login` — a distinct key the `Del`s never touch. The serve proxy
is a standard `httputil.ReverseProxy` whose `r.Out` is a clone of the inbound
request, so the surviving underscore header is forwarded to the backend. There
is no catch-all `Tailscale-*`/`Tailscale_*` prefix strip anywhere on the path
(only the six explicit dash `Del`s above).

## Proof of concept

`poc/` runs the finding end-to-end using Go's **real** `net/http/httputil.ReverseProxy`,
wired with the **exact** `Del` sequence copied verbatim from `serve.go`
(Funnel branch), in front of a CGI/RFC-3875 backend (the header→`HTTP_*`
env mapping used by CGI/FastCGI/PHP):

```
$ cd poc && go run .
internet client sends: Tailscale-User-Login=stripped-dash AND Tailscale_User_Login=attacker@evil.example
  backend raw headers seen: ... "Tailscale-Funnel-Request" "Tailscale_user_login"
  backend HTTP_TAILSCALE_USER_LOGIN = "attacker@evil.example"
  >>> SPOOFED: backend authenticated the internet attacker as a trusted Tailscale user <<<
```

The dash header is stripped; the underscore header survives the real proxy and
is read by the backend as `HTTP_TAILSCALE_USER_LOGIN`. (`poc/run-output.txt`.)

## Impact

An unauthenticated internet client reaching a Funnel-exposed proxy backend can
set `Tailscale_User_Login` (and `Tailscale_User_Name`, `Tailscale_App_Capabilities`,
or suppress/forge `Tailscale_Funnel_Request`) and have the backend treat the
request as coming from an arbitrary authenticated tailnet user — defeating the
documented serve-headers trust model. For apps that gate admin access on
`Tailscale-User-Login`, this is an authentication bypass.

## Preconditions / honest scope

- Funnel enabled on a serve mount with a `Proxy` backend.
- The backend (or an intermediate gateway) must map `_` and `-` headers to the
  same variable. This is true for CGI/FastCGI/PHP/WSGI and for nginx with
  `underscores_in_headers on`; nginx's **default** (`off`) drops underscore
  headers, so an nginx-fronted backend is not affected by default. The
  tailscaled-side gap is unconditional; reach depends on the backend.

## Remediation

Strip the identity/capability/funnel headers by a normalized or prefix match
(e.g. remove any header whose canonical name, with `_`→`-`, matches a reserved
`Tailscale-*` name), and/or reject requests carrying `_`-variants of reserved
names, rather than `Del`-ing only the exact dash spellings.

## References
- `ipn/ipnlocal/serve.go` `addTailscaleIdentityHeaders` (~:1098-1126),
  `addAppCapabilitiesHeader` (~:1144)
- RFC 3875 §4.1.18 (CGI meta-variable mapping of header names)
- Serve headers contract: https://tailscale.com/s/serve-headers

## Disclosure
Reported privately to Tailscale (security@tailscale.com). No public disclosure
until a fix ships / per program policy.
