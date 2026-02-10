package authsession

import (
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
)

// SetSecureCookieDefaults overrides the default cookie options on a CookieStore
// to fix the compatibility issue introduced in gorilla/sessions v1.3.0+, which
// defaults to Secure=true and SameSite=None. That combination breaks plain HTTP
// setups because browsers reject SameSite=None without Secure, and Secure
// cookies are never sent over HTTP.
//
// This sets the store defaults to:
//   - Secure=false  (safe baseline; upgraded per-request by CookieSecureMiddleware)
//   - SameSite=Lax  (CSRF protection while allowing normal same-site navigation)
//
// SameSite=Lax is the correct choice for both HTTP and HTTPS because:
//   - It was the effective browser default before gorilla changed it to None.
//   - It blocks cross-origin POST requests from sending cookies (CSRF protection).
//   - It allows top-level GET navigations to include cookies (normal usage).
//   - OWASP recommends Lax as the standard for same-site applications.
func SetSecureCookieDefaults(store *sessions.CookieStore) {
	store.Options.Secure = false
	store.Options.SameSite = http.SameSiteLaxMode
}

// CookieSecureMiddleware returns an HTTP middleware that dynamically sets the
// Secure flag on session cookies based on the request's transport protocol.
//
// When the request is over HTTPS — either directly (r.TLS != nil) or behind a
// TLS-terminating reverse proxy (X-Forwarded-Proto: https) — any Set-Cookie
// headers written by downstream handlers are upgraded to include the Secure flag.
// This ensures cookies are marked Secure on HTTPS without breaking HTTP.
//
// This works in tandem with SetSecureCookieDefaults: the store defaults to
// Secure=false (for HTTP compatibility), and this middleware upgrades to
// Secure=true for HTTPS requests at the HTTP response level.
func CookieSecureMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isTLS(r) {
			w = &secureResponseWriter{ResponseWriter: w}
		}
		next.ServeHTTP(w, r)
	})
}

// isTLS reports whether the request was made over HTTPS, either directly
// (r.TLS != nil) or via a TLS-terminating reverse proxy that sets the
// X-Forwarded-Proto header. The worst case for a spoofed header on plain
// HTTP is that the Secure flag gets set and the browser refuses to send
// the cookie back — a self-denial-of-service, not a security escalation.
func isTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// secureResponseWriter wraps http.ResponseWriter and adds the Secure flag
// to all Set-Cookie headers before they are flushed to the client.
//
// Headers are flushed on the first call to WriteHeader or Write. Both methods
// are intercepted to ensure cookies are upgraded regardless of which is called
// first.
type secureResponseWriter struct {
	http.ResponseWriter
	headerWritten bool
}

// upgradeCookies upgrades Set-Cookie headers exactly once, before the
// headers are flushed to the client.
func (w *secureResponseWriter) upgradeCookies() {
	if !w.headerWritten {
		w.headerWritten = true
		upgradeCookiesToSecure(w.ResponseWriter.Header())
	}
}

// WriteHeader intercepts the response status to upgrade all Set-Cookie headers
// with the Secure flag before the headers are sent to the client.
func (w *secureResponseWriter) WriteHeader(statusCode int) {
	w.upgradeCookies()
	w.ResponseWriter.WriteHeader(statusCode)
}

// Write upgrades cookies before the first write, which implicitly flushes
// headers if WriteHeader has not been called yet.
func (w *secureResponseWriter) Write(b []byte) (int, error) {
	w.upgradeCookies()
	return w.ResponseWriter.Write(b)
}

// Flush implements http.Flusher by upgrading cookies (which flushes headers)
// and then delegating to the underlying ResponseWriter's Flush if supported.
// This ensures the wrapper doesn't silently break SSE or streaming responses.
func (w *secureResponseWriter) Flush() {
	w.upgradeCookies()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter, allowing middleware further
// up the chain to access optional interfaces via httputil.ResponseController
// or similar unwrapping mechanisms.
func (w *secureResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// upgradeCookiesToSecure adds the Secure attribute to all Set-Cookie headers
// that don't already have it.
func upgradeCookiesToSecure(h http.Header) {
	cookies := h.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	h.Del("Set-Cookie")
	for _, cookie := range cookies {
		if !hasSecureFlag(cookie) {
			cookie += "; Secure"
		}
		h.Add("Set-Cookie", cookie)
	}
}

// hasSecureFlag checks if a Set-Cookie header value contains the Secure attribute.
func hasSecureFlag(cookie string) bool {
	// The Secure attribute is a standalone flag (no =value).
	// Split on ";" and check each part after trimming whitespace.
	for _, part := range strings.Split(cookie, ";") {
		if strings.EqualFold(strings.TrimSpace(part), "secure") {
			return true
		}
	}
	return false
}
