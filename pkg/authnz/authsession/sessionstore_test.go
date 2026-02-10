package authsession

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/require"
)

func TestSetSecureCookieDefaults(t *testing.T) {
	require := require.New(t)

	store := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))

	// Confirm gorilla v1.4.0 problematic defaults
	require.True(store.Options.Secure, "gorilla/sessions v1.4.0 should default Secure=true")
	require.Equal(http.SameSiteNoneMode, store.Options.SameSite, "gorilla/sessions v1.4.0 should default SameSite=None")

	SetSecureCookieDefaults(store)

	require.False(store.Options.Secure, "Secure must be false after SetSecureCookieDefaults")
	require.Equal(http.SameSiteLaxMode, store.Options.SameSite, "SameSite must be Lax after SetSecureCookieDefaults")

	// Verify other defaults are preserved
	require.Equal("/", store.Options.Path)
	require.Equal(86400*30, store.Options.MaxAge)
}

func TestSetSecureCookieDefaults_SessionInheritsOptions(t *testing.T) {
	require := require.New(t)

	store := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	SetSecureCookieDefaults(store)

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)

	session, err := store.Get(r, "test-session")
	require.NoError(err)

	// Session options should inherit the store defaults
	require.False(session.Options.Secure, "new sessions must inherit Secure=false")
	require.Equal(http.SameSiteLaxMode, session.Options.SameSite, "new sessions must inherit SameSite=Lax")
}

func TestCookieSecureMiddleware_HTTP_NoSecureFlag(t *testing.T) {
	require := require.New(t)

	store := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	SetSecureCookieDefaults(store)

	handler := CookieSecureMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "test-session")
		require.NoError(err)
		session.Values["key"] = "value"
		err = session.Save(r, w)
		require.NoError(err)
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	// r.TLS is nil for HTTP
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	require.NotEmpty(cookies, "expected a Set-Cookie header")
	require.False(cookies[0].Secure, "cookie must NOT have Secure flag for HTTP requests")
}

func TestCookieSecureMiddleware_HTTPS_HasSecureFlag(t *testing.T) {
	require := require.New(t)

	store := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	SetSecureCookieDefaults(store)

	handler := CookieSecureMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "test-session")
		require.NoError(err)
		session.Values["key"] = "value"
		err = session.Save(r, w)
		require.NoError(err)
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	require.NotEmpty(cookies, "expected a Set-Cookie header")
	require.True(cookies[0].Secure, "cookie must have Secure flag for HTTPS requests")
}

func TestCookieSecureMiddleware_HTTPS_UpgradesSessionSave(t *testing.T) {
	require := require.New(t)

	// Simulate the real flow: store defaults are Secure=false,
	// session.Save() writes a non-Secure cookie, but the middleware
	// must upgrade it to Secure on HTTPS.
	store := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	SetSecureCookieDefaults(store)

	handler := CookieSecureMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "test-session")
		require.NoError(err)
		session.Values["user"] = "admin"
		// session.Save() goes directly to CookieStore (bypassing any wrapper).
		// The middleware's ResponseWriter interception is what adds Secure.
		err = session.Save(r, w)
		require.NoError(err)
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	require.NotEmpty(cookies)
	require.True(cookies[0].Secure, "session.Save() cookie must be upgraded to Secure on HTTPS")
}

func TestCookieSecureMiddleware_HTTP_PreservesNonSecure(t *testing.T) {
	require := require.New(t)

	store := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	SetSecureCookieDefaults(store)

	handler := CookieSecureMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "test-session")
		require.NoError(err)
		session.Values["user"] = "admin"
		err = session.Save(r, w)
		require.NoError(err)
	}))

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	require.NotEmpty(cookies)
	require.False(cookies[0].Secure, "HTTP cookies must not have Secure flag")
}

func TestCookieSecureMiddleware_HTTPS_PreservesMaxAge(t *testing.T) {
	require := require.New(t)

	store := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	SetSecureCookieDefaults(store)

	handler := CookieSecureMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "test-session")
		require.NoError(err)
		session.Options.MaxAge = -1 // delete cookie
		err = session.Save(r, w)
		require.NoError(err)
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	require.NotEmpty(cookies)
	require.True(cookies[0].Secure, "Secure must be set on HTTPS even for deletion cookies")
	require.True(cookies[0].MaxAge < 0, "MaxAge must be preserved")
}

func TestCookieSecureMiddleware_MultipleCookies(t *testing.T) {
	require := require.New(t)

	handler := CookieSecureMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "a", Value: "1"})
		http.SetCookie(w, &http.Cookie{Name: "b", Value: "2"})
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	require.Len(cookies, 2, "both cookies must be present")
	for _, c := range cookies {
		require.True(c.Secure, "all cookies must have Secure flag on HTTPS: %s", c.Name)
	}
}

func TestCookieSecureMiddleware_AlreadySecureCookie(t *testing.T) {
	require := require.New(t)

	handler := CookieSecureMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "a", Value: "1", Secure: true})
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	require.Len(cookies, 1)
	require.True(cookies[0].Secure)
}

func TestHasSecureFlag(t *testing.T) {
	tests := []struct {
		name   string
		cookie string
		want   bool
	}{
		{"with Secure", "session=abc; Path=/; Secure; HttpOnly", true},
		{"without Secure", "session=abc; Path=/; HttpOnly", false},
		{"Secure only", "session=abc; Secure", true},
		{"secure lowercase", "session=abc; secure", true},
		{"SECURE uppercase", "session=abc; SECURE", true},
		{"SecureValue is not flag", "session=abc; SecureFoo=bar", false},
		{"empty cookie", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			require.Equal(tt.want, hasSecureFlag(tt.cookie))
		})
	}
}

func TestCookieSecureMiddleware_ImplicitWriteHeader(t *testing.T) {
	require := require.New(t)

	// When a handler writes the body without calling WriteHeader explicitly,
	// Go's net/http calls WriteHeader(200) implicitly on the first Write call.
	// The middleware must still upgrade cookies in that case.
	store := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	SetSecureCookieDefaults(store)

	handler := CookieSecureMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "test-session")
		require.NoError(err)
		session.Values["key"] = "value"
		err = session.Save(r, w)
		require.NoError(err)
		// Write body without explicit WriteHeader — triggers implicit flush
		_, _ = w.Write([]byte("ok"))
	}))

	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	require.NotEmpty(cookies, "expected a Set-Cookie header")
	require.True(cookies[0].Secure, "cookie must have Secure flag even without explicit WriteHeader")
}

func TestCookieSecureMiddleware_XForwardedProto_HTTPS(t *testing.T) {
	require := require.New(t)

	store := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	SetSecureCookieDefaults(store)

	handler := CookieSecureMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "test-session")
		require.NoError(err)
		session.Values["key"] = "value"
		err = session.Save(r, w)
		require.NoError(err)
		w.WriteHeader(http.StatusOK)
	}))

	// Simulate a reverse proxy: r.TLS is nil but X-Forwarded-Proto is https
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	require.NotEmpty(cookies, "expected a Set-Cookie header")
	require.True(cookies[0].Secure, "cookie must have Secure flag when X-Forwarded-Proto is https")
}

func TestCookieSecureMiddleware_XForwardedProto_HTTP(t *testing.T) {
	require := require.New(t)

	store := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	SetSecureCookieDefaults(store)

	handler := CookieSecureMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "test-session")
		require.NoError(err)
		session.Values["key"] = "value"
		err = session.Save(r, w)
		require.NoError(err)
		w.WriteHeader(http.StatusOK)
	}))

	// X-Forwarded-Proto is http — should NOT upgrade
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.Header.Set("X-Forwarded-Proto", "http")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	require.NotEmpty(cookies, "expected a Set-Cookie header")
	require.False(cookies[0].Secure, "cookie must NOT have Secure flag when X-Forwarded-Proto is http")
}

func TestIsTLS(t *testing.T) {
	tests := []struct {
		name           string
		tls            bool
		forwardedProto string
		want           bool
	}{
		{"direct TLS", true, "", true},
		{"direct TLS with header", true, "https", true},
		{"proxy HTTPS", false, "https", true},
		{"proxy HTTPS uppercase", false, "HTTPS", true},
		{"proxy HTTP", false, "http", false},
		{"no TLS no header", false, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if tt.forwardedProto != "" {
				r.Header.Set("X-Forwarded-Proto", tt.forwardedProto)
			}
			require.Equal(tt.want, isTLS(r))
		})
	}
}

// flushRecorder wraps httptest.ResponseRecorder and tracks Flush calls.
type flushRecorder struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (f *flushRecorder) Flush() {
	f.flushed = true
	f.ResponseRecorder.Flush()
}

func TestSecureResponseWriter_Flush(t *testing.T) {
	require := require.New(t)

	handler := CookieSecureMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "a", Value: "1"})
		// Flush should be forwarded to the underlying writer
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		} else {
			t.Fatal("secureResponseWriter must implement http.Flusher")
		}
	}))

	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.TLS = &tls.ConnectionState{}
	w := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}

	handler.ServeHTTP(w, r)

	require.True(w.flushed, "Flush must be forwarded to the underlying ResponseWriter")
	cookies := w.Result().Cookies()
	require.NotEmpty(cookies)
	require.True(cookies[0].Secure, "cookies must be upgraded before flush")
}

func TestSecureResponseWriter_Unwrap(t *testing.T) {
	require := require.New(t)

	inner := httptest.NewRecorder()
	srw := &secureResponseWriter{ResponseWriter: inner}
	require.Equal(inner, srw.Unwrap(), "Unwrap must return the underlying ResponseWriter")
}
