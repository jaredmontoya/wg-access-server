package authsession

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/require"
)

func TestSecureCookieStore_Save_HTTPS(t *testing.T) {
	require := require.New(t)

	inner := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	store := NewSecureCookieStore(inner)

	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.TLS = &tls.ConnectionState{} // marks request as HTTPS
	w := httptest.NewRecorder()

	session, err := store.Get(r, "test-session")
	require.NoError(err)

	session.Values["key"] = "value"
	err = store.Save(r, w, session)
	require.NoError(err)

	require.True(session.Options.Secure, "Secure flag must be true for HTTPS requests")
	require.Equal(http.SameSiteLaxMode, session.Options.SameSite, "SameSite must be Lax for HTTPS requests")

	// Verify the Set-Cookie header contains Secure
	cookies := w.Result().Cookies()
	require.NotEmpty(cookies, "expected a Set-Cookie header")
	require.True(cookies[0].Secure, "cookie Secure attribute must be true for HTTPS")
}

func TestSecureCookieStore_Save_HTTP(t *testing.T) {
	require := require.New(t)

	inner := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	store := NewSecureCookieStore(inner)

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	// r.TLS is nil for plain HTTP
	w := httptest.NewRecorder()

	session, err := store.Get(r, "test-session")
	require.NoError(err)

	session.Values["key"] = "value"
	err = store.Save(r, w, session)
	require.NoError(err)

	require.False(session.Options.Secure, "Secure flag must be false for HTTP requests")
	require.Equal(http.SameSiteLaxMode, session.Options.SameSite, "SameSite must be Lax for HTTP requests")

	// Verify the Set-Cookie header does not contain Secure
	cookies := w.Result().Cookies()
	require.NotEmpty(cookies, "expected a Set-Cookie header")
	require.False(cookies[0].Secure, "cookie Secure attribute must be false for HTTP")
}

func TestSecureCookieStore_Save_NilOptions(t *testing.T) {
	require := require.New(t)

	inner := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	store := NewSecureCookieStore(inner)

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w := httptest.NewRecorder()

	session, err := store.Get(r, "test-session")
	require.NoError(err)

	// Force nil Options to test the nil-guard
	session.Options = nil
	session.Values["key"] = "value"
	err = store.Save(r, w, session)
	require.NoError(err)

	require.NotNil(session.Options, "Options must be initialized if nil")
	require.False(session.Options.Secure)
	require.Equal(http.SameSiteLaxMode, session.Options.SameSite)
}

func TestSecureCookieStore_Save_OverridesStoreDefaults(t *testing.T) {
	require := require.New(t)

	// gorilla/sessions v1.4.0 defaults: Secure=true, SameSite=None
	inner := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	// Verify that the inner store has the problematic defaults
	require.True(inner.Options.Secure, "gorilla/sessions v1.4.0 should default Secure=true")
	require.Equal(http.SameSiteNoneMode, inner.Options.SameSite, "gorilla/sessions v1.4.0 should default SameSite=None")

	store := NewSecureCookieStore(inner)

	// HTTP request: the wrapper must override the insecure defaults
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w := httptest.NewRecorder()

	session, err := store.Get(r, "test-session")
	require.NoError(err)

	session.Values["key"] = "value"
	err = store.Save(r, w, session)
	require.NoError(err)

	require.False(session.Options.Secure, "wrapper must override Secure to false for HTTP")
	require.Equal(http.SameSiteLaxMode, session.Options.SameSite, "wrapper must override SameSite to Lax")
}

func TestSecureCookieStore_GetNew_Delegate(t *testing.T) {
	require := require.New(t)

	inner := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	store := NewSecureCookieStore(inner)

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)

	// Test Get
	session, err := store.Get(r, "test-session")
	require.NoError(err)
	require.NotNil(session)
	require.True(session.IsNew)

	// Test New
	session2, err := store.New(r, "test-session-2")
	require.NoError(err)
	require.NotNil(session2)
	require.True(session2.IsNew)
}

func TestSecureCookieStore_Save_PreservesMaxAge(t *testing.T) {
	require := require.New(t)

	inner := sessions.NewCookieStore([]byte("0123456789abcdef0123456789abcdef"))
	store := NewSecureCookieStore(inner)

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w := httptest.NewRecorder()

	session, err := store.Get(r, "test-session")
	require.NoError(err)

	// Set MaxAge to -1 (delete cookie) and verify it's preserved
	session.Options.MaxAge = -1
	session.Values["key"] = "value"
	err = store.Save(r, w, session)
	require.NoError(err)

	require.Equal(-1, session.Options.MaxAge, "MaxAge must be preserved by the wrapper")
	require.False(session.Options.Secure)
	require.Equal(http.SameSiteLaxMode, session.Options.SameSite)
}
