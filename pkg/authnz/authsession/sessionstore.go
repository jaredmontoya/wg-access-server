package authsession

import (
	"net/http"

	"github.com/gorilla/sessions"
)

// SecureCookieStore wraps a sessions.Store and dynamically adjusts cookie
// security attributes based on the transport protocol of each request.
//
// gorilla/sessions v1.3.0+ defaults to Secure=true and SameSite=None,
// which breaks plain HTTP setups because browsers reject SameSite=None
// cookies without the Secure flag, and Secure cookies are never sent
// over HTTP.
//
// This wrapper inspects each request's TLS state and sets:
//   - HTTPS requests: Secure=true,  SameSite=Lax
//   - HTTP  requests: Secure=false, SameSite=Lax
//
// SameSite=Lax is used in both cases because it provides CSRF protection
// (blocks cross-origin POST) while allowing normal same-site navigation,
// and it was the effective browser default before the gorilla change.
type SecureCookieStore struct {
	store sessions.Store
}

// NewSecureCookieStore creates a SecureCookieStore wrapping the given store.
func NewSecureCookieStore(store sessions.Store) *SecureCookieStore {
	return &SecureCookieStore{store: store}
}

func (s *SecureCookieStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return s.store.Get(r, name)
}

func (s *SecureCookieStore) New(r *http.Request, name string) (*sessions.Session, error) {
	return s.store.New(r, name)
}

// Save delegates to the underlying store after adjusting the session's cookie
// security attributes to match the request's transport protocol.
func (s *SecureCookieStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	if session.Options == nil {
		session.Options = &sessions.Options{}
	}
	session.Options.Secure = r.TLS != nil
	session.Options.SameSite = http.SameSiteLaxMode
	return s.store.Save(r, w, session)
}
