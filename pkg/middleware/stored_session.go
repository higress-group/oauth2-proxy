package middleware

import (
	"context"
	"errors"
	"net/http"
	"time"

	middlewareapi "oidc/pkg/apis/middleware"
	sessionsapi "oidc/pkg/apis/sessions"

	"github.com/justinas/alice"
)

const (
	// When attempting to obtain the lock, if it's not done before this timeout
	// then exit and fail the refresh attempt.
	// TODO: This should probably be configurable by the end user.
	sessionRefreshObtainTimeout = 5 * time.Second

	// Maximum time allowed for a session refresh attempt.
	// If the refresh request isn't finished within this time, the lock will be
	// released.
	// TODO: This should probably be configurable by the end user.
	sessionRefreshLockDuration = 2 * time.Second

	// How long to wait after failing to obtain the lock before trying again.
	// TODO: This should probably be configurable by the end user.
	sessionRefreshRetryPeriod = 10 * time.Millisecond
)

// StoredSessionLoaderOptions contains all the requirements to construct
// a stored session loader.
// All options must be provided.
type StoredSessionLoaderOptions struct {
	// Session storage backend
	SessionStore sessionsapi.SessionStore

	// How often should sessions be refreshed
	RefreshPeriod time.Duration

	// Provider based session refreshing
	RefreshSession func(context.Context, *sessionsapi.SessionState) (bool, error)

	// Provider based session validation.
	// If the session is older than `RefreshPeriod` but the provider doesn't
	// refresh it, we must re-validate using this validation.
	ValidateSession func(context.Context, *sessionsapi.SessionState) bool
}

// NewStoredSessionLoader creates a new storedSessionLoader which loads
// sessions from the session store.
// If no session is found, the request will be passed to the nex handler.
// If a session was loader by a previous handler, it will not be replaced.
func NewStoredSessionLoader(opts *StoredSessionLoaderOptions) alice.Constructor {
	ss := &storedSessionLoader{
		store:         opts.SessionStore,
		refreshPeriod: opts.RefreshPeriod,
	}
	return ss.loadSession
}

// storedSessionLoader is responsible for loading sessions from cookie
// identified sessions in the session store.
type storedSessionLoader struct {
	store         sessionsapi.SessionStore
	refreshPeriod time.Duration
}

// loadSession attempts to load a session as identified by the request cookies.
// If no session is found, the request will be passed to the next handler.
// If a session was loader by a previous handler, it will not be replaced.
func (s *storedSessionLoader) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		if scope.Session != nil {
			// The session was already loaded, pass to the next handler
			next.ServeHTTP(rw, req)
			return
		}
		session, err := s.getValidatedSession(rw, req)
		if err != nil && !errors.Is(err, http.ErrNoCookie) {
			// In the case when there was an error loading the session,
			// we should clear the session
			//logger.Errorf("Error loading cookied session: %v, removing session", err)
			err = s.store.Clear(rw, req)
			if err != nil {
				//logger.Errorf("Error removing session: %v", err)
			}
		}

		// Add the session to the scope if it was found
		scope.Session = session
		next.ServeHTTP(rw, req)
	})
}

// getValidatedSession is responsible for loading a session and making sure
// that is valid.
func (s *storedSessionLoader) getValidatedSession(rw http.ResponseWriter, req *http.Request) (*sessionsapi.SessionState, error) {
	session, err := s.store.Load(req)
	if err != nil || session == nil {
		// No session was found in the storage or error occurred, nothing more to do
		return nil, err
	}

	return session, nil
}
