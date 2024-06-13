package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	middlewareapi "oidc/pkg/apis/middleware"
	"oidc/pkg/apis/options"
	sessionsapi "oidc/pkg/apis/sessions"
	"oidc/pkg/app/redirect"
	"oidc/pkg/cookies"
	"oidc/pkg/encryption"
	"oidc/pkg/middleware"
	requestutil "oidc/pkg/requests/util"
	"oidc/pkg/sessions"
	"oidc/providers"
	"strings"
	"time"

	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/gorilla/mux"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/justinas/alice"
)

const (
	schemeHTTP      = "http"
	schemeHTTPS     = "https"
	applicationJSON = "application/json"

	oauthStartPath    = "/start"
	oauthCallbackPath = "/callback"
)

var (
	// ErrNeedsLogin means the user should be redirected to the login page
	ErrNeedsLogin = errors.New("redirect to login page")

	// ErrAccessDenied means the user should receive a 401 Unauthorized response
	ErrAccessDenied = errors.New("access denied")
)

// OAuthProxy is the main authentication proxy
type OAuthProxy struct {
	CookieOptions *options.Cookie
	Validator     func(string) bool

	redirectURL         *url.URL // the url to receive requests at
	relativeRedirectURL bool
	whitelistDomains    []string
	provider            providers.Provider
	sessionStore        sessionsapi.SessionStore
	ProxyPrefix         string
	skipAuthPreflight   bool

	sessionChain alice.Chain
	preAuthChain alice.Chain

	serveMux          *mux.Router
	redirectValidator redirect.Validator
	appDirector       redirect.AppDirector

	encodeState bool

	client wrapper.HttpClient
	logger *wrapper.Log
}

// NewOAuthProxy creates a new instance of OAuthProxy from the options provided
func NewOAuthProxy(opts *options.Options, validator func(string) bool, log *wrapper.Log) (*OAuthProxy, error) {
	sessionStore, err := sessions.NewSessionStore(&opts.Session, &opts.Cookie)
	if err != nil {
		return nil, fmt.Errorf("error initialising session store: %v", err)
	}

	provider, err := providers.NewProvider(opts.Providers[0])
	if err != nil {
		return nil, fmt.Errorf("error initialising provider: %v", err)
	}

	redirectURL := opts.GetRedirectURL()
	if redirectURL.Path == "" {
		redirectURL.Path = fmt.Sprintf("%s/callback", opts.ProxyPrefix)
	}

	// logger.Printf("OAuthProxy configured for %s Client ID: %s", provider.Data().ProviderName, opts.Providers[0].ClientID)
	// refresh := "disabled"
	// if opts.Cookie.Refresh != time.Duration(0) {
	// 	refresh = fmt.Sprintf("after %s", opts.Cookie.Refresh)
	// } // TODO: check

	// logger.Printf("Cookie settings: name:%s secure(https):%v httponly:%v expiry:%s domains:%s path:%s samesite:%s refresh:%s", opts.Cookie.Name, opts.Cookie.Secure, opts.Cookie.HTTPOnly, opts.Cookie.Expire, strings.Join(opts.Cookie.Domains, ","), opts.Cookie.Path, opts.Cookie.SameSite, refresh)

	preAuthChain, err := buildPreAuthChain(opts)
	if err != nil {
		return nil, fmt.Errorf("could not build pre-auth chain: %v", err)
	}
	sessionChain := buildSessionChain(opts, provider, sessionStore)

	redirectValidator := redirect.NewValidator(opts.WhitelistDomains)
	appDirector := redirect.NewAppDirector(redirect.AppDirectorOpts{
		ProxyPrefix: opts.ProxyPrefix,
		Validator:   redirectValidator,
	})

	serviceClient, err := opts.Service.NewService()
	if err != nil {
		return nil, err
	}
	p := &OAuthProxy{
		CookieOptions: &opts.Cookie,
		Validator:     validator,

		ProxyPrefix:         opts.ProxyPrefix,
		provider:            provider,
		sessionStore:        sessionStore,
		redirectURL:         redirectURL,
		relativeRedirectURL: opts.RelativeRedirectURL,
		whitelistDomains:    opts.WhitelistDomains,
		skipAuthPreflight:   opts.SkipAuthPreflight,

		sessionChain: sessionChain,
		preAuthChain: preAuthChain,

		redirectValidator: redirectValidator,
		appDirector:       appDirector,
		encodeState:       opts.EncodeState,

		client: serviceClient,
		logger: log,
	}
	p.buildServeMux(opts.ProxyPrefix)

	return p, nil
}

func (p *OAuthProxy) buildServeMux(proxyPrefix string) {
	// Use the encoded path here, so we can have the option to pass it on in the upstream mux.
	// Otherwise, something like /%2F/ would be redirected to / here already.
	r := mux.NewRouter().UseEncodedPath()
	// Everything served by the router must go through the preAuthChain first.
	r.Use(p.preAuthChain.Then)

	// This will register all the paths under the proxy prefix, except the auth only path so that no cache headers
	// are not applied.
	p.buildProxySubRouter(r.PathPrefix(proxyPrefix).Subrouter())

	// Register serveHTTP last, so it catches anything that isn't already caught earlier.
	// Anything that got to this point needs to have a session loaded.
	r.PathPrefix("/").Handler(p.sessionChain.ThenFunc(p.Proxy))
	p.serveMux = r
}

func (p *OAuthProxy) buildProxySubRouter(s *mux.Router) {
	s.Use(prepareNoCacheMiddleware)

	s.Path(oauthStartPath).HandlerFunc(p.OAuthStart)
	s.Path(oauthCallbackPath).HandlerFunc(p.OAuthCallback)
}

// buildPreAuthChain constructs a chain that should process every request before
// the OAuth2 Proxy authentication logic kicks in.
// For example forcing HTTPS or health checks.
func buildPreAuthChain(opts *options.Options) (alice.Chain, error) {
	chain := alice.New(middleware.NewScope(opts.ReverseProxy, "X-Request-Id"))
	return chain, nil
}

func buildSessionChain(opts *options.Options, provider providers.Provider, sessionStore sessionsapi.SessionStore) alice.Chain {
	chain := alice.New()

	chain = chain.Append(middleware.NewStoredSessionLoader(&middleware.StoredSessionLoaderOptions{
		SessionStore:    sessionStore,
		RefreshPeriod:   opts.Cookie.Refresh,
		RefreshSession:  provider.RefreshSession,
		ValidateSession: provider.ValidateSession,
	}))

	return chain
}

// OAuthStart starts the OAuth2 authentication flow
func (p *OAuthProxy) OAuthStart(rw http.ResponseWriter, req *http.Request) {
	// start the flow permitting login URL query parameters to be overridden from the request URL
	p.doOAuthStart(rw, req, req.URL.Query())
}

func (p *OAuthProxy) doOAuthStart(rw http.ResponseWriter, req *http.Request, overrides url.Values) {
	extraParams := p.provider.Data().LoginURLParams(overrides)
	prepareNoCache(rw)

	var (
		err                                              error
		codeChallenge, codeVerifier, codeChallengeMethod string
	)
	if p.provider.Data().CodeChallengeMethod != "" {
		codeChallengeMethod = p.provider.Data().CodeChallengeMethod
		codeVerifier, err = encryption.GenerateRandomASCIIString(96)
		if err != nil {
			p.logger.Errorf("Unable to build random ASCII string for code verifier: %v", err)
			return
		}

		codeChallenge, err = encryption.GenerateCodeChallenge(p.provider.Data().CodeChallengeMethod, codeVerifier)
		if err != nil {
			p.logger.Errorf("Error creating code challenge: %v", err)
			return
		}

		extraParams.Add("code_challenge", codeChallenge)
		extraParams.Add("code_challenge_method", codeChallengeMethod)
	}

	csrf, err := cookies.NewCSRF(p.CookieOptions, codeVerifier)
	if err != nil {
		p.logger.Errorf("Error creating CSRF nonce: %v", err)
		return
	}

	appRedirect, err := p.appDirector.GetRedirect(req)
	if err != nil {
		p.logger.Errorf("Error obtaining application redirect: %v", err)
		return
	}
	callbackRedirect := p.getOAuthRedirectURI(req)

	loginURL := p.provider.GetLoginURL(
		callbackRedirect,
		encodeState(csrf.HashOAuthState(), appRedirect, p.encodeState),
		csrf.HashOIDCNonce(),
		extraParams,
	)

	if _, err := csrf.SetCookie(rw, req); err != nil {
		p.logger.Errorf("Error setting CSRF cookie: %v", err)
		return
	}
	headersMap := [][2]string{{"Location", loginURL}}
	for key, value := range rw.Header() {
		headersMap = append(headersMap, [2]string{key, strings.Join(value, ",")})
	}
	fmt.Println(headersMap)
	proxywasm.SendHttpResponse(http.StatusFound, headersMap, nil, -1)
}

// getOAuthRedirectURI returns the redirectURL that the upstream OAuth Provider will
// redirect clients to once authenticated.
// This is usually the OAuthProxy callback URL.
func (p *OAuthProxy) getOAuthRedirectURI(req *http.Request) string {
	// if `p.redirectURL` already has a host, return it
	if p.relativeRedirectURL || p.redirectURL.Host != "" {
		return p.redirectURL.String()
	}

	// Otherwise figure out the scheme + host from the request
	rd := *p.redirectURL
	rd.Host = requestutil.GetRequestHost(req)
	rd.Scheme = requestutil.GetRequestProto(req)

	// If there's no scheme in the request, we should still include one
	if rd.Scheme == "" {
		rd.Scheme = schemeHTTP
	}

	// If CookieSecure is true, return `https` no matter what
	// Not all reverse proxies set X-Forwarded-Proto
	if p.CookieOptions.Secure {
		rd.Scheme = schemeHTTPS
	}
	return rd.String()
}

// OAuthCallback is the OAuth2 authentication flow callback that finishes the
// OAuth2 authentication flow
func (p *OAuthProxy) OAuthCallback(rw http.ResponseWriter, req *http.Request) {
	// finish the oauth cycle
	err := req.ParseForm()
	if err != nil {
		p.logger.Errorf("Error while parsing OAuth2 callback: %v", err)
		return
	}
	errorString := req.Form.Get("error")
	if errorString != "" {
		p.logger.Errorf("Error while parsing OAuth2 callback: %s", errorString)
		return
	}

	csrf, err := cookies.LoadCSRFCookie(req, p.CookieOptions)
	if err != nil {
		p.logger.Errorf("Invalid authentication via OAuth2. Error while loading CSRF cookie: %v", err)
		return
	}
	fmt.Printf("[DEBUG] csrf : %+v", csrf)
	// session, err := p.redeemCode(req, csrf.GetCodeVerifier())
	// if err != nil {
	// 	//logger.Errorf("Error redeeming code during OAuth2 callback: %v", err)
	// 	// p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
	// 	return
	// }

	// err = p.enrichSessionState(req.Context(), session)
	// if err != nil {
	// 	//logger.Errorf("Error creating session during OAuth2 callback: %v", err)
	// 	// p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
	// 	return
	// }

	// csrf.ClearCookie(rw, req)

	// nonce, appRedirect, err := decodeState(req.Form.Get("state"), p.encodeState)
	// if err != nil {
	// 	//logger.Errorf("Error while parsing OAuth2 state: %v", err)
	// 	// p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
	// 	return
	// }

	// if !csrf.CheckOAuthState(nonce) {
	// 	//logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authentication via OAuth2: CSRF token mismatch, potential attack")
	// 	// p.ErrorPage(rw, req, http.StatusForbidden, "CSRF token mismatch, potential attack", "Login Failed: Unable to find a valid CSRF token. Please try again.")
	// 	return
	// }

	// csrf.SetSessionNonce(session)
	// if !p.provider.ValidateSession(req.Context(), session) {
	// 	//logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Session validation failed: %s", session)
	// 	// p.ErrorPage(rw, req, http.StatusForbidden, "Session validation failed")
	// 	return
	// }

	// if !p.redirectValidator.IsValidRedirect(appRedirect) {
	// 	appRedirect = "/"
	// }

	// // set cookie, or deny
	// authorized, err := p.provider.Authorize(req.Context(), session)
	// if err != nil {
	// 	//logger.Errorf("Error with authorization: %v", err)
	// }
	// if p.Validator(session.Email) && authorized {
	// 	//logger.PrintAuthf(session.Email, req, logger.AuthSuccess, "Authenticated via OAuth2: %s", session)
	// 	err := p.SaveSession(rw, req, session)
	// 	if err != nil {
	// 		//logger.Errorf("Error saving session state for %s: %v", remoteAddr, err)
	// 		// p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
	// 		return
	// 	}
	// 	//http.Redirect(rw, req, appRedirect, http.StatusFound)
	// } else {
	// 	//logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authentication via OAuth2: unauthorized")
	// 	// p.ErrorPage(rw, req, http.StatusForbidden, "Invalid session: unauthorized")
	// }
}

// Proxy proxies the user request if the user is authenticated else it prompts
// them to authenticate
func (p *OAuthProxy) Proxy(rw http.ResponseWriter, req *http.Request) {
	session, err := p.getAuthenticatedSession(rw, req)
	switch {
	case err == nil:
		// we are authenticated
		p.addHeadersForProxying(rw, session)
		//TODO：check correct？
	case errors.Is(err, ErrNeedsLogin):
		// we need to send the user to a login screen
		if isAjax(req) {
			p.logger.Infof("No valid authentication in request. Access Denied.")
			// no point redirecting an AJAX request
			return
		}
		p.logger.Infof("No valid authentication in request. Initiating login.")
		// start OAuth flow, but only with the default login URL params - do not
		// consider this request's query params as potential overrides, since
		// the user did not explicitly start the login flow
		p.doOAuthStart(rw, req, nil)
	case errors.Is(err, ErrAccessDenied):
		// p.ErrorPage(rw, req, http.StatusForbidden, "The session failed authorization checks")
	default:
		// unknown error
		p.logger.Errorf("Unexpected internal error: %v", err)
	}
}

// getAuthenticatedSession checks whether a user is authenticated and returns a session object and nil error if so
// Returns:
// - `nil, ErrNeedsLogin` if user needs to log in.
// - `nil, ErrAccessDenied` if the authenticated user is not authorized
// Set-Cookie headers may be set on the response as a side effect of calling this method.
func (p *OAuthProxy) getAuthenticatedSession(rw http.ResponseWriter, req *http.Request) (*sessionsapi.SessionState, error) {
	session := middlewareapi.GetRequestScope(req).Session

	// Check this after loading the session so that if a valid session exists, we can add headers from it
	if p.IsAllowedRequest(req) {
		return session, nil
	}

	if session == nil {
		return nil, ErrNeedsLogin
	}

	invalidEmail := session.Email != "" && !p.Validator(session.Email)
	authorized, err := p.provider.Authorize(req.Context(), session)
	if err != nil {
		// logger.Errorf("Error with authorization: %v", err)
	}

	if invalidEmail || !authorized {
		// cause := "unauthorized"
		// if invalidEmail {
		// 	cause = "invalid email"
		// } TODO: check

		// logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authorization via session (%s): removing session %s", cause, session)
		// Invalid session, clear it
		err := p.ClearSessionCookie(rw, req)
		if err != nil {
			// logger.Errorf("Error clearing session cookie: %v", err)
		}
		return nil, ErrAccessDenied
	}

	return session, nil
}

// IsAllowedRequest is used to check if auth should be skipped for this request
func (p *OAuthProxy) IsAllowedRequest(req *http.Request) bool {
	isPreflightRequestAllowed := p.skipAuthPreflight && req.Method == "OPTIONS"
	return isPreflightRequestAllowed
}

// See https://developers.google.com/web/fundamentals/performance/optimizing-content-efficiency/http-caching?hl=en
var noCacheHeaders = map[string]string{
	"Expires":         time.Unix(0, 0).Format(time.RFC1123),
	"Cache-Control":   "no-cache, no-store, must-revalidate, max-age=0",
	"X-Accel-Expires": "0", // https://www.nginx.com/resources/wiki/start/topics/examples/x-accel/
}

// prepareNoCache prepares headers for preventing browser caching.
func prepareNoCache(w http.ResponseWriter) {
	// Set NoCache headers
	for k, v := range noCacheHeaders {
		w.Header().Set(k, v)
	}
}

func prepareNoCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		prepareNoCache(rw)
		next.ServeHTTP(rw, req)
	})
}

// encodedState builds the OAuth state param out of our nonce and
// original application redirect
func encodeState(nonce string, redirect string, encode bool) string {
	rawString := fmt.Sprintf("%v:%v", nonce, redirect)
	if encode {
		return base64.RawURLEncoding.EncodeToString([]byte(rawString))
	}
	return rawString
}

// decodeState splits the reflected OAuth state response back into
// the nonce and original application redirect
func decodeState(state string, encode bool) (string, string, error) {
	toParse := state
	if encode {
		decoded, _ := base64.RawURLEncoding.DecodeString(state)
		toParse = string(decoded)
	}

	parsedState := strings.SplitN(toParse, ":", 2)
	if len(parsedState) != 2 {
		return "", "", errors.New("invalid length")
	}
	return parsedState[0], parsedState[1], nil
}

// SaveSession creates a new session cookie value and sets this on the response
func (p *OAuthProxy) SaveSession(rw http.ResponseWriter, req *http.Request, s *sessionsapi.SessionState) error {
	return p.sessionStore.Save(rw, req, s)
}

// ClearSessionCookie creates a cookie to unset the user's authentication cookie
// stored in the user's session
func (p *OAuthProxy) ClearSessionCookie(rw http.ResponseWriter, req *http.Request) error {
	return p.sessionStore.Clear(rw, req)
}

// addHeadersForProxying adds the appropriate headers the request / response for proxying
func (p *OAuthProxy) addHeadersForProxying(rw http.ResponseWriter, session *sessionsapi.SessionState) {
	if session == nil {
		return
	}
	if session.Email == "" {
		rw.Header().Set("GAP-Auth", session.User)
	} else {
		rw.Header().Set("GAP-Auth", session.Email)
	}
} // TODO: check if this is still needed

func (p *OAuthProxy) redeemCode(req *http.Request, codeVerifier string) (*sessionsapi.SessionState, error) {
	code := req.Form.Get("code")
	if code == "" {
		return nil, providers.ErrMissingCode
	}

	redirectURI := p.getOAuthRedirectURI(req)
	s, err := p.provider.Redeem(req.Context(), redirectURI, code, codeVerifier)
	if err != nil {
		return nil, err
	}

	// Force setting these in case the Provider didn't
	if s.CreatedAt == nil {
		s.CreatedAtNow()
	}
	if s.ExpiresOn == nil {
		s.ExpiresIn(p.CookieOptions.Expire)
	}

	return s, nil
}

func (p *OAuthProxy) enrichSessionState(ctx context.Context, s *sessionsapi.SessionState) error {
	var err error
	if s.Email == "" {
		// TODO: Remove once all provider are updated to implement EnrichSession
		// nolint:static check
		s.Email, err = p.provider.GetEmailAddress(ctx, s)
		if err != nil && !errors.Is(err, providers.ErrNotImplemented) {
			return err
		}
	}

	return p.provider.EnrichSession(ctx, s)
}

// isAjax checks if a request is an ajax request
func isAjax(req *http.Request) bool {
	acceptValues := req.Header.Values("Accept")
	const ajaxReq = applicationJSON
	// Iterate over multiple Accept headers, i.e.
	// Accept: application/json
	// Accept: text/plain
	for _, mimeTypes := range acceptValues {
		// Iterate over multiple mimetypes in a single header, i.e.
		// Accept: application/json, text/plain, */*
		for _, mimeType := range strings.Split(mimeTypes, ",") {
			mimeType = strings.TrimSpace(mimeType)
			if mimeType == ajaxReq {
				return true
			}
		}
	}
	return false
}
