package providers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"oidc/pkg/apis/options"
	"oidc/pkg/apis/sessions"
	"oidc/pkg/util"

	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
)

// OIDCProvider represents an OIDC based Identity Provider
type OIDCProvider struct {
	*ProviderData

	SkipNonce bool
}

const oidcDefaultScope = "openid email profile"

// NewOIDCProvider initiates a new OIDCProvider
func NewOIDCProvider(p *ProviderData, opts options.OIDCOptions) *OIDCProvider {
	name := "OpenID Connect"

	if p.ProviderName != "" {
		name = p.ProviderName
	}

	oidcProviderDefaults := providerDefaults{
		name:        name,
		loginURL:    nil,
		redeemURL:   nil,
		profileURL:  nil,
		validateURL: nil,
		scope:       oidcDefaultScope,
	}

	if len(p.AllowedGroups) > 0 {
		oidcProviderDefaults.scope += " groups"
	}

	p.setProviderDefaults(oidcProviderDefaults)
	p.getAuthorizationHeaderFunc = makeOIDCHeader

	return &OIDCProvider{
		ProviderData: p,
		SkipNonce:    opts.InsecureSkipNonce,
	}
}

var _ Provider = (*OIDCProvider)(nil)

// GetLoginURL makes the LoginURL with optional nonce support
func (p *OIDCProvider) GetLoginURL(redirectURI, state, nonce string, extraParams url.Values) string {
	if !p.SkipNonce {
		extraParams.Add("nonce", nonce)
	}
	loginURL := makeLoginURL(p.Data(), redirectURI, state, extraParams)
	return loginURL.String()
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *OIDCProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string, client wrapper.HttpClient, callback func(sesssion *sessions.SessionState)) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}
	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if codeVerifier != "" {
		params.Add("code_verifier", codeVerifier)
	}

	req, err := http.NewRequest("POST", p.RedeemURL.String(), strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var headerArray [][2]string
	for key, values := range req.Header {
		if len(values) > 0 {
			headerArray = append(headerArray, [2]string{key, values[0]})
		}
	}
	bodyBytes, err := io.ReadAll(req.Body)
	req.Body.Close()

	client.Post(p.RedeemURL.String(), headerArray, bodyBytes, func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		token, err := util.UnmarshalToken(responseHeaders, responseBody)
		if err != nil {
			return
		}
		session, err := p.createSession(ctx, token, false)
		if err != nil {
			util.Logger.Error(err.Error())
		}
		callback(session)
	}, 2000)

	return nil
}

// EnrichSession is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
func (p *OIDCProvider) EnrichSession(_ context.Context, s *sessions.SessionState) error {
	// If a mandatory email wasn't set, error at this point.
	if s.Email == "" {
		return errors.New("neither the id_token nor the profileURL set an email")
	}
	return nil
}

// ValidateSession checks that the session's IDToken is still valid
func (p *OIDCProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	_, err := p.Verifier.Verify(ctx, s.IDToken)
	if err != nil {
		util.Logger.Errorf("id_token verification failed: %v", err)
		return false
	}
	if p.SkipNonce {
		return true
	}
	err = p.checkNonce(s)
	if err != nil {
		util.Logger.Errorf("nonce verification failed: %v", err)
		return false
	}
	return true
}

// RefreshSession uses the RefreshToken to fetch new Access and ID Tokens
func (p *OIDCProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}

	// err := p.redeemRefreshToken(ctx, s)
	// if err != nil {
	// 	return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	// }

	return true, nil
}

// redeemRefreshToken uses a RefreshToken with the RedeemURL to refresh the
// Access Token and (probably) the ID Token.
// func (p *OIDCProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) error {
// 	clientSecret, err := p.GetClientSecret()
// 	if err != nil {
// 		return err
// 	}

// 	c := oauth2.Config{
// 		ClientID:     p.ClientID,
// 		ClientSecret: clientSecret,
// 		Endpoint: oauth2.Endpoint{
// 			TokenURL: p.RedeemURL.String(),
// 		},
// 	}
// 	t := &oauth2.Token{
// 		RefreshToken: s.RefreshToken,
// 		Expiry:       time.Now().Add(-time.Hour),
// 	}
// 	token, err := c.TokenSource(ctx, t).Token()
// 	if err != nil {
// 		return fmt.Errorf("failed to get token: %v", err)
// 	}

// 	newSession, err := p.createSession(ctx, token, true)
// 	if err != nil {
// 		return fmt.Errorf("unable create new session state from response: %v", err)
// 	}

// 	// It's possible that if the refresh token isn't in the token response the
// 	// session will not contain an id token.
// 	// If it doesn't it's probably better to retain the old one
// 	if newSession.IDToken != "" {
// 		s.IDToken = newSession.IDToken
// 		s.Email = newSession.Email
// 		s.User = newSession.User
// 		s.Groups = newSession.Groups
// 		s.PreferredUsername = newSession.PreferredUsername
// 	}

// 	s.AccessToken = newSession.AccessToken
// 	s.RefreshToken = newSession.RefreshToken
// 	s.CreatedAt = newSession.CreatedAt
// 	s.ExpiresOn = newSession.ExpiresOn

// 	return nil
// }

// CreateSessionFromToken converts Bearer IDTokens into sessions
func (p *OIDCProvider) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	idToken, err := p.Verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	ss, err := p.buildSessionFromClaims(token, "")
	if err != nil {
		return nil, err
	}

	// Allow empty Email in Bearer case since we can't hit the ProfileURL
	if ss.Email == "" {
		ss.Email = ss.User
	}

	ss.AccessToken = token
	ss.IDToken = token
	ss.RefreshToken = ""

	ss.CreatedAtNow()
	ss.SetExpiresOn(idToken.Expiry)

	return ss, nil
}

// createSession takes an oauth2.Token and creates a SessionState from it.
// It alters behavior if called from Redeem vs Refresh
func (p *OIDCProvider) createSession(ctx context.Context, token *util.Token, refresh bool) (*sessions.SessionState, error) {
	_, err := p.verifyIDToken(ctx, token)
	if err != nil {
		switch err {
		case ErrMissingIDToken:
			// IDToken is mandatory in Redeem but optional in Refresh
			if !refresh {
				return nil, errors.New("token response did not contain an id_token")
			}
		default:
			return nil, fmt.Errorf("could not verify id_token: %v", err)
		}
	}

	rawIDToken := getIDToken(token)
	ss, err := p.buildSessionFromClaims(rawIDToken, token.AccessToken)
	if err != nil {
		return nil, err
	}

	ss.AccessToken = token.AccessToken
	ss.RefreshToken = token.RefreshToken
	ss.IDToken = rawIDToken

	ss.CreatedAtNow()
	ss.SetExpiresOn(token.Expiry)

	return ss, nil
}
