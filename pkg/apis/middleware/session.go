package middleware

import (
	"context"
	"fmt"

	sessionsapi "github.com/higress-group/oauth2-proxy/pkg/apis/sessions"

	oidc "github.com/higress-group/oauth2-proxy/pkg/providers/go_oidc"
)

// TokenToSessionFunc takes a raw ID Token and converts it into a SessionState.
type TokenToSessionFunc func(ctx context.Context, token string) (*sessionsapi.SessionState, error)

// VerifyFunc takes a raw bearer token and verifies it returning the converted
// oidc.IDToken representation of the token.
type VerifyFunc func(ctx context.Context, token string) (*oidc.IDToken, error)

// CreateTokenToSessionFunc provides a handler that is a default implementation
// for converting a JWT into a session.
func CreateTokenToSessionFunc(verify VerifyFunc) TokenToSessionFunc {
	return func(ctx context.Context, token string) (*sessionsapi.SessionState, error) {
		var claims struct {
			Subject           string   `json:"sub"`
			Email             string   `json:"email"`
			Verified          *bool    `json:"email_verified"`
			PreferredUsername string   `json:"preferred_username"`
			Groups            []string `json:"groups"`
		}

		idToken, err := verify(ctx, token)
		if err != nil {
			return nil, err
		}

		if err := idToken.Claims(&claims); err != nil {
			return nil, fmt.Errorf("failed to parse bearer token claims: %v", err)
		}

		if claims.Email == "" {
			claims.Email = claims.Subject
		}

		if claims.Verified != nil && !*claims.Verified {
			return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
		}

		newSession := &sessionsapi.SessionState{
			Email:             claims.Email,
			User:              claims.Subject,
			Groups:            claims.Groups,
			PreferredUsername: claims.PreferredUsername,
			AccessToken:       token,
			IDToken:           token,
			RefreshToken:      "",
			ExpiresOn:         &idToken.Expiry,
		}

		return newSession, nil
	}
}
