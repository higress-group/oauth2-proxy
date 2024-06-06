package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// StaticKeySet is a verifier that validates JWT against a static set of public keys.
type StaticKeySet struct {
	// PublicKeys used to verify the JWT. Supported types are *rsa.PublicKey and
	// *ecdsa.PublicKey.
	PublicKeys []crypto.PublicKey
}

// VerifySignature compares the signature against a static set of public keys.
func (s *StaticKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	// Algorithms are already checked by Verifier, so this parse method accepts
	// any algorithm.
	jws, err := jose.ParseSigned(jwt, allAlgs)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt: %v", err)
	}
	for _, pub := range s.PublicKeys {
		switch pub.(type) {
		case *rsa.PublicKey:
		case *ecdsa.PublicKey:
		case ed25519.PublicKey:
		default:
			return nil, fmt.Errorf("invalid public key type provided: %T", pub)
		}
		payload, err := jws.Verify(pub)
		if err != nil {
			continue
		}
		return payload, nil
	}
	return nil, fmt.Errorf("no public keys able to verify jwt")
}

// NewRemoteKeySet returns a KeySet that can validate JSON web tokens by using HTTP
// GETs to fetch JSON web token sets hosted at a remote URL. This is automatically
// used by NewProvider using the URLs returned by OpenID Connect discovery, but is
// exposed for providers that don't support discovery or to prevent round trips to the
// discovery URL.
//
// The returned KeySet is a long lived verifier that caches keys based on any
// keys change. Reuse a common remote key set instead of creating new ones as needed.
func NewRemoteKeySet(ctx context.Context, jwksURL string) *RemoteKeySet {
	return newRemoteKeySet(ctx, jwksURL, time.Now)
}

func newRemoteKeySet(ctx context.Context, jwksURL string, now func() time.Time) *RemoteKeySet {
	if now == nil {
		now = time.Now
	}
	return &RemoteKeySet{jwksURL: jwksURL, ctx: ctx, now: now}
}

// RemoteKeySet is a KeySet implementation that validates JSON web tokens against
// a jwks_uri endpoint.
type RemoteKeySet struct {
	jwksURL string
	ctx     context.Context
	now     func() time.Time

	// guard all other fields
	mu sync.RWMutex

	// A set of cached keys.
	cachedKeys []jose.JSONWebKey
}

// inflight is used to wait on some in-flight request from multiple goroutines.
type inflight struct {
	doneCh chan struct{}

	keys []jose.JSONWebKey
	err  error
}

// paresdJWTKey is a context key that allows common setups to avoid parsing the
// JWT twice. It holds a *jose.JSONWebSignature value.
var parsedJWTKey int

// VerifySignature validates a payload against a signature from the jwks_uri.
//
// Users MUST NOT call this method directly and should use an IDTokenVerifier
// instead. This method skips critical validations such as 'alg' values and is
// only exported to implement the KeySet interface.
func (r *RemoteKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, ok := ctx.Value(parsedJWTKey).(*jose.JSONWebSignature)
	if !ok {
		// The algorithm values are already enforced by the Validator, which also sets
		// the context value above to pre-parsed signature.
		//
		// Practically, this codepath isn't called in normal use of this package, but
		// if it is, the algorithms have already been checked.
		var err error
		jws, err = jose.ParseSigned(jwt, allAlgs)
		if err != nil {
			return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
		}
	}
	return r.verify(ctx, jws)
}

func (r *RemoteKeySet) verify(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	// We don't support JWTs signed with multiple signatures.
	keyID := ""
	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID
		break
	}

	keys := r.keysFromCache()
	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			if payload, err := jws.Verify(&key); err == nil {
				return payload, nil
			}
		}
	}

	// If the kid doesn't match, check for new keys from the remote. This is the
	// strategy recommended by the spec.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
	// keys, err := r.keysFromRemote()
	// if err != nil {
	// 	return nil, fmt.Errorf("fetching keys %w", err)
	// }

	// for _, key := range keys {
	// 	if keyID == "" || key.KeyID == keyID {
	// 		if payload, err := jws.Verify(&key); err == nil {
	// 			return payload, nil
	// 		}
	// 	}
	// }
	return nil, errors.New("failed to verify id token signature")
}

func (r *RemoteKeySet) keysFromCache() (keys []jose.JSONWebKey) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cachedKeys
}

// keysFromRemote syncs the key set from the remote set, records the values in the
// cache, and returns the key set.
// func (r *RemoteKeySet) keysFromRemote() ([]jose.JSONWebKey, error) {
// 	r.mu.Lock()
// 	defer r.mu.Unlock()
// 	// Sync keys and finish inflight when that's done.
// 	keys, err := r.updateKeys()
// 	if err == nil {
// 		r.cachedKeys = keys
// 	}
// 	return keys, nil
// }

// func (r *RemoteKeySet) updateKeys() ([]jose.JSONWebKey, error) {
// 	req, err := http.NewRequest("GET", r.jwksURL, nil)
// 	if err != nil {
// 		return nil, fmt.Errorf("oidc: can't create request: %v", err)
// 	}

// 	resp, err := doRequest(r.ctx, req)
// 	if err != nil {
// 		return nil, fmt.Errorf("oidc: get keys failed %w", err)
// 	}
// 	defer resp.Body.Close()

// 	body, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		return nil, fmt.Errorf("unable to read response body: %v", err)
// 	}

// 	if resp.StatusCode != http.StatusOK {
// 		return nil, fmt.Errorf("oidc: get keys failed: %s %s", resp.Status, body)
// 	}

// 	var keySet jose.JSONWebKeySet
// 	err = unmarshalResp(resp, body, &keySet)
// 	if err != nil {
// 		return nil, fmt.Errorf("oidc: failed to decode keys: %v %s", err, body)
// 	}
// 	return keySet.Keys, nil
// }
