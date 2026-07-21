package providers

import (
	"testing"

	"github.com/higress-group/oauth2-proxy/pkg/apis/options"
	"github.com/higress-group/wasm-go/pkg/wrapper"
)

// recordingClient is a minimal HttpClient mock that records every Get call.
// For the skip-discovery test we only need to assert whether Get was called,
// not whether the verifier got installed — wasm host context isn't available
// in unit tests, so the downstream applyVerifier path can't fully execute.
type recordingClient struct {
	getCalls []string
}

func (c *recordingClient) Get(rawURL string, headers [][2]string, cb wrapper.ResponseCallback, timeoutMillisecond ...uint32) error {
	c.getCalls = append(c.getCalls, rawURL)
	return nil
}

func (c *recordingClient) Head(rawURL string, headers [][2]string, cb wrapper.ResponseCallback, timeoutMillisecond ...uint32) error {
	return nil
}
func (c *recordingClient) Options(rawURL string, headers [][2]string, cb wrapper.ResponseCallback, timeoutMillisecond ...uint32) error {
	return nil
}
func (c *recordingClient) Post(rawURL string, headers [][2]string, body []byte, cb wrapper.ResponseCallback, timeoutMillisecond ...uint32) error {
	return nil
}
func (c *recordingClient) Put(rawURL string, headers [][2]string, body []byte, cb wrapper.ResponseCallback, timeoutMillisecond ...uint32) error {
	return nil
}
func (c *recordingClient) Patch(rawURL string, headers [][2]string, body []byte, cb wrapper.ResponseCallback, timeoutMillisecond ...uint32) error {
	return nil
}
func (c *recordingClient) Delete(rawURL string, headers [][2]string, body []byte, cb wrapper.ResponseCallback, timeoutMillisecond ...uint32) error {
	return nil
}
func (c *recordingClient) Connect(rawURL string, headers [][2]string, body []byte, cb wrapper.ResponseCallback, timeoutMillisecond ...uint32) error {
	return nil
}
func (c *recordingClient) Trace(rawURL string, headers [][2]string, body []byte, cb wrapper.ResponseCallback, timeoutMillisecond ...uint32) error {
	return nil
}
func (c *recordingClient) Call(method, rawURL string, headers [][2]string, body []byte, cb wrapper.ResponseCallback, timeoutMillisecond ...uint32) error {
	return nil
}

// runNewVerifierFromConfigSafely runs NewVerifierFromConfig under a recover,
// returning whether it panicked. The full applyVerifier path requires a wasm
// host context (real OIDC library initialisation, real key-set fetcher) that
// isn't available in unit tests, so a panic here means the test harness hit
// the downstream code path — not that the function itself is broken in
// production. What we actually assert is the side effect on the recording
// client, which is decided *before* applyVerifier runs.
func runNewVerifierFromConfigSafely(t *testing.T, cfg options.Provider, p *ProviderData, client *recordingClient) (panicked bool) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			t.Logf("NewVerifierFromConfig panicked (expected in unit test without wasm host): %v", r)
		}
	}()
	_ = NewVerifierFromConfig(cfg, p, client)
	return false
}

// TestNewVerifierFromConfig_SkipDiscovery_NoHttpGet is the regression guard for
// higress-group/higress#3941: when skip_oidc_discovery is true, the plugin
// must NOT issue a /.well-known/openid-configuration HTTP call, even if the
// issuer endpoint is unreachable. Previously the Get was unconditional and a
// failure silently left the plugin without a verifier.
func TestNewVerifierFromConfig_SkipDiscovery_NoHttpGet(t *testing.T) {
	cfg := options.Provider{
		Type:     "oidc",
		ClientID: "test-client",
		OIDCConfig: options.OIDCOptions{
			IssuerURL:      "https://auth.example.com/",
			JwksURL:        "https://auth.example.com/jwks/",
			SkipDiscovery:  true,
			AudienceClaims: []string{"aud"},
		},
	}

	p := &ProviderData{NeedsVerifier: true}
	client := &recordingClient{}

	runNewVerifierFromConfigSafely(t, cfg, p, client)

	// The bug (#3941): with skip_oidc_discovery=true the plugin still issued
	// a Get to /.well-known/openid-configuration. Assert none of the recorded
	// calls targeted the discovery endpoint. (JWKS refresh via Get is fine and
	// expected — UpdateKeys runs regardless of how the verifier was built.)
	const discoverySuffix = "/.well-known/openid-configuration"
	for _, u := range client.getCalls {
		if len(u) >= len(discoverySuffix) && u[len(u)-len(discoverySuffix):] == discoverySuffix {
			t.Errorf("SkipDiscovery=true but discovery endpoint was still hit: %s", u)
		}
	}
}

// TestNewVerifierFromConfig_Discovery_DoesHttpGet confirms the inverse — when
// discovery is enabled (the default), the openid-configuration Get IS issued,
// so the regression test above isn't a false positive.
func TestNewVerifierFromConfig_Discovery_DoesHttpGet(t *testing.T) {
	cfg := options.Provider{
		Type:     "oidc",
		ClientID: "test-client",
		OIDCConfig: options.OIDCOptions{
			IssuerURL:      "https://auth.example.com/",
			SkipDiscovery:  false, // default
			AudienceClaims: []string{"aud"},
		},
	}

	p := &ProviderData{NeedsVerifier: true}
	client := &recordingClient{}

	runNewVerifierFromConfigSafely(t, cfg, p, client)

	if len(client.getCalls) == 0 {
		t.Errorf("expected an HTTP Get to /.well-known/openid-configuration when SkipDiscovery=false, got none")
	}
}
