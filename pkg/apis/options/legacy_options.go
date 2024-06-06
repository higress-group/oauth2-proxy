package options

import (
	"fmt"
)

type LegacyOptions struct {
	// Legacy options for single provider
	LegacyProvider LegacyProvider `mapstructure:",squash"`

	Options Options `mapstructure:",squash"`
}

func NewLegacyOptions() *LegacyOptions {
	return &LegacyOptions{
		LegacyProvider: legacyProviderDefaults(),
		Options:        *NewOptions(),
	}
}

func (l *LegacyOptions) ToOptions() (*Options, error) {

	providers, err := l.LegacyProvider.convert()
	if err != nil {
		return nil, fmt.Errorf("error converting provider: %v", err)
	}
	l.Options.Providers = providers

	return &l.Options, nil
}

type LegacyProvider struct {
	ClientID                           string   `mapstructure:"client_id"`
	ClientSecret                       string   `mapstructure:"client_secret"`
	ClientSecretFile                   string   `mapstructure:"client_secret_file"`
	ProviderType                       string   `mapstructure:"provider"`
	ProviderName                       string   `mapstructure:"provider_display_name"`
	ProviderCAFiles                    []string `mapstructure:"provider_ca_files"`
	UseSystemTrustStore                bool     `mapstructure:"use_system_trust_store"`
	OIDCIssuerURL                      string   `mapstructure:"oidc_issuer_url"`
	InsecureOIDCAllowUnverifiedEmail   bool     `mapstructure:"insecure_oidc_allow_unverified_email"`
	InsecureOIDCSkipIssuerVerification bool     `mapstructure:"insecure_oidc_skip_issuer_verification"`
	InsecureOIDCSkipNonce              bool     `mapstructure:"insecure_oidc_skip_nonce"`
	SkipOIDCDiscovery                  bool     `mapstructure:"skip_oidc_discovery"`
	OIDCJwksURL                        string   `mapstructure:"oidc_jwks_url"`
	OIDCEmailClaim                     string   `mapstructure:"oidc_email_claim"`
	OIDCGroupsClaim                    string   `mapstructure:"oidc_groups_claim"`
	OIDCAudienceClaims                 []string `mapstructure:"oidc_audience_claims"`
	OIDCExtraAudiences                 []string `mapstructure:"oidc_extra_audiences"`
	LoginURL                           string   `mapstructure:"login_url"`
	RedeemURL                          string   `mapstructure:"redeem_url"`
	ProfileURL                         string   `mapstructure:"profile_url"`
	SkipClaimsFromProfileURL           bool     `mapstructure:"skip_claims_from_profile_url"`
	ProtectedResource                  string   `mapstructure:"resource"`
	ValidateURL                        string   `mapstructure:"validate_url"`
	Scope                              string   `mapstructure:"scope"`
	Prompt                             string   `mapstructure:"prompt"`
	ApprovalPrompt                     string   `mapstructure:"approval_prompt"`
	UserIDClaim                        string   `mapstructure:"user_id_claim"`
	AllowedGroups                      []string `mapstructure:"allowed_groups"`
	AllowedRoles                       []string `mapstructure:"allowed_roles"`
	BackendLogoutURL                   string   `mapstructure:"backend_logout_url"`
	AcrValues                          string   `mapstructure:"acr_values"`
	JWTKey                             string   `mapstructure:"jwt_key"`
	JWTKeyFile                         string   `mapstructure:"jwt_key_file"`
	PubJWKURL                          string   `mapstructure:"pubjwk_url"`
	CodeChallengeMethod                string   `mapstructure:"code_challenge_method"`
	ForceCodeChallengeMethod           string   `mapstructure:"force_code_challenge_method"`
}

func legacyProviderDefaults() LegacyProvider {
	return LegacyProvider{
		ClientID:                           "",
		ClientSecret:                       "",
		ClientSecretFile:                   "",
		ProviderType:                       "oidc",
		ProviderName:                       "",
		ProviderCAFiles:                    nil,
		UseSystemTrustStore:                false,
		OIDCIssuerURL:                      "",
		InsecureOIDCAllowUnverifiedEmail:   false,
		InsecureOIDCSkipIssuerVerification: false,
		InsecureOIDCSkipNonce:              true,
		SkipOIDCDiscovery:                  false,
		OIDCJwksURL:                        "",
		OIDCEmailClaim:                     OIDCEmailClaim,
		OIDCGroupsClaim:                    OIDCGroupsClaim,
		OIDCAudienceClaims:                 []string{"aud"},
		OIDCExtraAudiences:                 nil,
		LoginURL:                           "",
		RedeemURL:                          "",
		ProfileURL:                         "",
		SkipClaimsFromProfileURL:           false,
		ProtectedResource:                  "",
		ValidateURL:                        "",
		Scope:                              "",
		Prompt:                             "",
		ApprovalPrompt:                     "force",
		UserIDClaim:                        OIDCEmailClaim,
		AllowedGroups:                      nil,
		AllowedRoles:                       nil,
		BackendLogoutURL:                   "",
		AcrValues:                          "",
		JWTKey:                             "",
		JWTKeyFile:                         "",
		PubJWKURL:                          "",
		CodeChallengeMethod:                "",
		ForceCodeChallengeMethod:           "",
	}
}

func (l *LegacyProvider) convert() (Providers, error) {
	providers := Providers{}

	provider := Provider{
		ClientID:                 l.ClientID,
		ClientSecret:             l.ClientSecret,
		ClientSecretFile:         l.ClientSecretFile,
		Type:                     ProviderType(l.ProviderType),
		CAFiles:                  l.ProviderCAFiles,
		UseSystemTrustStore:      l.UseSystemTrustStore,
		LoginURL:                 l.LoginURL,
		RedeemURL:                l.RedeemURL,
		ProfileURL:               l.ProfileURL,
		SkipClaimsFromProfileURL: l.SkipClaimsFromProfileURL,
		ProtectedResource:        l.ProtectedResource,
		ValidateURL:              l.ValidateURL,
		Scope:                    l.Scope,
		AllowedGroups:            l.AllowedGroups,
		CodeChallengeMethod:      l.CodeChallengeMethod,
		BackendLogoutURL:         l.BackendLogoutURL,
	}

	// This part is out of the switch section for all providers that support OIDC
	provider.OIDCConfig = OIDCOptions{
		IssuerURL:                      l.OIDCIssuerURL,
		InsecureAllowUnverifiedEmail:   l.InsecureOIDCAllowUnverifiedEmail,
		InsecureSkipIssuerVerification: l.InsecureOIDCSkipIssuerVerification,
		InsecureSkipNonce:              l.InsecureOIDCSkipNonce,
		SkipDiscovery:                  l.SkipOIDCDiscovery,
		JwksURL:                        l.OIDCJwksURL,
		UserIDClaim:                    l.UserIDClaim,
		EmailClaim:                     l.OIDCEmailClaim,
		GroupsClaim:                    l.OIDCGroupsClaim,
		AudienceClaims:                 l.OIDCAudienceClaims,
		ExtraAudiences:                 l.OIDCExtraAudiences,
	}

	// Support for legacy configuration option
	if l.ForceCodeChallengeMethod != "" && l.CodeChallengeMethod == "" {
		provider.CodeChallengeMethod = l.ForceCodeChallengeMethod
	}

	if l.ProviderName != "" {
		provider.ID = l.ProviderName
		provider.Name = l.ProviderName
	} else {
		provider.ID = l.ProviderType + "=" + l.ClientID
	}

	// handle AcrValues, Prompt and ApprovalPrompt
	var urlParams []LoginURLParameter
	if l.AcrValues != "" {
		urlParams = append(urlParams, LoginURLParameter{Name: "acr_values", Default: []string{l.AcrValues}})
	}
	switch {
	case l.Prompt != "":
		urlParams = append(urlParams, LoginURLParameter{Name: "prompt", Default: []string{l.Prompt}})
	case l.ApprovalPrompt != "":
		urlParams = append(urlParams, LoginURLParameter{Name: "approval_prompt", Default: []string{l.ApprovalPrompt}})
	default:
		// match legacy behaviour by default - if neither prompt nor approval_prompt
		// specified, use approval_prompt=force
		urlParams = append(urlParams, LoginURLParameter{Name: "approval_prompt", Default: []string{"force"}})
	}

	provider.LoginURLParameters = urlParams

	providers = append(providers, provider)

	return providers, nil
}
