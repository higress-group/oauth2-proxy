package options

import (
	"crypto"
	"net/url"
)

// SignatureData holds hmacauth signature hash and key
type SignatureData struct {
	Hash crypto.Hash
	Key  string
}

// Options holds Configuration Options that can be set by Command Line Flag,
// or Config File
type Options struct {
	ProxyPrefix         string `mapstructure:"proxy_prefix"`
	ReverseProxy        bool   `mapstructure:"reverse_proxy"`
	RawRedirectURL      string `mapstructure:"redirect_url"`
	RelativeRedirectURL bool   `mapstructure:"relative_redirect_url"`

	WhitelistDomains []string `mapstructure:"whitelist_domains"`

	Cookie  Cookie         `mapstructure:",squash"`
	Session SessionOptions `mapstructure:",squash"`
	Service Service        `mapstructure:",squash"`

	Providers Providers

	SkipAuthPreflight bool `mapstructure:"skip_auth_preflight"`
	EncodeState       bool `mapstructure:"encode_state"`
	PassAuthorization bool `mapstructure:"pass_authorization_header"`

	VerifierInterval   int64 `mapstructure:"verifier_interval"`
	UpdateKeysInterval int64 `mapstructure:"update_keys_interval"`
	// internal values that are set after config validation
	redirectURL *url.URL // 私有字段通常不需要 mapstructure 标签
}

// Options for Getting internal values
func (o *Options) GetRedirectURL() *url.URL { return o.redirectURL }

// Options for Setting internal values
func (o *Options) SetRedirectURL(s *url.URL) { o.redirectURL = s }

// NewOptions constructs a new Options with defaulted values
func NewOptions() *Options {
	return &Options{
		ProxyPrefix:        "/oauth2",
		Providers:          providerDefaults(),
		Cookie:             cookieDefaults(),
		Session:            sessionOptionsDefaults(),
		SkipAuthPreflight:  false,
		PassAuthorization:  true,
		VerifierInterval:   24 * 60 * 60 * 1000, // 24h
		UpdateKeysInterval: 15 * 60 * 1000,      // 15m
	}
}
