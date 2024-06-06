package main

import (
	"net/http"
	"net/url"
	"oidc/pkg/apis/options"
	"oidc/pkg/util"
	"oidc/pkg/validation"
	"strings"

	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
)

// MyResponseWriter 是一个自定义的 ResponseWriter
// 它嵌入 http.ResponseWriter 接口，并且可以增加其他成员
type MyResponseWriter struct {
	http.ResponseWriter
	StatusCode int // 用于记录状态码
}

func main() {
	wrapper.SetCtx(
		// 插件名称
		"oidc",
		// 为解析插件配置，设置自定义函数
		wrapper.ParseConfigBy(parseConfig),
		// 为处理请求头，设置自定义函数
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

type OidcConfig struct {
	Options     *options.Options
	OidcHandler *OAuthProxy
	Client      wrapper.HttpClient
}

// 在控制台插件配置中填写的yaml配置会自动转换为json，此处直接从json这个参数里解析配置即可
func parseConfig(json gjson.Result, config *OidcConfig, log wrapper.Log) error {
	opts, err := options.LoadOptions(json)
	if err != nil {
		return err
	}

	if err = validation.Validate(opts); err != nil {
		return err
	}

	config.Options = opts
	validator := func(string) bool { return true }
	oauthproxy, err := NewOAuthProxy(opts, validator, &log)
	if err != nil {
		return err
	}
	config.OidcHandler = oauthproxy
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config OidcConfig, log wrapper.Log) types.Action {
	log.Debugf("otps service: %v", config.Options.Service)
	headers, _ := proxywasm.GetHttpRequestHeaders()

	var method, path string
	for _, header := range headers {
		switch header[0] {
		case ":method":
			method = header[1]
		case ":path":
			path = header[1]
		}
	}
	parsedURL, _ := url.Parse(path)

	req := &http.Request{
		Method: method,
		URL:    parsedURL,
		Header: make(http.Header),
		Body:   nil,
	}

	for _, header := range headers {
		if !strings.HasPrefix(header[0], ":") {
			req.Header.Add(header[0], header[1])
		}
	}
	rw := util.NewRecorder()
	config.OidcHandler.serveMux.ServeHTTP(rw, req)
	return types.ActionContinue
}
