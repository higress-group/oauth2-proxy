package util

import (
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
)

var Logger *wrapper.Log

func SendError(errMsg string, status int) {
	Logger.Errorf(errMsg)
	proxywasm.SendHttpResponse(uint32(status), nil, []byte(errMsg), -1)
}
