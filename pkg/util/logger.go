package util

import (
	"net/http"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	logs "github.com/higress-group/wasm-go/pkg/log"
)

var Logger logs.Log

func SendError(errMsg string, rw http.ResponseWriter, status int) {
	Logger.Errorf(errMsg)
	if rw != nil {
		rw.WriteHeader(status)
	}
	proxywasm.SendHttpResponseWithDetail(uint32(status), errMsg, nil, []byte(http.StatusText(status)), -1)
}
