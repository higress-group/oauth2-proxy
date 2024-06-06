package util

import (
	"net/http"
)

// ResponseRecorder is an implementation of [http.ResponseWriter] that
// records its mutations for later inspection in tests.
type ResponseRecorder struct {
	HeaderMap http.Header
}

// NewRecorder returns an initialized [ResponseRecorder].
func NewRecorder() *ResponseRecorder {
	return &ResponseRecorder{
		HeaderMap: make(http.Header),
	}
}

func (rw *ResponseRecorder) Header() http.Header {
	m := rw.HeaderMap
	if m == nil {
		m = make(http.Header)
		rw.HeaderMap = m
	}
	return m
}

func (rw *ResponseRecorder) Write(buf []byte) (int, error) {
	return len(buf), nil
}

// WriteHeader implements [http.ResponseWriter].
func (rw *ResponseRecorder) WriteHeader(code int) {

}
