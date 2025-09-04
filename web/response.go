package web

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

type Response struct {
	StatusCode int
	Body       []byte
	Headers    http.Header
	Cookies    []*http.Cookie
}

func (r *Response) Text() string {
	return string(r.Body)
}

func (r *Response) Contains(s string) bool {
	return strings.Contains(r.Text(), s)
}

func (r *Response) GetHeader(key string) string {
	return r.Headers.Get(key)
}

func (r *Response) GetAllHeaders() string {
	var b strings.Builder

	keys := make([]string, 0, len(r.Headers))
	for k := range r.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		values := strings.Join(r.Headers[key], ", ")
		fmt.Fprintf(&b, "%s: %s\n", key, values)
	}

	return b.String()
}
