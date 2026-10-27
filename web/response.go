package web

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

type Response struct {
	StatusCode int
	Body       []byte
	Headers    http.Header
	Cookies    []*http.Cookie

	logger      *slog.Logger
	failOnError bool
}

func (r *Response) failf(msg string, args ...any) {
	if r.logger != nil {
		r.logger.Error(msg, args...)
	}
	if r.failOnError {
		os.Exit(1)
	}
}

func (r *Response) Match(pattern string) string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		r.failf("invalid regex pattern",
			slog.String("pattern", pattern),
			slog.String("error", err.Error()))
		return ""
	}
	m := re.FindStringSubmatch(r.Text())
	if m == nil {
		r.failf("no match for pattern", slog.String("pattern", pattern))
		return ""
	}
	if len(m) > 1 {
		return m[1]
	}
	return m[0]
}

func (r *Response) MatchAll(pattern string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		r.failf("invalid regex pattern",
			slog.String("pattern", pattern),
			slog.String("error", err.Error()))
		return nil
	}
	matches := re.FindAllStringSubmatch(r.Text(), -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) > 1 {
			out = append(out, m[1])
		} else {
			out = append(out, m[0])
		}
	}
	return out
}

func (r *Response) Flag(prefix string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(prefix) + `\{[^}]*\}`)
	m := re.FindString(r.Text())
	if m == "" {
		r.failf("no flag found", slog.String("prefix", prefix))
		return ""
	}
	return m
}

func (r *Response) JSON(v any) {
	if err := json.Unmarshal(r.Body, v); err != nil {
		r.failf("could not parse response JSON", slog.String("error", err.Error()))
	}
}

func (r *Response) OK() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

func (r *Response) Is(code int) bool {
	return r.StatusCode == code
}

func (r *Response) Location() string {
	return r.Headers.Get("Location")
}

func (r *Response) Cookie(name string) string {
	for _, c := range r.Cookies {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func (r *Response) Text() string {
	return string(r.Body)
}

func (r *Response) Lines() []string {
	return strings.Split(string(r.Body), "\n")
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
