package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func (c *WebConn) Get(path string, opts ...RequestOption) (*Response, error) {
	return c.Client.Get(path, opts...)
}

func (c *WebConn) Post(path string, data url.Values, opts ...RequestOption) (*Response, error) {
	return c.Client.Post(path, data, opts...)
}

func (c *WebConn) Put(path string, data url.Values, opts ...RequestOption) (*Response, error) {
	return c.Client.Put(path, data, opts...)
}

func (c *WebConn) Patch(path string, data url.Values, opts ...RequestOption) (*Response, error) {
	return c.Client.Patch(path, data, opts...)
}

func (c *WebConn) Delete(path string, opts ...RequestOption) (*Response, error) {
	return c.Client.Delete(path, opts...)
}

func (c *WebConn) Head(path string, opts ...RequestOption) (*Response, error) {
	return c.Client.Head(path, opts...)
}

func (c *WebConn) Options(path string, opts ...RequestOption) (*Response, error) {
	return c.Client.Options(path, opts...)
}

func (c *Client) Get(path string, opts ...RequestOption) (*Response, error) {
	attrs := []any{
		slog.String("url", c.baseURL),
		slog.String("path", path),
	}
	for i, opt := range opts {
		attrs = append(attrs, slog.String(fmt.Sprintf("opt[%d]", i), fmt.Sprint(opt)))
	}
	c.logger.Debug("Making a GET request", attrs...)
	return c.request("GET", path, nil, opts...)
}

func (c *Client) Post(path string, data url.Values, opts ...RequestOption) (*Response, error) {
	c.logger.Info("Making a POST request",
		slog.String("url", c.baseURL),
		slog.String("path", path))
	options := []any{}
	for i, opt := range opts {
		options = append(options, slog.String(fmt.Sprintf("opt[%d]", i), fmt.Sprint(opt)))
	}
	c.logger.Debug("Using the following options", options...)
	if len(c.headers) != 0 {
		c.logHeaders()
	}
	if len(c.GetCookies()) != 0 {
		c.logCookies()
	}
	return c.request("POST", path, data, opts...)
}

func (c *Client) Put(path string, data url.Values, opts ...RequestOption) (*Response, error) {
	c.logger.Info("Making a PUT request",
		slog.String("url", c.baseURL),
		slog.String("path", path))
	return c.request("PUT", path, data, opts...)
}

func (c *Client) Patch(path string, data url.Values, opts ...RequestOption) (*Response, error) {
	c.logger.Info("Making a PATCH request",
		slog.String("url", c.baseURL),
		slog.String("path", path))
	return c.request("PATCH", path, data, opts...)
}

func (c *Client) Delete(path string, opts ...RequestOption) (*Response, error) {
	c.logger.Info("Making a DELETE request",
		slog.String("url", c.baseURL),
		slog.String("path", path))
	return c.request("DELETE", path, nil, opts...)
}

func (c *Client) Head(path string, opts ...RequestOption) (*Response, error) {
	c.logger.Info("Making a HEAD request",
		slog.String("url", c.baseURL),
		slog.String("path", path))
	return c.request("HEAD", path, nil, opts...)
}

func (c *Client) Options(path string, opts ...RequestOption) (*Response, error) {
	c.logger.Info("Making an OPTIONS request",
		slog.String("url", c.baseURL),
		slog.String("path", path))
	return c.request("OPTIONS", path, nil, opts...)
}

func (c *Client) request(method, path string, data interface{}, opts ...RequestOption) (*Response, error) {
	fullURL := c.baseURL + path

	var body io.Reader
	isForm := false
	if data != nil {
		switch v := data.(type) {
		case string:
			body = strings.NewReader(v)
		case []byte:
			body = bytes.NewReader(v)
		case url.Values:
			body = strings.NewReader(v.Encode())
			isForm = true
		}
	}

	u, err := url.Parse(fullURL)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}

	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	for _, opt := range opts {
		if opt != nil {
			opt(req, u)
		}
	}
	req.URL = u

	if isForm && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode:  resp.StatusCode,
		Body:        bodyBytes,
		Headers:     resp.Header,
		Cookies:     c.jar.Cookies(req.URL),
		logger:      c.logger,
		failOnError: c.failOnError,
	}, nil
}

type RequestOption func(req *http.Request, u *url.URL)

func WithParam(key, value string) RequestOption {
	return func(_ *http.Request, u *url.URL) {
		q := u.Query()
		q.Add(key, value)
		u.RawQuery = q.Encode()
	}
}

func WithParams(vals url.Values) RequestOption {
	return func(_ *http.Request, u *url.URL) {
		q := u.Query()
		for k, vs := range vals {
			for _, v := range vs {
				q.Add(k, v)
			}
		}
		u.RawQuery = q.Encode()
	}
}

func WithHeader(key, value string) RequestOption {
	return func(req *http.Request, _ *url.URL) {
		req.Header.Set(key, value)
	}
}

func WithCookie(name, value string) RequestOption {
	return func(req *http.Request, _ *url.URL) {
		cookie := http.Cookie{
			Name:  name,
			Value: value,
		}
		req.AddCookie(&cookie)
	}
}

func WithCookies(cookies map[string]string) RequestOption {
	return func(req *http.Request, _ *url.URL) {
		for name, value := range cookies {
			req.AddCookie(&http.Cookie{Name: name, Value: value})
		}
	}
}

func WithHeaders(headers map[string]string) RequestOption {
	return func(req *http.Request, _ *url.URL) {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
}

func WithContentType(contentType string) RequestOption {
	return func(req *http.Request, _ *url.URL) {
		req.Header.Set("Content-Type", contentType)
	}
}

func WithBasicAuth(username, password string) RequestOption {
	return func(req *http.Request, _ *url.URL) {
		req.SetBasicAuth(username, password)
	}
}

func WithBearer(token string) RequestOption {
	return func(req *http.Request, _ *url.URL) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

type Fields map[string]string

func parseFormArgs(args []any) (url.Values, []RequestOption, error) {
	form := url.Values{}
	var opts []RequestOption
	var pairs []string
	for _, a := range args {
		switch v := a.(type) {
		case Fields:
			for k, val := range v {
				form.Set(k, val)
			}
		case map[string]string:
			for k, val := range v {
				form.Set(k, val)
			}
		case url.Values:
			for k, vals := range v {
				for _, val := range vals {
					form.Add(k, val)
				}
			}
		case RequestOption:
			opts = append(opts, v)
		case string:
			pairs = append(pairs, v)
		default:
			return nil, nil, fmt.Errorf("unsupported PostForm argument type: %T", a)
		}
	}
	if len(pairs)%2 != 0 {
		return nil, nil, fmt.Errorf("PostForm got an odd number of string arguments (%d); expected key/value pairs", len(pairs))
	}
	for i := 0; i < len(pairs); i += 2 {
		form.Set(pairs[i], pairs[i+1])
	}
	return form, opts, nil
}

func (c *WebConn) PostForm(path string, args ...any) (*Response, error) {
	return c.Client.PostForm(path, args...)
}

func (c *Client) PostForm(path string, args ...any) (*Response, error) {
	form, opts, err := parseFormArgs(args)
	if err != nil {
		return nil, err
	}
	return c.Post(path, form, opts...)
}

func LoadFields(path string) Fields {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("pwngears: could not read fields file %q: %v", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		log.Fatalf("pwngears: could not parse fields file %q: %v", path, err)
	}
	f := make(Fields, len(raw))
	for k, v := range raw {
		f[k] = fmt.Sprint(v)
	}
	return f
}

func LoadJSON(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("pwngears: could not read JSON file %q: %v", path, err)
	}
	return data
}

func toJSONBody(v any) ([]byte, error) {
	switch b := v.(type) {
	case []byte:
		return b, nil
	case string:
		return []byte(b), nil
	default:
		return json.Marshal(v)
	}
}

func (c *WebConn) PostJSON(path string, v any, opts ...RequestOption) (*Response, error) {
	return c.Client.PostJSON(path, v, opts...)
}

func (c *Client) PostJSON(path string, v any, opts ...RequestOption) (*Response, error) {
	body, err := toJSONBody(v)
	if err != nil {
		return nil, err
	}
	allOpts := append([]RequestOption{WithContentType("application/json")}, opts...)
	return c.request("POST", path, body, allOpts...)
}
