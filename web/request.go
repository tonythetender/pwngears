package web

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

func (c *WebConn) Get(path string, opts ...RequestOption) (*Response, error) {
	attrs := []any{
		slog.String("url", c.Client.baseURL),
		slog.String("path", path),
	}
	for i, opt := range opts {
		attrs = append(attrs, slog.String(fmt.Sprintf("opt[%d]", i), fmt.Sprint(opt)))
	}
	c.logger.Debug("Making a GET request", attrs)
	return c.Client.request("GET", path, nil, opts...)
}

func (c *WebConn) Post(path string, data url.Values, opts ...RequestOption) (*Response, error) {
	c.logger.Info("Making a GET request",
		slog.String("url", c.Client.baseURL),
		slog.String("path", path))
	options := []slog.Attr{}
	for i, opt := range opts {
		options = append(options, slog.String(fmt.Sprintf("opt[%d]", i), fmt.Sprint(opt)))
	}
	c.logger.Debug("Using the following options",
		options)
	if len(c.Client.headers) != 0 {
		c.logHeaders()
	}
	if len(c.GetCookies()) != 0 {
		c.logCookies()
	}
	return c.Client.request("POST", path, data, opts...)
}

func (c *Client) request(method, path string, data interface{}, opts ...RequestOption) (*Response, error) {
	fullURL := c.baseURL + path

	var body io.Reader
	if data != nil {
		switch v := data.(type) {
		case string:
			body = strings.NewReader(v)
		case []byte:
			body = bytes.NewReader(v)
		case url.Values:
			body = strings.NewReader(v.Encode())
			if c.headers["Content-Type"] == "" {
				if c.headers == nil {
					c.headers = make(map[string]string)
				}
				c.headers["Content-Type"] = "application/x-www-form-urlencoded"
			}
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
		StatusCode: resp.StatusCode,
		Body:       bodyBytes,
		Headers:    resp.Header,
		Cookies:    c.jar.Cookies(req.URL),
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
