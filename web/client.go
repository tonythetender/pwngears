package web

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Client struct {
	httpClient *http.Client
	baseURL    string
	headers    map[string]string
	jar        *cookiejar.Jar
}

func NewClient(baseURL string) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Jar:     jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		baseURL: baseURL,
		headers: make(map[string]string),
		jar:     jar,
	}, nil
}

func (c *Client) SetHeader(key, value string) {
	c.headers[key] = value
}

func (c *Client) SetCookie(name, value string) error {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return err
	}

	cookies := []*http.Cookie{
		{
			Name:   name,
			Value:  value,
			Domain: u.Host,
			Path:   "/",
		},
	}
	c.jar.SetCookies(u, cookies)
	return nil
}

func (c *Client) GetCookies() []*http.Cookie {
	u, _ := url.Parse(c.baseURL)
	return c.jar.Cookies(u)
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

func (c *Client) Get(path string, opts ...RequestOption) (*Response, error) {
	return c.request("GET", path, nil, opts...)
}

func (c *Client) Post(path string, data interface{}, opts ...RequestOption) (*Response, error) {
	return c.request("POST", path, data, opts...)
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

func (c *Client) DisableRedirect() {
	c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
}

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
