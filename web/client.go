package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"time"
)

type Client struct {
	httpClient *http.Client
	baseURL    string
	headers    map[string]string
	jar        *cookiejar.Jar
	logger     *slog.Logger
}

func NewClient(baseURL string, logger *slog.Logger) (*Client, error) {
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
		logger:  logger,
	}, nil
}

func (c *WebConn) DisableRedirect() {
	c.Client.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
}
