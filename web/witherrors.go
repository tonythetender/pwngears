package web

import (
	"log"
	"net/url"

	"github.com/tonythetender/pwngears"
)

type WebConnWithErrors struct {
	Conn *WebConn
}

func ConnWithErrors(baseUrl string) (*WebConnWithErrors, error) {
	logger, err := pwngears.NewDefaultLogger("IGNORE")
	if err != nil {
		log.Fatal("error generating the default logger: %v", err)
	}
	conn, err := NewConn(logger, baseUrl)
	if err != nil {
		return nil, err
	}
	connWithErrors := WebConnWithErrors{
		Conn: conn,
	}
	return &connWithErrors, nil
}

func (c *WebConnWithErrors) Get(path string, opts ...RequestOption) (*Response, error) {
	return c.Conn.Get(path, opts...)
}

func (c *WebConnWithErrors) Post(path string, data url.Values, opts ...RequestOption) (*Response, error) {
	return c.Conn.Post(path, data, opts...)
}

func (c *WebConnWithErrors) DisableRedirect() {
	c.Conn.DisableRedirect()
}

func (c *WebConnWithErrors) SetCookie(name, value string) error {
	err := c.Conn.SetCookie(name, value)
	if err != nil {
		return err
	}
	return nil
}

func (c *WebConnWithErrors) Client() *Client {
	return c.Conn.Client
}

func (c *WebConnWithErrors) Session() *Session {
	return c.Conn.Session()
}
