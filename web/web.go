package web

import (
	"fmt"
	"net/url"
	"time"

	"pwngears/bruteforce"
)

type WebConn struct {
	Client      *Client
	Bruteforcer *bruteforce.Bruteforcer
	BaseURL     string
}

func Conn(baseURL string) (*WebConn, error) {
	c, err := NewClient(baseURL)
	if err != nil {
		return nil, err
	}

	return &WebConn{
		Client:      c,
		Bruteforcer: bruteforce.NewBruteforcer(),
		BaseURL:     baseURL,
	}, nil
}

func NewForm() url.Values {
	return url.Values{}
}

func (c *WebConn) Session() *Session {
	return &Session{
		ctf:     c,
		cookies: make(map[string]string),
		data:    make(map[string]interface{}),
	}
}

type Session struct {
	ctf     *WebConn
	cookies map[string]string
	data    map[string]interface{}
}

func (s *Session) Client() *Client {
	return s.ctf.Client
}

func (s *Session) SaveCookies() {
	for _, cookie := range s.ctf.Client.GetCookies() {
		s.cookies[cookie.Name] = cookie.Value
	}
}

func (s *Session) RestoreCookies() {
	for name, value := range s.cookies {
		s.ctf.Client.SetCookie(name, value)
	}
}

func (s *Session) Store(key string, value interface{}) {
	s.data[key] = value
}

func (s *Session) Get(key string) interface{} {
	return s.data[key]
}

func (s *Session) ChainRequests(requests ...RequestFunc) error {
	for i, req := range requests {
		fmt.Printf("[*] Executing request %d/%d\n", i+1, len(requests))
		if err := req(s); err != nil {
			return err
		}
		s.SaveCookies()
		time.Sleep(500 * time.Millisecond)
	}
	return nil
}

type RequestFunc func(*Session) error
