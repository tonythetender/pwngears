package web

import (
	"net/http"
	"net/url"
)

func (c *WebConn) SetCookie(name, value string) error {
	return c.Client.SetCookie(name, value)
}

func (c *WebConn) RemoveCookie(name string) error {
	return c.Client.RemoveCookie(name)
}

func (c *WebConn) GetCookies() []*http.Cookie {
	return c.Client.GetCookies()
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

func (c *Client) RemoveCookie(name string) error {
	var updatedCookies []*http.Cookie
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return err
	}

	for _, cookie := range c.jar.Cookies(u) {
		if cookie.Name != name {
			updatedCookies = append(updatedCookies, cookie)
		}
	}
	c.jar.SetCookies(u, updatedCookies)
	return nil
}

func (c *Client) GetCookies() []*http.Cookie {
	u, _ := url.Parse(c.baseURL)
	return c.jar.Cookies(u)
}
