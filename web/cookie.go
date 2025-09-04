package web

import (
	"net/http"
	"net/url"
)

func (c *WebConn) SetCookie(name, value string) error {
	u, err := url.Parse(c.Client.baseURL)
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
	c.Client.jar.SetCookies(u, cookies)
	return nil
}

func (c *WebConn) RemoveCookie(name string) error {
	var updatedCookies []*http.Cookie
	u, err := url.Parse(c.Client.baseURL)
	if err != nil {
		return err
	}

	for _, cookie := range c.Client.jar.Cookies(u) {
		if cookie.Name != name {
			updatedCookies = append(updatedCookies, cookie)
		}
	}
	c.Client.jar.SetCookies(u, updatedCookies)
	return nil
}

func (c *WebConn) GetCookies() []*http.Cookie {
	u, _ := url.Parse(c.Client.baseURL)
	return c.Client.jar.Cookies(u)
}
