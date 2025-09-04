package web

func (c *WebConn) SetHeader(key, value string) {
	c.Client.SetHeader(key, value)
}

func (c *WebConn) RemoveHeader(key string) {
	c.Client.RemoveHeader(key)
}

func (c *Client) SetHeader(key, value string) {
	c.headers[key] = value
}

func (c *Client) RemoveHeader(key string) {
	delete(c.headers, key)
}
