package web

func (c *WebConn) SetHeader(key, value string) {
	c.Client.headers[key] = value
}

func (c *WebConn) RemoveHeader(key string) {
	delete(c.Client.headers, key)
}
