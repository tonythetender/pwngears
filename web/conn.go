package web

type Connection interface {
	Client() *Client
}
