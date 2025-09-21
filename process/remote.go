package process

import (
	"bufio"
	"fmt"
	"net"
)

type RemoteConn struct {
	baseTube
	conn net.Conn
	host string
	port int
	ssl  bool
}

type RemoteOptions struct {
	SSL bool
}

func WithSSL(sslOn bool) RemoteOption {
	return func(o *RemoteOptions) {
		o.SSL = sslOn
	}
}

type RemoteOption func(*RemoteOptions)

func getDefaultRemoteOptions() *RemoteOptions {
	return &RemoteOptions{
		SSL: false,
	}
}

func NewRemote(host string, port int, options ...RemoteOption) (*RemoteConn, error) {
	opts := getDefaultRemoteOptions()
	for _, option := range options {
		option(opts)
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	r := &RemoteConn{
		conn: conn,
		host: host,
		port: port,
		ssl:  opts.SSL,
	}

	r.reader = bufio.NewReader(conn)
	r.writer = conn
	r.closer = conn

	Log(LogInfo, "Remote", fmt.Sprintf("Connected to %s", addr))

	return r, nil
}

func RemoteSSL(host string, port int) (*RemoteConn, error) {
	return NewRemote(host, port, WithSSL(true))
}

func (r *RemoteConn) GetPID() int {
	return -1
}

func (r *RemoteConn) Reconnect() (*RemoteConn, error) {
	if r.ssl {
		return NewRemote(r.host, r.port, WithSSL(true))
	}
	return NewRemote(r.host, r.port)
}
