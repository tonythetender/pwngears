package process

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"
)

type RemoteConn struct {
	baseTube
	conn       net.Conn
	host       string
	port       int
	ssl        bool
	sni        string
	verifyCert bool
}

type RemoteOptions struct {
	SSL        bool
	SNI        string
	VerifyCert bool
}

func WithSSL(sslOn bool) RemoteOption {
	return func(o *RemoteOptions) {
		o.SSL = sslOn
	}
}

func SSL() RemoteOption {
	return WithSSL(true)
}

func WithSNI(serverName string) RemoteOption {
	return func(o *RemoteOptions) {
		o.SNI = serverName
	}
}

func WithVerifyCert(verify bool) RemoteOption {
	return func(o *RemoteOptions) {
		o.VerifyCert = verify
	}
}

type RemoteOption func(*RemoteOptions)

func getDefaultRemoteOptions() *RemoteOptions {
	return &RemoteOptions{
		SSL:        false,
		SNI:        "",
		VerifyCert: false,
	}
}

func NewRemote(host string, port int, options ...RemoteOption) (*RemoteConn, error) {
	opts := getDefaultRemoteOptions()
	for _, option := range options {
		option(opts)
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	var conn net.Conn
	var err error
	if opts.SSL {
		sni := opts.SNI
		if sni == "" {
			sni = host
		}
		conn, err = tls.Dial("tcp", addr, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: !opts.VerifyCert,
		})
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return nil, err
	}

	r := &RemoteConn{
		conn:       conn,
		host:       host,
		port:       port,
		ssl:        opts.SSL,
		sni:        opts.SNI,
		verifyCert: opts.VerifyCert,
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

// SetReadDeadline bounds how long a subsequent read may block. A zero time
// clears the deadline. After the deadline passes, reads fail with a timeout
// error, which higher-level loops treat as end-of-stream.
func (r *RemoteConn) SetReadDeadline(t time.Time) error {
	if r.conn == nil {
		return nil
	}
	return r.conn.SetReadDeadline(t)
}

func (r *RemoteConn) Reconnect() (*RemoteConn, error) {
	return NewRemote(r.host, r.port,
		WithSSL(r.ssl),
		WithSNI(r.sni),
		WithVerifyCert(r.verifyCert),
	)
}
