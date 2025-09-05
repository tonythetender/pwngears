package web

import (
	"fmt"
	"log"
	"log/slog"
	"net/url"
	"strings"

	"github.com/tonythetender/pwngears"
)

type WebConnWithLogger struct {
	Conn        *WebConn
	failOnError bool
}

func (c *WebConnWithLogger) logAndFatal(msg string, args ...any) {
	c.Conn.logger.Error(msg, args...)
	if c.failOnError {
		log.Fatal()
	}
}

func Conn(baseUrl string) *WebConnWithLogger {
	logger, err := pwngears.NewDefaultLogger("INFO")
	if err != nil {
		log.Fatalf("error generating the default logger: %v", err)
	}
	return ConnWithLogger(baseUrl, logger)
}

func ConnWithLogger(baseUrl string, logger *slog.Logger) *WebConnWithLogger {
	conn, err := NewConn(logger, baseUrl)
	if err != nil {
		logger.Error("Could not establish connection to the given URL",
			slog.String("error", err.Error()),
			slog.String("url", baseUrl))
	}
	connWithLogger := WebConnWithLogger{
		Conn:        conn,
		failOnError: true,
	}
	return &connWithLogger
}

func (c *WebConnWithLogger) SetFailOnError(fail bool) {
	c.failOnError = fail
}

func (c *WebConnWithLogger) SetLogLevel(logLevel string) {
	switch logLevel {
	case "DEBUG", "debug":
		pwngears.LogLevel.Set(slog.LevelDebug)
	case "INFO", "info":
		pwngears.LogLevel.Set(slog.LevelInfo)
	case "WARN", "warn":
		pwngears.LogLevel.Set(slog.LevelWarn)
	case "ERROR", "error":
		pwngears.LogLevel.Set(slog.LevelError)
	case "IGNORE", "ignore":
		pwngears.LogLevel.Set(12)
	}
}

func (c *WebConnWithLogger) Get(path string, opts ...RequestOption) *Response {
	resp, err := c.Conn.Get(path, opts...)
	if err != nil {
		c.logAndFatal("Error during GET request",
			slog.String("error", err.Error()),
			slog.String("base-url", c.Conn.BaseURL),
			slog.String("path", path))
	}
	return resp
}

func (c *WebConnWithLogger) Post(path string, data url.Values, opts ...RequestOption) *Response {
	resp, err := c.Conn.Post(path, data, opts...)
	if err != nil {
		optsAttr := make([]slog.Attr, 0)
		for i, opt := range opts {
			optsAttr = append(optsAttr, slog.String(fmt.Sprintf("opt[%d]", i), fmt.Sprint(opt)))
		}
		dataAttr := make([]slog.Attr, 0)
		for k, v := range data {
			dataAttr = append(dataAttr, slog.String(k, strings.Join(v, ",")))
		}
		c.logAndFatal("Error during POST request",
			slog.String("error", err.Error()),
			slog.String("base-url", c.Conn.BaseURL),
			slog.String("path", path),
			"options", slog.GroupValue(optsAttr...),
			"data", slog.GroupValue(dataAttr...))
	}
	return resp
}

func (c *WebConnWithLogger) DisableRedirect() {
	c.Conn.DisableRedirect()
}

func (c *WebConnWithLogger) SetCookie(name, value string) {
	c.Conn.logger.Debug("Setting Cookie",
		slog.String(name, value))
	c.Conn.SetCookie(name, value)
}

func (c *Client) logHeaders() {
	attrs := make([]slog.Attr, 0, len(c.headers))
	for k, v := range c.headers {
		attrs = append(attrs, slog.String(k, v))
	}
	c.logger.Debug("Using the following headers",
		"headers", slog.GroupValue(attrs...))
}

func (c *Client) logCookies() {
	attrs := make([]slog.Attr, 0, len(c.GetCookies()))
	for _, cookie := range c.GetCookies() {
		attrs = append(attrs, slog.String(cookie.Name, cookie.Value))
	}
	c.logger.Debug("Using the following headers",
		"cookies", slog.GroupValue(attrs...))
}

func (c *WebConnWithLogger) Client() *Client {
	return c.Conn.Client
}

func (c *WebConnWithLogger) Session() *Session {
	return c.Conn.Session()
}
