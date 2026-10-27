package process

import (
	"log/slog"
	"os"
	"time"

	pwnlog "github.com/tonythetender/pwngears/internal/pwnlog"
)

func logFatal(logger *slog.Logger, failOnError bool, msg string, args ...any) {
	logger.Error(msg, args...)
	if failOnError {
		os.Exit(1)
	}
}

func sendT(t Tube, lg *slog.Logger, fail bool, data any) {
	if err := t.Send(data); err != nil {
		logFatal(lg, fail, "Could not send data to tube", slog.String("error", err.Error()))
	}
}

func sendLineT(t Tube, lg *slog.Logger, fail bool, data any) {
	if err := t.SendLine(data); err != nil {
		logFatal(lg, fail, "Could not send line to tube", slog.String("error", err.Error()))
	}
}

func sendAfterT(t Tube, lg *slog.Logger, fail bool, delim, data any) {
	if err := t.SendAfter(delim, data); err != nil {
		logFatal(lg, fail, "Could not send data after delimiter", slog.String("error", err.Error()))
	}
}

func sendLineAfterT(t Tube, lg *slog.Logger, fail bool, delim, data any) {
	if err := t.SendLineAfter(delim, data); err != nil {
		logFatal(lg, fail, "Could not send line after delimiter", slog.String("error", err.Error()))
	}
}

func recvT(t Tube, lg *slog.Logger, fail bool, n int) []byte {
	b, err := t.Recv(n)
	if err != nil {
		logFatal(lg, fail, "Could not receive data from tube", slog.String("error", err.Error()))
	}
	return b
}

func recvUntilT(t Tube, lg *slog.Logger, fail bool, delim any) []byte {
	b, err := t.RecvUntil(delim)
	if err != nil {
		logFatal(lg, fail, "Could not receive until delimiter", slog.String("error", err.Error()))
	}
	return b
}

func recvLineT(t Tube, lg *slog.Logger, fail bool) []byte {
	b, err := t.RecvLine()
	if err != nil {
		logFatal(lg, fail, "Could not receive line from tube", slog.String("error", err.Error()))
	}
	return b
}

func recvStringT(t Tube, lg *slog.Logger, fail bool) string {
	s, err := t.RecvString()
	if err != nil {
		logFatal(lg, fail, "Could not receive string from tube", slog.String("error", err.Error()))
	}
	return s
}

func recvLineStringT(t Tube, lg *slog.Logger, fail bool) string {
	s, err := t.RecvLineString()
	if err != nil {
		logFatal(lg, fail, "Could not receive line string from tube", slog.String("error", err.Error()))
	}
	return s
}

func recvAllT(t Tube, lg *slog.Logger, fail bool, timeout time.Duration) []byte {
	b, err := t.RecvAll(timeout)
	if err != nil {
		logFatal(lg, fail, "Could not receive all data from tube", slog.String("error", err.Error()))
	}
	return b
}

func recvAllStringT(t Tube, lg *slog.Logger, fail bool, timeout time.Duration) string {
	s, err := t.RecvAllString(timeout)
	if err != nil {
		logFatal(lg, fail, "Could not receive all data as string from tube", slog.String("error", err.Error()))
	}
	return s
}

func interactiveT(t Tube, lg *slog.Logger, fail bool) {
	if err := t.Interactive(); err != nil {
		logFatal(lg, fail, "Error during interactive session", slog.String("error", err.Error()))
	}
}

func closeT(t Tube, lg *slog.Logger, fail bool) {
	if err := t.Close(); err != nil {
		logFatal(lg, fail, "Could not close tube", slog.String("error", err.Error()))
	}
}

func sendPayloadT(t Tube, lg *slog.Logger, fail bool, p *Payload) {
	if err := t.Send(p.Bytes()); err != nil {
		logFatal(lg, fail, "Could not send payload to tube", slog.String("error", err.Error()))
	}
}

func sendPayloadSizeT(t Tube, lg *slog.Logger, fail bool, p *Payload) {
	if err := t.Send(P32(uint32(p.Len()))); err != nil {
		logFatal(lg, fail, "Could not send payload size to tube", slog.String("error", err.Error()))
	}
}

func setLogLevel(logLevel string) {
	switch logLevel {
	case "DEBUG", "debug":
		pwnlog.LogLevel.Set(slog.LevelDebug)
	case "INFO", "info":
		pwnlog.LogLevel.Set(slog.LevelInfo)
	case "WARN", "warn":
		pwnlog.LogLevel.Set(slog.LevelWarn)
	case "ERROR", "error":
		pwnlog.LogLevel.Set(slog.LevelError)
	case "IGNORE", "ignore":
		pwnlog.LogLevel.Set(12)
	}
}

type ProcessConnWithLogger struct {
	*ProcessConn
	failOnError bool
}

type processConfig struct {
	args   []string
	env    map[string]string
	logger *slog.Logger
}

type ProcessOption func(*processConfig)

func WithArgs(args ...string) ProcessOption {
	return func(c *processConfig) { c.args = append(c.args, args...) }
}

func WithEnv(env map[string]string) ProcessOption {
	return func(c *processConfig) {
		if c.env == nil {
			c.env = make(map[string]string)
		}
		for k, v := range env {
			c.env[k] = v
		}
	}
}

func WithEnvVar(key, value string) ProcessOption {
	return func(c *processConfig) {
		if c.env == nil {
			c.env = make(map[string]string)
		}
		c.env[key] = value
	}
}

func WithProcessLogger(logger *slog.Logger) ProcessOption {
	return func(c *processConfig) { c.logger = logger }
}

func Process(path string, args ...string) *ProcessConnWithLogger {
	return ProcessWith(path, WithArgs(args...))
}

func ProcessWithLogger(logger *slog.Logger, path string, args ...string) *ProcessConnWithLogger {
	return ProcessWith(path, WithProcessLogger(logger), WithArgs(args...))
}

func ProcessWith(path string, opts ...ProcessOption) *ProcessConnWithLogger {
	cfg := &processConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	logger := cfg.logger
	if logger == nil {
		l, err := pwnlog.NewDefaultLogger("INFO")
		if err != nil {
			slog.Default().Error("error generating the default logger", slog.String("error", err.Error()))
			os.Exit(1)
		}
		logger = l
	}

	allArgs := append([]string{path}, cfg.args...)
	p, err := NewProcess(logger, allArgs, cfg.env)
	if err != nil {
		wd, _ := os.Getwd()
		logger.Error("Could not start process",
			slog.String("error", err.Error()),
			slog.String("working-directory", wd),
			slog.String("executable-path", path))
		os.Exit(1)
	}

	return &ProcessConnWithLogger{
		ProcessConn: p,
		failOnError: true,
	}
}

func (p *ProcessConnWithLogger) SetFailOnError(fail bool) { p.failOnError = fail }

func (p *ProcessConnWithLogger) SetLogLevel(logLevel string) { setLogLevel(logLevel) }

func (p *ProcessConnWithLogger) GetPID() int { return p.ProcessConn.GetPID() }

func (p *ProcessConnWithLogger) Kill() {
	if err := p.ProcessConn.Kill(); err != nil {
		logFatal(p.ProcessConn.logger, p.failOnError, "Could not send kill signal", slog.String("error", err.Error()))
	}
}

func (p *ProcessConnWithLogger) Wait() {
	if err := p.ProcessConn.Wait(); err != nil {
		logFatal(p.ProcessConn.logger, p.failOnError, "Could not wait for command to exit", slog.String("error", err.Error()))
	}
}

func (p *ProcessConnWithLogger) Send(data any) {
	sendT(p.ProcessConn, p.ProcessConn.logger, p.failOnError, data)
}

func (p *ProcessConnWithLogger) SendLine(data any) {
	sendLineT(p.ProcessConn, p.ProcessConn.logger, p.failOnError, data)
}

func (p *ProcessConnWithLogger) SendAfter(delim, data any) {
	sendAfterT(p.ProcessConn, p.ProcessConn.logger, p.failOnError, delim, data)
}

func (p *ProcessConnWithLogger) SendLineAfter(delim, data any) {
	sendLineAfterT(p.ProcessConn, p.ProcessConn.logger, p.failOnError, delim, data)
}

func (p *ProcessConnWithLogger) Recv(n int) []byte {
	return recvT(p.ProcessConn, p.ProcessConn.logger, p.failOnError, n)
}

func (p *ProcessConnWithLogger) RecvUntil(delim any) []byte {
	return recvUntilT(p.ProcessConn, p.ProcessConn.logger, p.failOnError, delim)
}

func (p *ProcessConnWithLogger) RecvLine() []byte {
	return recvLineT(p.ProcessConn, p.ProcessConn.logger, p.failOnError)
}

func (p *ProcessConnWithLogger) RecvString() string {
	return recvStringT(p.ProcessConn, p.ProcessConn.logger, p.failOnError)
}

func (p *ProcessConnWithLogger) RecvLineString() string {
	return recvLineStringT(p.ProcessConn, p.ProcessConn.logger, p.failOnError)
}

func (p *ProcessConnWithLogger) RecvAll(timeout time.Duration) []byte {
	return recvAllT(p.ProcessConn, p.ProcessConn.logger, p.failOnError, timeout)
}

func (p *ProcessConnWithLogger) RecvAllString(timeout time.Duration) string {
	return recvAllStringT(p.ProcessConn, p.ProcessConn.logger, p.failOnError, timeout)
}

func (p *ProcessConnWithLogger) SendPayload(payload *Payload) {
	sendPayloadT(p.ProcessConn, p.ProcessConn.logger, p.failOnError, payload)
}

func (p *ProcessConnWithLogger) SendPayloadSize(payload *Payload) {
	sendPayloadSizeT(p.ProcessConn, p.ProcessConn.logger, p.failOnError, payload)
}

func (p *ProcessConnWithLogger) Interactive() {
	interactiveT(p.ProcessConn, p.ProcessConn.logger, p.failOnError)
}

func (p *ProcessConnWithLogger) Close() {
	closeT(p.ProcessConn, p.ProcessConn.logger, p.failOnError)
}

type RemoteConnWithLogger struct {
	*RemoteConn
	logger      *slog.Logger
	failOnError bool
}

func Remote(host string, port int, opts ...RemoteOption) *RemoteConnWithLogger {
	logger, err := pwnlog.NewDefaultLogger("INFO")
	if err != nil {
		slog.Default().Error("error generating the default logger", slog.String("error", err.Error()))
		os.Exit(1)
	}
	return RemoteWithLogger(logger, host, port, opts...)
}

func RemoteWithLogger(logger *slog.Logger, host string, port int, opts ...RemoteOption) *RemoteConnWithLogger {
	remote, err := NewRemote(host, port, opts...)
	if err != nil {
		logger.Error("Could not establish connection to the given host",
			slog.String("error", err.Error()),
			slog.String("host", host))
		os.Exit(1)
	}
	return &RemoteConnWithLogger{
		RemoteConn:  remote,
		logger:      logger,
		failOnError: true,
	}
}

func (r *RemoteConnWithLogger) SetFailOnError(fail bool) { r.failOnError = fail }

func (r *RemoteConnWithLogger) SetLogLevel(logLevel string) { setLogLevel(logLevel) }

func (r *RemoteConnWithLogger) GetPID() int { return r.RemoteConn.GetPID() }

func (r *RemoteConnWithLogger) Reconnect() *RemoteConnWithLogger {
	remote, err := r.RemoteConn.Reconnect()
	if err != nil {
		logFatal(r.logger, r.failOnError, "Could not reconnect to host", slog.String("error", err.Error()))
	}
	return &RemoteConnWithLogger{
		RemoteConn:  remote,
		logger:      r.logger,
		failOnError: r.failOnError,
	}
}

func (r *RemoteConnWithLogger) Send(data any) {
	sendT(r.RemoteConn, r.logger, r.failOnError, data)
}

func (r *RemoteConnWithLogger) SendLine(data any) {
	sendLineT(r.RemoteConn, r.logger, r.failOnError, data)
}

func (r *RemoteConnWithLogger) SendAfter(delim, data any) {
	sendAfterT(r.RemoteConn, r.logger, r.failOnError, delim, data)
}

func (r *RemoteConnWithLogger) SendLineAfter(delim, data any) {
	sendLineAfterT(r.RemoteConn, r.logger, r.failOnError, delim, data)
}

func (r *RemoteConnWithLogger) Recv(n int) []byte {
	return recvT(r.RemoteConn, r.logger, r.failOnError, n)
}

func (r *RemoteConnWithLogger) RecvUntil(delim any) []byte {
	return recvUntilT(r.RemoteConn, r.logger, r.failOnError, delim)
}

func (r *RemoteConnWithLogger) RecvLine() []byte {
	return recvLineT(r.RemoteConn, r.logger, r.failOnError)
}

func (r *RemoteConnWithLogger) RecvString() string {
	return recvStringT(r.RemoteConn, r.logger, r.failOnError)
}

func (r *RemoteConnWithLogger) RecvLineString() string {
	return recvLineStringT(r.RemoteConn, r.logger, r.failOnError)
}

func (r *RemoteConnWithLogger) RecvAll(timeout time.Duration) []byte {
	return recvAllT(r.RemoteConn, r.logger, r.failOnError, timeout)
}

func (r *RemoteConnWithLogger) RecvAllString(timeout time.Duration) string {
	return recvAllStringT(r.RemoteConn, r.logger, r.failOnError, timeout)
}

func (r *RemoteConnWithLogger) SendPayload(payload *Payload) {
	sendPayloadT(r.RemoteConn, r.logger, r.failOnError, payload)
}

func (r *RemoteConnWithLogger) SendPayloadSize(payload *Payload) {
	sendPayloadSizeT(r.RemoteConn, r.logger, r.failOnError, payload)
}

func (r *RemoteConnWithLogger) Interactive() {
	interactiveT(r.RemoteConn, r.logger, r.failOnError)
}

func (r *RemoteConnWithLogger) Close() {
	closeT(r.RemoteConn, r.logger, r.failOnError)
}
