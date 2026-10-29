// Package scripting automates the recv-parse-compute-send shape that dominates
// CTF scripting challenges, and solves hash proof-of-work gates in parallel.
package scripting

import (
	"fmt"
	"time"

	"github.com/tonythetender/pwngears/process"
)

// LoggerTube is the no-error connection surface produced by process.Remote and
// process.Process. Both *process.RemoteConnWithLogger and
// *process.ProcessConnWithLogger satisfy it, so a Loop drives the default
// connection style directly.
type LoggerTube interface {
	Send(data any)
	SendLine(data any)
	SendAfter(delim, data any)
	SendLineAfter(delim, data any)
	Recv(n int) []byte
	RecvUntil(delim any) []byte
	RecvLine() []byte
	RecvLineString() string
	RecvAll(timeout time.Duration) []byte
	Close()
}

type readDeadliner interface {
	SetReadDeadline(time.Time) error
}

// Round is one iteration of a Loop: the prompt just read, plus the actions you
// can take in response. It embeds *Prompt, so the parsing helpers
// (Ints, Match, Flag, ...) are available directly on it.
type Round struct {
	*Prompt
	loop    *Loop
	stopped bool
}

// Send replies with v (numbers and other non-string/[]byte values are sent as
// their decimal/default text, since these are text protocols). Honors the
// loop's SendRaw setting for the trailing newline. You may call it zero or more
// times per round.
func (r *Round) Send(v any) {
	r.loop.send(v)
}

// Stop ends the loop after this round returns.
func (r *Round) Stop() { r.stopped = true }

// Tube returns the underlying connection for rounds that need to read or send
// more than the single prompt/answer exchange.
func (r *Round) Tube() LoggerTube { return r.loop.tube }

// Loop automates { read a prompt, compute an answer, send it } over a
// connection. Build it fluently, then call Run with a per-round handler.
type Loop struct {
	tube      LoggerTube
	raw       process.Tube
	deadliner readDeadliner
	delim     any
	rounds    int
	timeout   time.Duration
	sendRaw   bool
}

// NewLoop wraps a connection. When the connection is one of the concrete
// process WithLogger types, the loop reads through its embedded raw tube so it
// can detect end-of-stream precisely instead of the WithLogger methods'
// os.Exit-on-error behavior.
func NewLoop(t LoggerTube) *Loop {
	l := &Loop{tube: t}
	switch c := t.(type) {
	case *process.RemoteConnWithLogger:
		l.raw = c.RemoteConn
	case *process.ProcessConnWithLogger:
		l.raw = c.ProcessConn
	}
	if d, ok := l.raw.(readDeadliner); ok {
		l.deadliner = d
	}
	return l
}

// Until sets the per-round delimiter to read up to (default: read a line).
func (l *Loop) Until(delim any) *Loop { l.delim = delim; return l }

// Rounds caps the number of iterations (0 = until Stop or end-of-stream).
func (l *Loop) Rounds(n int) *Loop { l.rounds = n; return l }

// Timeout bounds the total time of the loop. When the connection supports read
// deadlines (remote connections do), a blocked read is interrupted at the
// deadline; otherwise the bound is enforced between rounds.
func (l *Loop) Timeout(d time.Duration) *Loop { l.timeout = d; return l }

// SendRaw sends replies without a trailing newline (default: SendLine).
func (l *Loop) SendRaw(on bool) *Loop { l.sendRaw = on; return l }

// Run reads a prompt each round and calls fn, which replies with r.Send(...),
// ends the loop with r.Stop(), or does nothing to skip the round. The loop also
// ends at the round cap, the timeout, or end-of-stream.
func (l *Loop) Run(fn func(r *Round)) {
	start := time.Now()
	if l.timeout > 0 && l.deadliner != nil {
		l.deadliner.SetReadDeadline(start.Add(l.timeout))
		defer l.deadliner.SetReadDeadline(time.Time{})
	}

	for round := 1; l.rounds == 0 || round <= l.rounds; round++ {
		if l.timeout > 0 && time.Since(start) > l.timeout {
			break
		}
		data, eof := l.recv()
		if len(data) == 0 && eof {
			break
		}
		rd := &Round{Prompt: &Prompt{Round: round, Data: data}, loop: l}
		fn(rd)
		if rd.stopped || eof {
			break
		}
	}
}

func (l *Loop) recv() (data []byte, eof bool) {
	if l.raw != nil {
		var b []byte
		var err error
		if l.delim != nil {
			b, err = l.raw.RecvUntil(l.delim)
		} else {
			b, err = l.raw.RecvLine()
		}
		return b, err != nil
	}
	if l.delim != nil {
		return l.tube.RecvUntil(l.delim), false
	}
	return l.tube.RecvLine(), false
}

func (l *Loop) send(ans any) {
	v := normalizeReply(ans)
	if l.sendRaw {
		l.tube.Send(v)
	} else {
		l.tube.SendLine(v)
	}
}

func normalizeReply(ans any) any {
	switch v := ans.(type) {
	case string:
		return v
	case []byte:
		return v
	default:
		return fmt.Sprint(v)
	}
}

// Expect is the one-liner for the common bounded case: read up to delim (nil for
// a line), for rounds iterations, handling each with fn.
func Expect(t LoggerTube, delim any, rounds int, fn func(r *Round)) {
	l := NewLoop(t).Rounds(rounds)
	if delim != nil {
		l.Until(delim)
	}
	l.Run(fn)
}
