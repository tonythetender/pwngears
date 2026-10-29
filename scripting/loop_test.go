package scripting

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pwnlog "github.com/tonythetender/pwngears/internal/pwnlog"
	"github.com/tonythetender/pwngears/process"
)

// arithServer serves `rounds` "Compute: a + b" prompts, verifies each answer,
// and records whether every answer was correct. If closeAfter >= 0 it closes
// the connection after that many prompts (to exercise the EOF path).
func arithServer(t *testing.T, rounds, closeAfter int) (port int, allCorrect *bool, done *sync.WaitGroup) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	ok := true
	allCorrect = &ok
	done = &sync.WaitGroup{}
	done.Add(1)

	go func() {
		defer done.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		for i := 1; i <= rounds; i++ {
			if closeAfter >= 0 && i > closeAfter {
				return // drop the connection -> client sees EOF
			}
			a, b := i, i*2
			fmt.Fprintf(rw, "Compute: %d + %d\n", a, b)
			rw.Flush()
			line, err := rw.ReadString('\n')
			if err != nil {
				ok = false
				return
			}
			got, _ := strconv.Atoi(strings.TrimSpace(line))
			if got != a+b {
				ok = false
			}
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port, allCorrect, done
}

func dial(t *testing.T, port int) *process.RemoteConnWithLogger {
	t.Helper()
	logger, err := pwnlog.NewDefaultLogger("IGNORE")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return process.RemoteWithLogger(logger, "127.0.0.1", port)
}

func TestLoopExpectArithmetic(t *testing.T) {
	port, allCorrect, done := arithServer(t, 5, -1)
	r := dial(t, port)
	defer r.Close()

	Expect(r, nil, 5, func(rd *Round) {
		n := rd.Ints()
		if len(n) != 2 {
			t.Errorf("round %d: expected 2 ints, got %v", rd.Round, n)
			return
		}
		rd.Send(n[0] + n[1])
	})

	done.Wait()
	if !*allCorrect {
		t.Fatal("server reported a wrong answer")
	}
}

func TestLoopStopsOnEOF(t *testing.T) {
	// Server promises 5 rounds but closes after 2; an unbounded loop must stop.
	port, _, done := arithServer(t, 5, 2)
	r := dial(t, port)
	defer r.Close()

	rounds := 0
	NewLoop(r).Run(func(rd *Round) {
		rounds++
		n := rd.Ints()
		rd.Send(n[0] + n[1])
	})
	if rounds != 2 {
		t.Fatalf("expected 2 rounds before EOF, got %d", rounds)
	}
	done.Wait()
}

func TestLoopStopSentinel(t *testing.T) {
	port, _, done := arithServer(t, 10, -1)
	r := dial(t, port)
	defer r.Close()

	rounds := 0
	NewLoop(r).Run(func(rd *Round) {
		rounds++
		if rounds == 3 {
			rd.Stop()
			return
		}
		n := rd.Ints()
		rd.Send(n[0] + n[1])
	})
	if rounds != 3 {
		t.Fatalf("expected to stop at round 3, ran %d", rounds)
	}
	_ = done
}

func TestClearPoW(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	okCh := make(chan bool, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			okCh <- false
			return
		}
		defer conn.Close()
		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		prefix := "chalABCD"
		fmt.Fprintf(rw, "solve sha256 with prefix=%s\n", prefix)
		rw.Flush()
		ans, err := rw.ReadString('\n')
		if err != nil {
			okCh <- false
			return
		}
		sum := sha256.Sum256([]byte(prefix + strings.TrimSpace(ans)))
		okCh <- digestLeadingZeroBits(sum[:]) >= 12
	}()

	r := dial(t, port)
	defer r.Close()

	pw := ClearPoW(r, `prefix=(?P<prefix>\w+)`, 12)
	if digestLeadingZeroBits(pw.Digest) < 12 {
		t.Fatal("ClearPoW did not satisfy the gate locally")
	}
	if !<-okCh {
		t.Fatal("server rejected the PoW answer")
	}
}

func TestLoopTimeoutInterruptsHang(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		time.Sleep(2 * time.Second) // never send; hold the connection open
		conn.Close()
	}()

	r := dial(t, port)
	defer r.Close()

	rounds := 0
	start := time.Now()
	NewLoop(r).Timeout(300 * time.Millisecond).Run(func(rd *Round) {
		rounds++
		rd.Send("x")
	})
	elapsed := time.Since(start)

	if rounds != 0 {
		t.Fatalf("expected 0 rounds against a silent server, got %d", rounds)
	}
	if elapsed > time.Second {
		t.Fatalf("read deadline did not interrupt the blocked recv: %v", elapsed)
	}
}
