// Command scripting is a complete, runnable example of solving an interactive
// challenge: clear a proof-of-work gate, answer a series of prompts under a
// round loop, and grab the flag.
//
// It is fully self-contained: a local stub "challenge" server runs in a
// goroutine so `go run ./examples/scripting/` works with no setup. The solve()
// function is written exactly as you would write it against a real target, so
// to use it for real you only change the Remote(host, port) line.
package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"math/bits"
	"net"
	"strconv"
	"strings"

	. "github.com/tonythetender/pwngears"
)

func main() {
	host, port := startChallenge()
	solve(host, port)
}

// solve is the part you would actually write for a challenge.
func solve(host string, port int) {
	r := Remote(host, port)
	defer r.Close()

	// 1. Clear the proof-of-work gate announced on the first line. The pattern
	//    captures the prefix and the difficulty (as a "bits" group); the 16 is a
	//    fallback if the line omits the difficulty.
	ClearPoW(r, `prefix=(?P<prefix>\w+), need (?P<bits>\d+)`, 16)

	// 2. Answer each arithmetic prompt until the flag arrives. An unbounded loop
	//    stops itself when it sees the flag (or on end-of-stream).
	var flag string
	NewLoop(r).Run(func(r *Round) {
		if f := r.Flag("flag"); f != "" {
			flag = f
			r.Stop()
			return
		}
		n := r.Ints()
		if len(n) < 2 {
			return // not an arithmetic line, skip
		}
		// Ints() grabs every integer in the line, including the "[3/10]" round
		// counter, so the two operands are the last two.
		a, b := n[len(n)-2], n[len(n)-1]
		switch r.Match(`[-+*]`) {
		case "+":
			r.Send(a + b)
		case "-":
			r.Send(a - b)
		case "*":
			r.Send(a * b)
		}
	})

	fmt.Println("recovered:", flag)
}

// ---------------------------------------------------------------------------
// Everything below is the local stub challenge server, so the example runs on
// its own. A real challenge replaces this.
// ---------------------------------------------------------------------------

func startChallenge() (string, int) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		defer ln.Close()
		serve(conn)
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func serve(conn net.Conn) {
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	// Proof-of-work gate: sha256(prefix + answer) must have >= 16 leading zero bits.
	const prefix, difficulty = "aB3xZ9kQ", 16
	fmt.Fprintf(rw, "proof of work: prefix=%s, need %d leading zero bits\n", prefix, difficulty)
	rw.Flush()
	ans, err := rw.ReadString('\n')
	if err != nil {
		return
	}
	sum := sha256.Sum256([]byte(prefix + strings.TrimSpace(ans)))
	if leadingZeroBits(sum[:]) < difficulty {
		fmt.Fprintln(rw, "bad pow")
		rw.Flush()
		return
	}

	// Ten arithmetic rounds, then the flag.
	ops := []struct {
		sym  string
		a, b int
	}{
		{"+", 7, 35}, {"*", 6, 7}, {"-", 90, 48}, {"+", 11, 22}, {"*", 9, 9},
		{"-", 100, 1}, {"+", 40, 2}, {"*", 8, 8}, {"-", 50, 8}, {"+", 19, 23},
	}
	for i, o := range ops {
		fmt.Fprintf(rw, "[%d/10] compute %d %s %d = \n", i+1, o.a, o.sym, o.b)
		rw.Flush()
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		want := map[string]int{"+": o.a + o.b, "-": o.a - o.b, "*": o.a * o.b}[o.sym]
		if got, _ := strconv.Atoi(strings.TrimSpace(line)); got != want {
			fmt.Fprintf(rw, "wrong: wanted %d\n", want)
			rw.Flush()
			return
		}
	}
	fmt.Fprintln(rw, "flag{scripting_loop_solved}")
	rw.Flush()
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, by := range b {
		if by == 0 {
			n += 8
			continue
		}
		n += bits.LeadingZeros8(by)
		break
	}
	return n
}
