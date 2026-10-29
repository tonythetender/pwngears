// Command web demonstrates the web client: requests with params and headers,
// form posts, response helpers, wordlist fuzzing, and blind char-by-char
// extraction through a boolean oracle. It runs against a local stub server, so
// `go run ./examples/web/` works with no setup.
package main

import (
	"fmt"
	"net"
	"net/http"
	"strconv"

	. "github.com/tonythetender/pwngears"
)

func main() {
	base := startServer()
	conn := Conn(base)

	// 1. GET with a query param and a header, then grep a flag from the body.
	resp := conn.Get("/welcome", WithParam("user", "guest"), WithHeader("X-Debug", "1"))
	fmt.Println("welcome:", resp.Flag("flag"))

	// 2. POST a login form and inspect the result.
	login := conn.PostForm("/login", Fields{"user": "admin", "password": "hunter2"})
	fmt.Printf("login: status=%d welcome=%v\n", login.StatusCode, login.Contains("welcome"))

	// 3. Fuzz a wordlist for live paths, keeping only 200s.
	words := []string{"home", "admin", "secret", "nope", "robots.txt"}
	hits := Fuzz(func(w string) *Response { return conn.Get("/" + w) }, words, MatchStatus(200))
	fmt.Print("fuzz hits:")
	for _, h := range hits {
		fmt.Printf(" /%s(%d)", h.Word, h.Status)
	}
	fmt.Println()

	// 4. Recover a secret one character at a time via a boolean oracle + Scan.
	scan := CharOracle(
		func(pos int, c byte) *Response {
			return conn.Get("/oracle",
				WithParam("pos", strconv.Itoa(pos)),
				WithParam("c", string(c)))
		},
		func(r *Response) bool { return r.Contains("match") },
	)
	bf := NewBruteforcer()
	bf.Charset = GenerateCharset("lowercase", "digits")
	secret, _ := bf.Scan(scan)
	fmt.Println("extracted secret:", secret)
}

// ---------------------------------------------------------------------------
// Local stub server, so the example runs on its own. A real target replaces it.
// ---------------------------------------------------------------------------

func startServer() string {
	const secret = "ctf42"

	mux := http.NewServeMux()
	mux.HandleFunc("/welcome", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hi %s, flag{web_client_demo}", r.URL.Query().Get("user"))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.FormValue("password") == "hunter2" {
			fmt.Fprint(w, "welcome admin")
			return
		}
		fmt.Fprint(w, "invalid credentials")
	})
	for _, p := range []string{"/home", "/admin", "/secret", "/robots.txt"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	}
	mux.HandleFunc("/oracle", func(w http.ResponseWriter, r *http.Request) {
		pos, _ := strconv.Atoi(r.URL.Query().Get("pos"))
		c := r.URL.Query().Get("c")
		if pos >= 1 && pos <= len(secret) && len(c) == 1 && secret[pos-1] == c[0] {
			fmt.Fprint(w, "match")
			return
		}
		fmt.Fprint(w, "no")
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	go http.Serve(ln, mux)
	return "http://" + ln.Addr().String()
}
