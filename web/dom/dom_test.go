package dom_test

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/tonythetender/pwngears/web"
	"github.com/tonythetender/pwngears/web/dom"
)

func TestDOMFetchSelectSubmit(t *testing.T) {
	const page = `<html><body>
	<h1>Welcome</h1>
	<a class="next" href="/step2">next</a>
	<form id="login" method="post" action="/login">
	  <input type="hidden" name="csrf" value="tok123">
	  <input name="user">
	</form>
	</body></html>`

	var gotUser, gotCSRF string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, page) })
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		gotUser = r.FormValue("user")
		gotCSRF = r.FormValue("csrf")
		fmt.Fprint(w, "Welcome admin")
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go http.Serve(ln, mux)

	conn := web.Conn("http://" + ln.Addr().String())
	conn.SetLogLevel("ERROR")

	p := dom.Fetch(conn, "/")
	if got := strings.TrimSpace(p.First("h1").Text()); got != "Welcome" {
		t.Fatalf("h1 text = %q", got)
	}
	if links := p.Links(); len(links) == 0 || !strings.HasSuffix(links[0], "/step2") {
		t.Fatalf("links = %v", links)
	}

	// Submitting pre-loads the hidden CSRF field, so we only set what we change.
	after := p.Form("#login").Set("user", "admin").Submit()
	if !after.Resp.Contains("Welcome admin") {
		t.Fatalf("submit response = %q", after.Text())
	}
	if gotUser != "admin" || gotCSRF != "tok123" {
		t.Fatalf("server received user=%q csrf=%q (hidden CSRF should carry over)", gotUser, gotCSRF)
	}
}
