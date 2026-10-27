package main

import (
	"fmt"
	"regexp"

	. "github.com/tonythetender/pwngears/web"
)

// Adjust to the challenge's flag format.
var flagRe = regexp.MustCompile(`FLAG\{[^}]*\}`)

func main() {
	conn := Conn("https://some-challenge.com")

	resp := conn.Get("/")
	fmt.Println("GET / ->", resp.StatusCode)

	form := NewForm()
	form.Set("username", "admin")
	form.Set("password", "password")
	resp = conn.Post("/login", form)
	fmt.Println("POST /login ->", resp.StatusCode)

	body := resp.Text()
	if m := flagRe.FindString(body); m != "" {
		fmt.Println("flag:", m)
	} else {
		fmt.Println(body)
	}
}
