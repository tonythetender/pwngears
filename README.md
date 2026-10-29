Pwngears is a CTF framework and exploit development library based on pwntools. It aims to provide an improved API and better error handling while adding more functionnalities regarding challenges other than binary exploitation. It also aims to stay light on dependencies, leaning on the Go standard library with `golang.org/x/net` as the only third-party package (for HTML parsing). 

## Why Go? And why make an alternative to Pwntools?
- Compiles into a static binary, eliminating risk of an exploit not working on somebody else version of the python interpreter. Also has easy cross compilation.
- Good performance and cheap goroutines allows for easy and quick byte-by-bytes leaks, length leaks and blind SQLI.
- The Go standard library provides most of the tooling to make this library possible, keeping external dependencies to a minimum.
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
Almost everything is re-exported from a single root package, so most exploits only need one import.
```go
import . "github.com/tonythetender/pwngears"
```
This gives you the whole toolkit (binary exploitation, web, DOM parsing, cryptography, bruteforcing, injection payloads, scripting automation and the magic toolkit) under one namespace. Its only external dependency is `golang.org/x/net`, pulled in for the HTML parsing behind the DOM helpers, so it stays light and compiles to a small static binary. You can still import the subpackages directly (`pwngears/web`, `pwngears/bruteforce`, ...) if you prefer a narrower namespace.

> [!NOTE]
> The docs use the `.` dot-import for brevity. If you have name clashes with your own code or other libraries, switch to an explicit import.

## Runnable examples
Each area has a self-contained example that runs with no setup. A local stub stands in for the challenge server, so you can read the whole flow end to end.
```sh
go run ./examples/web/         # requests, form login, fuzzing, blind extraction
go run ./examples/scripting/   # proof-of-work gate + interactive round loop
go run ./examples/magic/       # decode chains, fingerprinting, cipher solving
go run ./examples/process/     # payload building, cyclic offsets, local process (+ remote exploit template)
```

## Connections: logging or errors
Every connection (`Conn` for web, `Process` and `Remote` for binary exploitation, and constructors like `NewBruteforcer`) comes in two flavors. The default returns values directly and logs, exiting on error, so a script stays terse.
```go
conn := Conn("http://chal.ctf")
resp := conn.Get("/")
```
If you prefer idiomatic Go error handling, open it with the `WithErrors` constructor and every method returns an `error` too.
```go
conn, err := ConnWithErrors("http://chal.ctf")
resp, err := conn.Get("/")
```
The default (logger) style is used throughout these docs. Set its level with `conn.SetLogLevel("DEBUG")`, pass your own slog logger with `ConnWithLogger(url, logger)`, and stop it exiting on error with `conn.SetFailOnError(false)`.

## Web
GET with query parameters, headers, cookies, or auth, all passed as options.
```go
resp := conn.Get("/search",
	WithParam("q", "admin"),
	WithHeader("X-Forwarded-For", "127.0.0.1"),
	WithCookie("session", "abc123"))

resp := conn.Get("/api", WithBearer(token))   // or WithBasicAuth("admin", "admin")
```
POST a form as key/value pairs or a `Fields` map, JSON with `PostJSON`, or a hand-crafted body with `PostRaw`.
```go
conn.PostForm("/login", Fields{"user": "admin", "password": "hunter2"})
conn.PostJSON("/api", map[string]any{"id": 1})
conn.PostRaw("/api", `{"id":1}`, WithContentType("application/json"))
```
`Put`, `Patch`, `Delete`, `Head` and `Options` round out the verbs. `NewForm()` handles multi-value fields, `LoadFields`/`LoadJSON` read a body from a file, and the package-level `Get`/`Post`/`PostForm`/`PostJSON` take a full URL for a one-off probe without a connection.

Read the response with helpers instead of hand-rolled parsing.
```go
resp.Match(`password: (\w+)`)   // first capture group (or whole match)
resp.Flag("FLAG")               // grep a FLAG{...} token
resp.OK()                       // status in the 2xx range
resp.Is(302)                    // exact status code
resp.JSON(&out)                 // decode the body into a struct
```
Under the default connection `Match` and `Flag` exit when nothing matches (call `SetFailOnError(false)` for an empty result instead). A complete flow, with params, a form login, fuzzing and blind extraction, is in `examples/web`.

### DOM parsing
To parse HTML rather than grep it, the DOM helpers come with the root import (they are what pulls in `golang.org/x/net`).
```go
page := Fetch(conn, "/")
title := page.First("h1").Text()
page.Form("#login").Set("user", "admin").Set("password", "x").Submit()
```
`Fetch` returns a `Page`, and `First`/`All` return a `Node`. It has a small CSS-like selector (`tag`, `.class`, `#id`, `[attr=value]`, descendants), link following that keeps the session, and a `Form` that pre-loads hidden and CSRF fields so you only set what you change.

## Binary exploitation
Connect to a local binary or a remote service. Both share the same send and receive API.
```go
p := Process("./chal")          // with args: Process("./chal", "arg1")
r := Remote("chal.ctf", 1337)   // with TLS: Remote(host, port, SSL())

r.SendLineAfter("Name: ", "Arthur")
leak := U64(r.Recv(8))
```
`ProcessWith(path, WithEnv(...))` sets environment variables (for example an `LD_PRELOAD` libc), and `SSL()` combines with `WithSNI` and `WithVerifyCert`.

Payloads are built fluently. `Pay()` and `Flat()` take any mix of parts: a `string` or `[]byte` goes in raw, and an integer is packed little-endian (64-bit by default, since addresses are the common case).
```go
r.SendPayload(Pay().PadTo(72).Flat(popRdi, binsh, ret).Ret(system))
```
> [!NOTE]
> `Pay`, `Flat` and `.Flat` pack a bare integer as 8 bytes. The older `.Add` packs an `int` as 4, so prefer `Flat`, `P64` or `Ret` for 64-bit addresses to avoid silently truncating them.

Leaking a stack canary or PIE base one byte at a time (brute-forced in parallel), the `NewExploit` reconnect flow, GDB attach, and cyclic-offset finding are shown end to end in `examples/process`. The leak helpers take a raw tube, so there you open the connection with `NewRemote` rather than the `Remote` wrapper.

## Bruteforcing and oracles
Recovering a value one character at a time (blind SQLi, a comparison endpoint, a reset-token check) always has the same shape: a `Bruteforcer` drives the loop and an *oracle* answers yes or no. There are two strategies, and the method names follow them.

- `Greater` with `BinarySearch`, when the oracle can compare (is byte > N). About 7 requests per character.
- `Equal` with `Scan`, when it can only test equality. One request per candidate, for a filtered target or a small known alphabet.

You build the oracle from how the payload is sent and what counts as success.
```go
greater := GreaterOracle(
	func(pos, value int) *Response { return conn.Get("/item", WithParam("id", q.Greater(pos, value))) },
	func(r *Response) bool { return r.Contains("found") },
)
password, _ := NewBruteforcer().BinarySearch(greater)
```
Set `bf.Workers` to race the charset concurrently and `bf.Delay` for a rate-limited target. `TimingAttack` covers the case where the only signal is how long a request takes. `examples/web` runs `CharOracle` with `Scan` against a live stub.

### Injection payloads
`SQLi` generates blind-extraction conditions in the right dialect, so you never hand-write `SUBSTRING`, `ASCII` or `LENGTH` or pick the wrong one.
```go
q := SQLi{Dialect: MySQL, Expr: "password", From: "users", Prefix: "1 AND ", Suffix: MySQL.Comment()}

q.Greater(pos, value)   // 1 AND ASCII(SUBSTRING((SELECT password FROM users),pos,1))>value--
q.Equal(pos, 'a')
q.LengthGreater(10)
```
Dialects are `MySQL`, `Postgres`, `SQLite`, `MSSQL` and `OracleDB`, and the conditions drop straight into the oracles above. To throw a list of known vectors at an endpoint, the catalog returns ready-made payloads for `Fuzz`: `AuthBypass`, `UnionNull`, `OrderBy` and `TimeDelay` for SQL, plus `CmdInjection`, `PathTraversal`, `SSTI`, `XSS` and `NoSQL`.

### Fuzzing
`Fuzz` runs a wordlist concurrently and keeps the responses that pass your filters.
```go
hits := Fuzz(func(w string) *Response { return conn.Get("/" + w) }, wordlist, MatchStatus(200, 301))
```
`MatchStatus`/`MatchLength`/`MatchRegex` keep a response, and the matching `Filter*` discard one (handy for hiding a known "not found" page). It runs 20 workers by default and returns hits in wordlist order.

## Scripting and automation
Interactive challenges are a connect-and-loop grind: read a prompt, compute an answer, send it, repeat, often behind a proof-of-work gate. `Expect` drives the loop and hands each round a `Round`.
```go
r := Remote("chal.ctf", 1337)
defer r.Close()

Expect(r, nil, 500, func(r *Round) {
	n := r.Ints()
	r.Send(n[0] + n[1])
})
```
A `Round` embeds a `Prompt` (`Int`/`Ints`/`BigInt`, `Hex`, `Base64`, `Match` and `Flag`). Reply with `r.Send(...)`, end the loop with `r.Stop()`, or do nothing to skip a round. For finer control, `NewLoop(r).Until("> ").Rounds(100).Timeout(30*time.Second).Run(fn)` sets the delimiter, a round cap and a real read deadline (a blocked read is interrupted instead of hanging the script).

Proof-of-work gates are solved in parallel.
```go
pow := PoWLeadingZeroBits([]byte(prefix), 24)   // redpwn style
r.SendLine(pow.Suffix)
```
Also `PoWLeadingZeroNibbles`, `PoWPrefixEquals`, `PoWSuffixEquals`, and `SolveHashPoW` for any predicate over the digest. When the gate is announced on the wire, `ClearPoW(r, pattern, bits)` reads the line, extracts the prefix, solves and sends in one call. `examples/scripting` is a complete solve, proof-of-work plus round loop, against a built-in stub.

## Magic: decode, identify, auto-solve
The magic helpers replace the CyberChef, hashid and `file` round-trip, offline.
```go
Magic(blob, WithFlagRegex(`flag\{[^}]*\}`))   // peel base64/hex/binary/rot/... layers, ranked best-first
Identify(blob)                                // hash type, encoding, file type, timestamp guesses
AutoSolve(ciphertext)                         // Caesar/XOR/Vigenere/rail-fence/substitution, ranked
```
Pass `WithFlagRegex` to `Magic` (or `WithSolveFlagRegex` to `AutoSolve`) so a known flag format ranks first, otherwise candidates are ranked by how English-like they read. The individual codecs (`B64Decode`, `HexDecode`, `BinaryDecode`, `ROT`, ...) are exported for direct use, as are the new `RailFenceCipher` and `SubstitutionDecrypt`. `examples/magic` runs all three end to end.
