# pwngears scaffolder

A small TUI that scaffolds a solve script for a CTF challenge with the imports and boilerplate already set up, and pulls in the latest tagged release of pwngears.

It lives in its own module so the core library stays dependency-free. Only this tool depends on [charmbracelet/huh](https://github.com/charmbracelet/huh).

## Install

```sh
go install github.com/tonythetender/pwngears/cmd/pwngears@latest
```

`@latest` resolves against this submodule's own tags (`cmd/pwngears/vX.Y.Z`), not the repository's root tags. Before such a tag exists you can still install from a branch or commit:

```sh
go install github.com/tonythetender/pwngears/cmd/pwngears@main
```

Or build it from a clone:

```sh
git clone https://github.com/tonythetender/pwngears
cd pwngears/cmd/pwngears && go build .
```

## Usage

Run it with no arguments for the interactive form:

```sh
pwngears
```

It asks for the category (pwn, web, crypto, reverse, misc), a name, where to put it (a new subfolder or the current directory), and an optional target.

A new subfolder initialises its own Go module. The current directory reuses an existing `go.mod` or creates one. Either way it runs `go get github.com/tonythetender/pwngears@latest` and `go mod tidy`.

Every field can be supplied as a flag, and `-yes` skips the form entirely:

```sh
pwngears -yes -cat pwn -name heap-overflow -target 127.0.0.1:1337
pwngears -yes -cat web -name admin-panel -target https://chal.ctf -here
```

| Flag | Meaning |
|------|---------|
| `-cat` | category: pwn, web, crypto, reverse, misc |
| `-name` | challenge name (folder and module name for a new subfolder) |
| `-target` | `./binary`, `host:port`, or a URL |
| `-here` | scaffold in the current directory instead of a new subfolder |
| `-yes` | skip the interactive form and use flags and defaults |

For a pwn or reverse target, a `host:port` becomes a `Remote(...)` connection and anything else a `Process(...)`. A web target becomes the base URL of the connection.
