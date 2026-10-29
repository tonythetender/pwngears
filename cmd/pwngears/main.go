package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
)

type config struct {
	name     string
	category string
	location string
	target   string
}

var categories = []string{"pwn", "web", "crypto", "reverse", "scripting", "misc"}

func main() {
	flagName := flag.String("name", "", "challenge name")
	flagCat := flag.String("cat", "", "category: pwn, web, crypto, reverse, misc")
	flagTarget := flag.String("target", "", "target: ./binary, host:port, or URL")
	flagHere := flag.Bool("here", false, "scaffold in the current directory instead of a new subfolder")
	flagYes := flag.Bool("yes", false, "skip the interactive form and use flags and defaults")
	flag.Parse()

	cfg := config{
		name:     *flagName,
		category: *flagCat,
		target:   *flagTarget,
		location: "new",
	}
	if *flagHere {
		cfg.location = "here"
	}

	if !*flagYes {
		if err := runForm(&cfg); err != nil {
			fmt.Fprintln(os.Stderr, "cancelled:", err)
			os.Exit(1)
		}
	}

	if cfg.category == "" {
		cfg.category = "pwn"
	}
	if !validCategory(cfg.category) {
		fmt.Fprintf(os.Stderr, "unknown category %q (want one of: %s)\n", cfg.category, strings.Join(categories, ", "))
		os.Exit(1)
	}

	if err := generate(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runForm(cfg *config) error {
	if cfg.name == "" {
		cfg.name = "solve"
	}
	if cfg.category == "" {
		cfg.category = "pwn"
	}
	if cfg.location == "" {
		cfg.location = "new"
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Category").
				Options(
					huh.NewOption("pwn (binary exploitation)", "pwn"),
					huh.NewOption("web", "web"),
					huh.NewOption("crypto", "crypto"),
					huh.NewOption("reverse", "reverse"),
					huh.NewOption("scripting (interactive / PoW)", "scripting"),
					huh.NewOption("misc", "misc"),
				).
				Value(&cfg.category),
			huh.NewInput().
				Title("Name").
				Value(&cfg.name),
			huh.NewSelect[string]().
				Title("Location").
				Options(
					huh.NewOption("New subfolder", "new"),
					huh.NewOption("Current directory", "here"),
				).
				Value(&cfg.location),
			huh.NewInput().
				Title("Target (optional)").
				DescriptionFunc(func() string { return targetHint(cfg.category) }, &cfg.category).
				PlaceholderFunc(func() string { return targetPlaceholder(cfg.category) }, &cfg.category).
				Value(&cfg.target),
		),
	)
	return form.Run()
}

func generate(cfg config) error {
	dir := "."
	if cfg.location == "new" {
		dir = folderName(cfg.name)
		if _, err := os.Stat(dir); err == nil {
			return fmt.Errorf("directory %q already exists", dir)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	if _, err := os.Stat(filepath.Join(dir, "go.mod")); errors.Is(err, os.ErrNotExist) {
		if err := run(dir, "go", "mod", "init", moduleName(cfg, dir)); err != nil {
			return err
		}
	}

	file := filepath.Join(dir, "main.go")
	if _, err := os.Stat(file); err == nil {
		file = filepath.Join(dir, folderName(cfg.name)+".go")
		if _, err := os.Stat(file); err == nil {
			return fmt.Errorf("%s already exists", file)
		}
	}
	if err := os.WriteFile(file, []byte(source(cfg)), 0o644); err != nil {
		return err
	}

	if err := run(dir, "go", "get", "github.com/tonythetender/pwngears@latest"); err != nil {
		return err
	}
	if err := run(dir, "go", "mod", "tidy"); err != nil {
		return err
	}

	fmt.Printf("\nScaffolded %s challenge in %s\n", cfg.category, filepath.Clean(dir))
	fmt.Printf("  cd %s && go run %s\n", filepath.Clean(dir), filepath.Base(file))
	return nil
}

func run(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func validCategory(c string) bool {
	for _, v := range categories {
		if v == c {
			return true
		}
	}
	return false
}

func folderName(name string) string {
	n := strings.TrimSpace(name)
	if n == "" {
		n = "solve"
	}
	return strings.ReplaceAll(n, " ", "-")
}

func moduleName(cfg config, dir string) string {
	if cfg.location == "new" {
		return folderName(cfg.name)
	}
	abs, err := filepath.Abs(dir)
	if err != nil || filepath.Base(abs) == "" {
		return "solve"
	}
	return filepath.Base(abs)
}

func source(cfg config) string {
	switch cfg.category {
	case "web":
		url := strings.TrimSpace(cfg.target)
		if url == "" {
			url = "http://localhost:8000"
		}
		return fmt.Sprintf(`package main

import (
	"fmt"
	"regexp"

	. "github.com/tonythetender/pwngears"
)

// Adjust to the challenge's flag format.
var flagRe = regexp.MustCompile(`+"`"+`FLAG\{[^}]*\}`+"`"+`)

func main() {
	conn := Conn(%q)

	// To parse the HTML (select elements, submit a form with its hidden fields),
	// the DOM helpers are in this same import:
	//   page := Fetch(conn, "/")
	//   page.Form("#login").Set("user", "admin").Submit()

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
`, url)

	case "crypto":
		return `package main

import (
	"fmt"

	. "github.com/tonythetender/pwngears"
)

func main() {
	engine := NewCryptoEngine()

	// Replace with the challenge ciphertext.
	ciphertext := []byte{}

	results := engine.BruteForce(XORCipher{}, ciphertext,
		WithMaxKeyLength(8),
		WithPatternPrefix("FLAG{"),
		WithPatternSuffix("}"),
	)
	for _, r := range results {
		fmt.Printf("[%s] key=%q\n%s\n", r.Cipher, r.Key, r.Plaintext)
	}
	if len(results) == 0 {
		fmt.Println("no key produced a matching plaintext")
	}
}
`

	case "misc":
		return `package main

import (
	"fmt"
	"regexp"

	. "github.com/tonythetender/pwngears"
)

// Adjust to the challenge's flag format.
var flagRe = regexp.MustCompile(` + "`" + `FLAG\{[^}]*\}` + "`" + `)

func main() {
	Info("solve")

	// Put whatever output you collect here, then grep it for the flag.
	data := ""
	if m := flagRe.FindString(data); m != "" {
		Success("flag: " + m)
	} else {
		fmt.Println("no flag found yet")
	}
}
`

	case "scripting":
		return fmt.Sprintf(`package main

import (
	"fmt"

	. "github.com/tonythetender/pwngears"
)

func main() {
	r := %s
	defer r.Close()

	// If the service gates on a proof of work, clear it first. Adjust the
	// pattern and difficulty to the challenge:
	//   ClearPoW(r, "prefix=(?P<prefix>\w+)", 24)

	// Read each prompt, compute an answer, send it, and stop at the flag.
	Expect(r, nil, 0, func(rd *Round) {
		if f := rd.Flag("FLAG"); f != "" {
			fmt.Println("flag:", f)
			rd.Stop()
			return
		}
		n := rd.Ints()
		if len(n) >= 2 {
			rd.Send(n[0] + n[1])
		}
	})
}
`, pwnConn(cfg.target))

	default: // pwn, reverse
		return fmt.Sprintf(`package main

import (
	"fmt"
	"regexp"
	"time"

	. "github.com/tonythetender/pwngears"
)

// Adjust to the challenge's flag format.
var flagRe = regexp.MustCompile(`+"`"+`FLAG\{[^}]*\}`+"`"+`)

func main() {
	p := %s
	defer p.Close()

	// Common primitives:
	//   p.SendLineAfter("Name: ", "pwner")
	//   line, _ := p.RecvLine()
	//   p.Send(Pay().PadTo(40).P64(0xdeadbeef).Bytes())

	out, _ := p.RecvAllString(2 * time.Second)
	fmt.Print(out)

	if m := flagRe.FindString(out); m != "" {
		Success("flag: " + m)
	}
}
`, pwnConn(cfg.target))
	}
}

func targetHint(category string) string {
	switch category {
	case "web":
		return "Base URL of the challenge"
	case "crypto", "misc":
		return "Not used for this category"
	default:
		return "A local ./binary or a remote host:port"
	}
}

func targetPlaceholder(category string) string {
	switch category {
	case "web":
		return "https://chal.example.com"
	case "crypto", "misc":
		return ""
	default:
		return "127.0.0.1:1337"
	}
}

func pwnConn(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return `Process("./chal")`
	}
	if i := strings.LastIndex(t, ":"); i > 0 && !strings.Contains(t, "/") {
		if _, err := strconv.Atoi(t[i+1:]); err == nil {
			return fmt.Sprintf("Remote(%q, %s)", t[:i], t[i+1:])
		}
	}
	return fmt.Sprintf("Process(%q)", t)
}
