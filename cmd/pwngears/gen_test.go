package main

import (
	"go/format"
	"strings"
	"testing"
)

// TestTemplatesParse checks that every scaffold template is syntactically valid
// Go and imports the single root package.
func TestTemplatesParse(t *testing.T) {
	for _, cat := range categories {
		cfg := config{name: "solve", category: cat, target: "127.0.0.1:1337"}
		src := source(cfg)
		if _, err := format.Source([]byte(src)); err != nil {
			t.Errorf("%s template does not parse: %v\n%s", cat, err, src)
			continue
		}
		if !strings.Contains(src, `. "github.com/tonythetender/pwngears"`+"\n") {
			t.Errorf("%s template does not use the single root import", cat)
		}
	}
}
