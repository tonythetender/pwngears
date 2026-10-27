package dom

import (
	"strings"

	"golang.org/x/net/html"
)

type attrMatch struct {
	key string
	val string
	has bool
}

type simpleSelector struct {
	tag     string
	id      string
	classes []string
	attrs   []attrMatch
}

type selector struct {
	steps []simpleSelector
}

func parseSelector(s string) selector {
	var sel selector
	for _, f := range strings.Fields(s) {
		sel.steps = append(sel.steps, parseSimple(f))
	}
	return sel
}

func parseSimple(s string) simpleSelector {
	var ss simpleSelector
	i := 0
	readTo := func() string {
		start := i
		for i < len(s) && s[i] != '.' && s[i] != '#' && s[i] != '[' {
			i++
		}
		return s[start:i]
	}
	if i < len(s) && s[i] != '.' && s[i] != '#' && s[i] != '[' {
		ss.tag = readTo()
	}
	for i < len(s) {
		switch s[i] {
		case '.':
			i++
			ss.classes = append(ss.classes, readTo())
		case '#':
			i++
			ss.id = readTo()
		case '[':
			i++
			start := i
			for i < len(s) && s[i] != ']' {
				i++
			}
			expr := s[start:i]
			if i < len(s) {
				i++
			}
			var am attrMatch
			if eq := strings.Index(expr, "="); eq >= 0 {
				am.key = strings.TrimSpace(expr[:eq])
				am.val = strings.Trim(strings.TrimSpace(expr[eq+1:]), `"'`)
				am.has = true
			} else {
				am.key = strings.TrimSpace(expr)
			}
			ss.attrs = append(ss.attrs, am)
		default:
			i++
		}
	}
	return ss
}

func (ss simpleSelector) match(n *html.Node) bool {
	if n.Type != html.ElementNode {
		return false
	}
	if ss.tag != "" && ss.tag != "*" && !strings.EqualFold(n.Data, ss.tag) {
		return false
	}
	if ss.id != "" && getAttr(n, "id") != ss.id {
		return false
	}
	if len(ss.classes) > 0 {
		have := strings.Fields(getAttr(n, "class"))
		for _, want := range ss.classes {
			if !contains(have, want) {
				return false
			}
		}
	}
	for _, am := range ss.attrs {
		v, ok := getAttrOK(n, am.key)
		if !ok {
			return false
		}
		if am.has && v != am.val {
			return false
		}
	}
	return true
}

func matchChain(n *html.Node, steps []simpleSelector) bool {
	last := len(steps) - 1
	if !steps[last].match(n) {
		return false
	}
	si := last - 1
	cur := n.Parent
	for si >= 0 && cur != nil {
		if steps[si].match(cur) {
			si--
		}
		cur = cur.Parent
	}
	return si < 0
}

func selectAll(root *html.Node, sel selector) []*html.Node {
	if len(sel.steps) == 0 {
		return nil
	}
	var out []*html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && matchChain(n, sel.steps) {
			out = append(out, n)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
