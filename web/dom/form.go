package dom

import (
	"net/url"
	"strings"

	"github.com/tonythetender/pwngears/web"
	"golang.org/x/net/html"
)

type Form struct {
	page   *Page
	node   *html.Node
	action *url.URL
	method string
	Values url.Values
}

func (p *Page) Form(sel string) *Form {
	var fn *html.Node
	if strings.TrimSpace(sel) == "" {
		fn = firstTag(p.root, "form")
	} else {
		for _, n := range selectAll(p.root, parseSelector(sel)) {
			if f := formForNode(n); f != nil {
				fn = f
				break
			}
		}
	}
	if fn == nil {
		return nil
	}

	f := &Form{page: p, node: fn, method: "GET", Values: url.Values{}}
	if m := getAttr(fn, "method"); m != "" {
		f.method = strings.ToUpper(m)
	}
	ref, _ := url.Parse(getAttr(fn, "action"))
	f.action = p.url.ResolveReference(ref)
	collectFields(fn, f.Values)
	return f
}

func formForNode(n *html.Node) *html.Node {
	if strings.EqualFold(n.Data, "form") {
		return n
	}
	return formAncestor(n)
}

func (f *Form) Set(key, value string) *Form {
	f.Values.Set(key, value)
	return f
}

func (f *Form) Get(key string) string {
	return f.Values.Get(key)
}

func (f *Form) Submit(opts ...web.RequestOption) *Page {
	base := resolve(f.page.conn.BaseURL(), "")

	if f.method == "POST" {
		if sameOrigin(base, f.action) {
			resp := f.page.conn.Post(originPathNoQuery(f.action), f.Values, opts...)
			return pageFrom(f.page.conn, f.action, resp)
		}
		resp := web.Post(f.action.String(), f.Values, opts...)
		return pageFrom(f.page.conn, f.action, resp)
	}

	target := *f.action
	q := target.Query()
	for k, vs := range f.Values {
		for i, v := range vs {
			if i == 0 {
				q.Set(k, v)
			} else {
				q.Add(k, v)
			}
		}
	}
	target.RawQuery = q.Encode()
	if sameOrigin(base, &target) {
		resp := f.page.conn.Get(originPath(&target), opts...)
		return pageFrom(f.page.conn, &target, resp)
	}
	resp := web.Get(target.String(), opts...)
	return pageFrom(f.page.conn, &target, resp)
}

func originPathNoQuery(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return path
}

func collectFields(form *html.Node, vals url.Values) {
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch strings.ToLower(n.Data) {
			case "input":
				if name := getAttr(n, "name"); name != "" {
					switch strings.ToLower(getAttr(n, "type")) {
					case "checkbox", "radio":
						if _, checked := getAttrOK(n, "checked"); checked {
							vals.Set(name, getAttr(n, "value"))
						}
					case "submit", "button", "image", "reset", "file":
					default:
						vals.Set(name, getAttr(n, "value"))
					}
				}
			case "textarea":
				if name := getAttr(n, "name"); name != "" {
					vals.Set(name, nodeText(n))
				}
			case "select":
				if name := getAttr(n, "name"); name != "" {
					vals.Set(name, selectedOption(n))
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(form)
}

func selectedOption(sel *html.Node) string {
	var first, chosen string
	seenFirst := false
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "option") {
			v, ok := getAttrOK(n, "value")
			if !ok {
				v = nodeText(n)
			}
			if !seenFirst {
				first = v
				seenFirst = true
			}
			if _, isSel := getAttrOK(n, "selected"); isSel {
				chosen = v
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(sel)
	if chosen != "" {
		return chosen
	}
	return first
}
