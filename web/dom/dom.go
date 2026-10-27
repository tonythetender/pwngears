package dom

import (
	"net/url"
	"strings"

	"github.com/tonythetender/pwngears/web"
	"golang.org/x/net/html"
)

type Conn interface {
	Get(path string, opts ...web.RequestOption) *web.Response
	Post(path string, data url.Values, opts ...web.RequestOption) *web.Response
	BaseURL() string
}

type Page struct {
	conn Conn
	url  *url.URL
	root *html.Node
	Resp *web.Response
}

type Node struct {
	page *Page
	n    *html.Node
}

func Fetch(conn Conn, path string, opts ...web.RequestOption) *Page {
	resp := conn.Get(path, opts...)
	return pageFrom(conn, resolve(conn.BaseURL(), path), resp)
}

func Parse(conn Conn, resp *web.Response) *Page {
	return pageFrom(conn, resolve(conn.BaseURL(), ""), resp)
}

func pageFrom(conn Conn, abs *url.URL, resp *web.Response) *Page {
	root, _ := html.Parse(strings.NewReader(resp.Text()))
	return &Page{conn: conn, url: abs, root: root, Resp: resp}
}

func resolve(base, ref string) *url.URL {
	b, err := url.Parse(base)
	if err != nil {
		b = nil
	}
	r, err := url.Parse(ref)
	if err != nil || r == nil {
		return b
	}
	if b == nil {
		return r
	}
	return b.ResolveReference(r)
}

func (p *Page) All(sel string) []*Node {
	nodes := selectAll(p.root, parseSelector(sel))
	out := make([]*Node, len(nodes))
	for i, n := range nodes {
		out[i] = &Node{page: p, n: n}
	}
	return out
}

func (p *Page) First(sel string) *Node {
	nodes := selectAll(p.root, parseSelector(sel))
	if len(nodes) == 0 {
		return nil
	}
	return &Node{page: p, n: nodes[0]}
}

func (p *Page) Text() string { return nodeText(p.root) }

func (p *Page) HTML() string {
	if p.Resp == nil {
		return ""
	}
	return p.Resp.Text()
}

func (p *Page) URL() string {
	if p.url == nil {
		return ""
	}
	return p.url.String()
}

func (p *Page) Links() []string {
	var out []string
	for _, a := range p.All("a[href]") {
		ref, err := url.Parse(a.Attr("href"))
		if err != nil {
			continue
		}
		out = append(out, p.url.ResolveReference(ref).String())
	}
	return out
}

func (p *Page) Attrs(sel, attr string) []string {
	var out []string
	for _, n := range p.All(sel) {
		if v, ok := getAttrOK(n.n, attr); ok {
			out = append(out, v)
		}
	}
	return out
}

func (p *Page) Texts(sel string) []string {
	var out []string
	for _, n := range p.All(sel) {
		out = append(out, n.Text())
	}
	return out
}

func (p *Page) Flag(prefix string) string {
	if p.Resp == nil {
		return ""
	}
	return p.Resp.Flag(prefix)
}

func (p *Page) Follow(sel string, opts ...web.RequestOption) *Page {
	nd := p.First(sel)
	if nd == nil {
		return nil
	}
	return nd.Follow(opts...)
}

func (nd *Node) Attr(key string) string {
	if nd == nil || nd.n == nil {
		return ""
	}
	return getAttr(nd.n, key)
}

func (nd *Node) HasAttr(key string) bool {
	if nd == nil || nd.n == nil {
		return false
	}
	_, ok := getAttrOK(nd.n, key)
	return ok
}

func (nd *Node) Text() string {
	if nd == nil || nd.n == nil {
		return ""
	}
	return nodeText(nd.n)
}

func (nd *Node) HTML() string {
	if nd == nil || nd.n == nil {
		return ""
	}
	return innerHTML(nd.n)
}

func (nd *Node) Tag() string {
	if nd == nil || nd.n == nil {
		return ""
	}
	return nd.n.Data
}

func (nd *Node) HasClass(class string) bool {
	return contains(strings.Fields(nd.Attr("class")), class)
}

func (nd *Node) Find(sel string) []*Node {
	if nd == nil || nd.n == nil {
		return nil
	}
	nodes := selectAll(nd.n, parseSelector(sel))
	out := make([]*Node, len(nodes))
	for i, n := range nodes {
		out[i] = &Node{page: nd.page, n: n}
	}
	return out
}

func (nd *Node) First(sel string) *Node {
	all := nd.Find(sel)
	if len(all) == 0 {
		return nil
	}
	return all[0]
}

func (nd *Node) Parent() *Node {
	if nd == nil || nd.n == nil || nd.n.Parent == nil {
		return nil
	}
	return &Node{page: nd.page, n: nd.n.Parent}
}

func (nd *Node) Follow(opts ...web.RequestOption) *Page {
	if nd == nil {
		return nil
	}
	href := nd.Attr("href")
	if href == "" {
		return nil
	}
	return nd.page.fetchURL(href, opts...)
}

func (p *Page) fetchURL(ref string, opts ...web.RequestOption) *Page {
	r, err := url.Parse(ref)
	if err != nil {
		return nil
	}
	target := p.url.ResolveReference(r)
	base := resolve(p.conn.BaseURL(), "")
	if sameOrigin(base, target) {
		resp := p.conn.Get(originPath(target), opts...)
		return pageFrom(p.conn, target, resp)
	}
	resp := web.Get(target.String(), opts...)
	return pageFrom(p.conn, target, resp)
}

func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func originPath(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return path
}

func getAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

func getAttrOK(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val, true
		}
	}
	return "", false
}

func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.TrimSpace(b.String())
}

func innerHTML(n *html.Node) string {
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		html.Render(&b, c)
	}
	return b.String()
}

func firstTag(root *html.Node, tag string) *html.Node {
	var found *html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if found != nil {
			return
		}
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, tag) {
			found = n
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return found
}

func formAncestor(n *html.Node) *html.Node {
	for cur := n; cur != nil; cur = cur.Parent {
		if cur.Type == html.ElementNode && strings.EqualFold(cur.Data, "form") {
			return cur
		}
	}
	return nil
}
