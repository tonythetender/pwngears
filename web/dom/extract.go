package dom

import "regexp"

func (p *Page) HiddenInputs() map[string]string {
	out := map[string]string{}
	for _, in := range p.All("input[type=hidden]") {
		if name := in.Attr("name"); name != "" {
			out[name] = in.Attr("value")
		}
	}
	return out
}

func (p *Page) Scripts() []string {
	var out []string
	for _, s := range p.All("script") {
		if t := s.Text(); t != "" {
			out = append(out, t)
		}
	}
	return out
}

var jsVarPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?m)(?:var|let|const)\s+(\w+)\s*=\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?m)(?:var|let|const)\s+(\w+)\s*=\s*(\d+)`),
	regexp.MustCompile(`(?m)(\w+)\s*[:=]\s*["']([^"']+)["']`),
}

func (p *Page) JSVars() map[string]string {
	vars := map[string]string{}
	for _, script := range p.Scripts() {
		for _, re := range jsVarPatterns {
			for _, m := range re.FindAllStringSubmatch(script, -1) {
				if len(m) > 2 {
					if _, exists := vars[m[1]]; !exists {
						vars[m[1]] = m[2]
					}
				}
			}
		}
	}
	return vars
}

var endpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`["'](/api/[^"']+)["']`),
	regexp.MustCompile(`["'](/v\d+/[^"']+)["']`),
	regexp.MustCompile(`fetch\(["']([^"']+)["']`),
	regexp.MustCompile(`\.ajax\([^)]*url:\s*["']([^"']+)["']`),
	regexp.MustCompile(`open\([^,]+,\s*["']([^"']+)["']`),
}

func (p *Page) Endpoints() []string {
	content := p.HTML()
	for _, script := range p.Scripts() {
		content += "\n" + script
	}
	var out []string
	seen := map[string]bool{}
	for _, re := range endpointPatterns {
		for _, m := range re.FindAllStringSubmatch(content, -1) {
			if len(m) > 1 && !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	return out
}
