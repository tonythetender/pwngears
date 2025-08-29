package web

import (
	"fmt"
	"regexp"
	"strings"
)

// ScrapedContent holds the parsed content from a web page
type ScrapedContent struct {
	Raw        string
	HTML       string
	Scripts    []string
	Styles     []string
	Links      []string
	Images     []string
	Forms      []Form
	Comments   []string
	Meta       map[string]string
	Title      string
	Headers    map[string][]string
	Attributes map[string][]string
}

// Form represents an HTML form
type Form struct {
	Action string
	Method string
	Inputs []Input
	Raw    string
}

// Input represents a form input field
type Input struct {
	Type        string
	Name        string
	Value       string
	Placeholder string
	ID          string
}

// Element represents a simple HTML element
type Element struct {
	Tag        string
	Attributes map[string]string
	Content    string
	InnerHTML  string
}

// ScrapeOptions allows customization of scraping behavior
type ScrapeOptions struct {
	IncludeComments bool
	IncludeScripts  bool
	IncludeStyles   bool
	CaseSensitive   bool
	ExtractForms    bool
	ExtractMeta     bool
	CustomPatterns  map[string]*regexp.Regexp
}

// ScrapeOption is a function that modifies ScrapeOptions
type ScrapeOption func(*ScrapeOptions)

// WithComments includes HTML comments in the scraped content
func WithComments() ScrapeOption {
	return func(o *ScrapeOptions) {
		o.IncludeComments = true
	}
}

// WithScripts includes script content
func WithScripts() ScrapeOption {
	return func(o *ScrapeOptions) {
		o.IncludeScripts = true
	}
}

// WithStyles includes style content
func WithStyles() ScrapeOption {
	return func(o *ScrapeOptions) {
		o.IncludeStyles = true
	}
}

// WithForms extracts form data
func WithForms() ScrapeOption {
	return func(o *ScrapeOptions) {
		o.ExtractForms = true
	}
}

// WithMeta extracts meta tags
func WithMeta() ScrapeOption {
	return func(o *ScrapeOptions) {
		o.ExtractMeta = true
	}
}

// WithCustomPattern adds a custom regex pattern to extract
func WithCustomPattern(name string, pattern string) ScrapeOption {
	return func(o *ScrapeOptions) {
		if o.CustomPatterns == nil {
			o.CustomPatterns = make(map[string]*regexp.Regexp)
		}
		if re, err := regexp.Compile(pattern); err == nil {
			o.CustomPatterns[name] = re
		}
	}
}

// Scrape performs web scraping on the response from a GET/POST request
func (c *Client) Scrape(path string, opts ...ScrapeOption) (*ScrapedContent, error) {
	resp, err := c.Get(path)
	if err != nil {
		return nil, err
	}
	return c.ScrapeResponse(resp, opts...)
}

// ScrapeResponse scrapes content from an existing Response
func (c *Client) ScrapeResponse(resp *Response, opts ...ScrapeOption) (*ScrapedContent, error) {
	options := &ScrapeOptions{
		IncludeComments: true,
		IncludeScripts:  true,
		IncludeStyles:   true,
		ExtractForms:    true,
		ExtractMeta:     true,
	}

	for _, opt := range opts {
		opt(options)
	}

	content := string(resp.Body)
	scraped := &ScrapedContent{
		Raw:        content,
		HTML:       content,
		Scripts:    []string{},
		Styles:     []string{},
		Links:      []string{},
		Images:     []string{},
		Forms:      []Form{},
		Comments:   []string{},
		Meta:       make(map[string]string),
		Headers:    make(map[string][]string),
		Attributes: make(map[string][]string),
	}

	scraped.extractScripts(content, options)
	scraped.extractStyles(content, options)
	scraped.extractLinks(content)
	scraped.extractImages(content)
	scraped.extractComments(content, options)
	scraped.extractTitle(content)
	scraped.extractHeaders(content)
	scraped.extractMeta(content, options)
	scraped.extractForms(content, options)
	scraped.extractAllAttributes(content)

	return scraped, nil
}

// FindAll finds all occurrences of a string
func (s *ScrapedContent) FindAll(search string) []string {
	var results []string
	content := strings.ToLower(s.Raw)
	search = strings.ToLower(search)

	index := 0
	for {
		pos := strings.Index(content[index:], search)
		if pos == -1 {
			break
		}

		start := index + pos
		end := start + len(search)

		contextStart := start - 50
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := end + 50
		if contextEnd > len(s.Raw) {
			contextEnd = len(s.Raw)
		}

		results = append(results, s.Raw[contextStart:contextEnd])
		index = start + 1
	}

	return results
}

// FindAllRegex finds all matches for a regex pattern
func (s *ScrapedContent) FindAllRegex(pattern string) ([]string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	matches := re.FindAllString(s.Raw, -1)
	return matches, nil
}

// Select simulates a simple CSS selector (supports tag, class, id)
func (s *ScrapedContent) Select(selector string) []Element {
	var elements []Element

	if strings.HasPrefix(selector, "#") {
		id := selector[1:]
		elements = s.findByID(id)
	} else if strings.HasPrefix(selector, ".") {
		class := selector[1:]
		elements = s.findByClass(class)
	} else {
		elements = s.findByTag(selector)
	}

	return elements
}

// GetAttribute gets all values for a specific attribute
func (s *ScrapedContent) GetAttribute(attrName string) []string {
	if values, exists := s.Attributes[attrName]; exists {
		return values
	}
	return []string{}
}

// GetInputsByName finds all inputs with a specific name
func (s *ScrapedContent) GetInputsByName(name string) []Input {
	var inputs []Input
	for _, form := range s.Forms {
		for _, input := range form.Inputs {
			if input.Name == name {
				inputs = append(inputs, input)
			}
		}
	}
	return inputs
}

// GetFormByAction finds a form by its action attribute
func (s *ScrapedContent) GetFormByAction(action string) *Form {
	for _, form := range s.Forms {
		if strings.Contains(form.Action, action) {
			return &form
		}
	}
	return nil
}

func (s *ScrapedContent) extractScripts(content string, options *ScrapeOptions) {
	if !options.IncludeScripts {
		return
	}

	scriptRe := regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)
	matches := scriptRe.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 && strings.TrimSpace(match[1]) != "" {
			s.Scripts = append(s.Scripts, strings.TrimSpace(match[1]))
		}
	}

	srcRe := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	srcMatches := srcRe.FindAllStringSubmatch(content, -1)
	for _, match := range srcMatches {
		if len(match) > 1 {
			s.Scripts = append(s.Scripts, "// External: "+match[1])
		}
	}
}

func (s *ScrapedContent) extractStyles(content string, options *ScrapeOptions) {
	if !options.IncludeStyles {
		return
	}

	styleRe := regexp.MustCompile(`(?is)<style[^>]*>(.*?)</style>`)
	matches := styleRe.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 && strings.TrimSpace(match[1]) != "" {
			s.Styles = append(s.Styles, strings.TrimSpace(match[1]))
		}
	}

	linkRe := regexp.MustCompile(`(?i)<link[^>]+rel=["']stylesheet["'][^>]+href=["']([^"']+)["']`)
	linkMatches := linkRe.FindAllStringSubmatch(content, -1)
	for _, match := range linkMatches {
		if len(match) > 1 {
			s.Styles = append(s.Styles, "/* External: "+match[1]+" */")
		}
	}
}

func (s *ScrapedContent) extractLinks(content string) {
	hrefRe := regexp.MustCompile(`(?i)href=["']([^"']+)["']`)
	matches := hrefRe.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] {
			s.Links = append(s.Links, match[1])
			seen[match[1]] = true
		}
	}
}

func (s *ScrapedContent) extractImages(content string) {
	imgRe := regexp.MustCompile(`(?i)<img[^>]+src=["']([^"']+)["']`)
	matches := imgRe.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] {
			s.Images = append(s.Images, match[1])
			seen[match[1]] = true
		}
	}
}

func (s *ScrapedContent) extractComments(content string, options *ScrapeOptions) {
	if !options.IncludeComments {
		return
	}

	commentRe := regexp.MustCompile(`<!--(.*?)-->`)
	matches := commentRe.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			comment := strings.TrimSpace(match[1])
			if comment != "" {
				s.Comments = append(s.Comments, comment)
			}
		}
	}
}

func (s *ScrapedContent) extractTitle(content string) {
	titleRe := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	match := titleRe.FindStringSubmatch(content)
	if len(match) > 1 {
		s.Title = strings.TrimSpace(match[1])
	}
}

func (s *ScrapedContent) extractHeaders(content string) {
	for i := 1; i <= 6; i++ {
		tag := fmt.Sprintf("h%d", i)
		headerRe := regexp.MustCompile(fmt.Sprintf(`(?i)<%s[^>]*>(.*?)</%s>`, tag, tag))
		matches := headerRe.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				text := stripTags(match[1])
				if text != "" {
					s.Headers[tag] = append(s.Headers[tag], strings.TrimSpace(text))
				}
			}
		}
	}
}

func (s *ScrapedContent) extractMeta(content string, options *ScrapeOptions) {
	if !options.ExtractMeta {
		return
	}

	metaRe := regexp.MustCompile(`(?i)<meta[^>]+>`)
	matches := metaRe.FindAllString(content, -1)

	for _, match := range matches {
		nameRe := regexp.MustCompile(`(?i)name=["']([^"']+)["']`)
		contentRe := regexp.MustCompile(`(?i)content=["']([^"']+)["']`)

		nameMatch := nameRe.FindStringSubmatch(match)
		contentMatch := contentRe.FindStringSubmatch(match)

		if len(nameMatch) > 1 && len(contentMatch) > 1 {
			s.Meta[nameMatch[1]] = contentMatch[1]
		}

		propRe := regexp.MustCompile(`(?i)property=["']([^"']+)["']`)
		propMatch := propRe.FindStringSubmatch(match)
		if len(propMatch) > 1 && len(contentMatch) > 1 {
			s.Meta[propMatch[1]] = contentMatch[1]
		}
	}
}

func (s *ScrapedContent) extractForms(content string, options *ScrapeOptions) {
	if !options.ExtractForms {
		return
	}

	formRe := regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	matches := formRe.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			form := Form{
				Raw:    match[0],
				Inputs: []Input{},
			}

			actionRe := regexp.MustCompile(`(?i)action=["']([^"']+)["']`)
			methodRe := regexp.MustCompile(`(?i)method=["']([^"']+)["']`)

			if actionMatch := actionRe.FindStringSubmatch(match[0]); len(actionMatch) > 1 {
				form.Action = actionMatch[1]
			}
			if methodMatch := methodRe.FindStringSubmatch(match[0]); len(methodMatch) > 1 {
				form.Method = strings.ToUpper(methodMatch[1])
			}

			inputRe := regexp.MustCompile(`(?i)<input[^>]+>`)
			inputMatches := inputRe.FindAllString(match[1], -1)

			for _, inputMatch := range inputMatches {
				input := extractInputAttributes(inputMatch)
				form.Inputs = append(form.Inputs, input)
			}

			textareaRe := regexp.MustCompile(`(?i)<textarea[^>]+name=["']([^"']+)["'][^>]*>`)
			textareaMatches := textareaRe.FindAllStringSubmatch(match[1], -1)
			for _, tm := range textareaMatches {
				if len(tm) > 1 {
					form.Inputs = append(form.Inputs, Input{
						Type: "textarea",
						Name: tm[1],
					})
				}
			}

			selectRe := regexp.MustCompile(`(?i)<select[^>]+name=["']([^"']+)["'][^>]*>`)
			selectMatches := selectRe.FindAllStringSubmatch(match[1], -1)
			for _, sm := range selectMatches {
				if len(sm) > 1 {
					form.Inputs = append(form.Inputs, Input{
						Type: "select",
						Name: sm[1],
					})
				}
			}

			s.Forms = append(s.Forms, form)
		}
	}
}

func (s *ScrapedContent) extractAllAttributes(content string) {
	attrRe := regexp.MustCompile(`(?i)(\w+)=["']([^"']+)["']`)
	matches := attrRe.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 2 {
			attrName := strings.ToLower(match[1])
			attrValue := match[2]

			found := false
			for _, existing := range s.Attributes[attrName] {
				if existing == attrValue {
					found = true
					break
				}
			}

			if !found {
				s.Attributes[attrName] = append(s.Attributes[attrName], attrValue)
			}
		}
	}
}

func (s *ScrapedContent) findByID(id string) []Element {
	var elements []Element

	pattern := fmt.Sprintf(`(?i)<(\w+)[^>]*id=["']%s["'][^>]*>(.*?)</\1>`, regexp.QuoteMeta(id))
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(s.Raw, -1)

	for _, match := range matches {
		if len(match) > 2 {
			elem := Element{
				Tag:        match[1],
				Content:    stripTags(match[2]),
				InnerHTML:  match[2],
				Attributes: extractAttributes(match[0]),
			}
			elements = append(elements, elem)
		}
	}

	return elements
}

func (s *ScrapedContent) findByClass(class string) []Element {
	var elements []Element

	pattern := fmt.Sprintf(`(?i)<(\w+)[^>]*class=["'][^"']*\b%s\b[^"']*["'][^>]*>(.*?)</\1>`, regexp.QuoteMeta(class))
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(s.Raw, -1)

	for _, match := range matches {
		if len(match) > 2 {
			elem := Element{
				Tag:        match[1],
				Content:    stripTags(match[2]),
				InnerHTML:  match[2],
				Attributes: extractAttributes(match[0]),
			}
			elements = append(elements, elem)
		}
	}

	return elements
}

func (s *ScrapedContent) findByTag(tag string) []Element {
	var elements []Element

	pattern := fmt.Sprintf(`(?i)<%s[^>]*>(.*?)</%s>`, regexp.QuoteMeta(tag), regexp.QuoteMeta(tag))
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(s.Raw, -1)

	for _, match := range matches {
		if len(match) > 1 {
			elem := Element{
				Tag:        tag,
				Content:    stripTags(match[1]),
				InnerHTML:  match[1],
				Attributes: extractAttributes(match[0]),
			}
			elements = append(elements, elem)
		}
	}

	return elements
}

func extractInputAttributes(input string) Input {
	result := Input{}

	typeRe := regexp.MustCompile(`(?i)type=["']([^"']+)["']`)
	nameRe := regexp.MustCompile(`(?i)name=["']([^"']+)["']`)
	valueRe := regexp.MustCompile(`(?i)value=["']([^"']+)["']`)
	placeholderRe := regexp.MustCompile(`(?i)placeholder=["']([^"']+)["']`)
	idRe := regexp.MustCompile(`(?i)id=["']([^"']+)["']`)

	if match := typeRe.FindStringSubmatch(input); len(match) > 1 {
		result.Type = match[1]
	}
	if match := nameRe.FindStringSubmatch(input); len(match) > 1 {
		result.Name = match[1]
	}
	if match := valueRe.FindStringSubmatch(input); len(match) > 1 {
		result.Value = match[1]
	}
	if match := placeholderRe.FindStringSubmatch(input); len(match) > 1 {
		result.Placeholder = match[1]
	}
	if match := idRe.FindStringSubmatch(input); len(match) > 1 {
		result.ID = match[1]
	}

	if result.Type == "" {
		result.Type = "text"
	}

	return result
}

func extractAttributes(element string) map[string]string {
	attrs := make(map[string]string)

	attrRe := regexp.MustCompile(`(?i)(\w+)=["']([^"']+)["']`)
	matches := attrRe.FindAllStringSubmatch(element, -1)

	for _, match := range matches {
		if len(match) > 2 {
			attrs[strings.ToLower(match[1])] = match[2]
		}
	}

	return attrs
}

func stripTags(html string) string {
	scriptRe := regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	html = scriptRe.ReplaceAllString(html, "")

	styleRe := regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	html = styleRe.ReplaceAllString(html, "")

	tagRe := regexp.MustCompile(`<[^>]+>`)
	text := tagRe.ReplaceAllString(html, " ")

	spaceRe := regexp.MustCompile(`\s+`)
	text = spaceRe.ReplaceAllString(text, " ")

	return strings.TrimSpace(text)
}

// FindFlags searches for common CTF flag patterns
func (s *ScrapedContent) FindFlags() []string {
	patterns := []string{
		`(?i)flag\{[^}]+\}`,
		`(?i)ctf\{[^}]+\}`,
		`(?i)[a-f0-9]{32}`,             // MD5
		`(?i)[a-f0-9]{40}`,             // SHA1
		`(?i)[a-f0-9]{64}`,             // SHA256
		`\b[A-Za-z0-9+/]{20,}={0,2}\b`, // Base64
	}

	var results []string
	seen := make(map[string]bool)

	for _, pattern := range patterns {
		if matches, err := s.FindAllRegex(pattern); err == nil {
			for _, match := range matches {
				if !seen[match] {
					results = append(results, match)
					seen[match] = true
				}
			}
		}
	}

	return results
}

// FindHiddenInputs finds all hidden input fields
func (s *ScrapedContent) FindHiddenInputs() []Input {
	var hidden []Input
	for _, form := range s.Forms {
		for _, input := range form.Inputs {
			if strings.ToLower(input.Type) == "hidden" {
				hidden = append(hidden, input)
			}
		}
	}
	return hidden
}

// FindJSVariables attempts to find JavaScript variable declarations
func (s *ScrapedContent) FindJSVariables() map[string]string {
	vars := make(map[string]string)

	patterns := []string{
		`(?m)^\s*(?:var|let|const)\s+(\w+)\s*=\s*["']([^"']+)["']`,
		`(?m)^\s*(?:var|let|const)\s+(\w+)\s*=\s*(\d+)`,
		`(?m)^\s*(\w+)\s*=\s*["']([^"']+)["']`,
	}

	for _, script := range s.Scripts {
		for _, pattern := range patterns {
			re := regexp.MustCompile(pattern)
			matches := re.FindAllStringSubmatch(script, -1)
			for _, match := range matches {
				if len(match) > 2 {
					vars[match[1]] = match[2]
				}
			}
		}
	}

	return vars
}

// FindAPIEndpoints looks for potential API endpoints
func (s *ScrapedContent) FindAPIEndpoints() []string {
	var endpoints []string
	seen := make(map[string]bool)

	patterns := []string{
		`["'](/api/[^"']+)["']`,
		`["'](/v\d+/[^"']+)["']`,
		`fetch\(["']([^"']+)["']`,
		`\.ajax\([^)]*url:\s*["']([^"']+)["']`,
		`XMLHttpRequest.*open\([^,]+,\s*["']([^"']+)["']`,
	}

	content := s.Raw
	for _, script := range s.Scripts {
		content += "\n" + script
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 && !seen[match[1]] {
				endpoints = append(endpoints, match[1])
				seen[match[1]] = true
			}
		}
	}

	return endpoints
}
