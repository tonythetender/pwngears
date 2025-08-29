package bfweb

import (
	"net/url"
	"strings"
	"time"

	"pwngears/bruteforce"
	"pwngears/web"
)

type BruteforceOptions struct {
	ResponseCode      int
	BadResponseCode   int
	RequireCode       bool
	BodyContains      []string
	BodyNotContains   []string
	HeaderContains    map[string]string
	HeaderNotContains map[string]string
	CookieContains    map[string]string
	ResponseTimeAbove time.Duration
	ResponseTimeBelow time.Duration
	ExtraFormFields   map[string]string
	CustomValidator   func(*web.Response) bool
}

type BruteforceOption func(*BruteforceOptions)

func WithResponseCode(code int) BruteforceOption {
	return func(o *BruteforceOptions) {
		o.ResponseCode = code
		o.RequireCode = true
	}
}

func WithoutResponseCode(code int) BruteforceOption {
	return func(o *BruteforceOptions) {
		o.BadResponseCode = code
		o.RequireCode = true
	}
}

func WithBodyContains(text string) BruteforceOption {
	return func(o *BruteforceOptions) {
		o.BodyContains = append(o.BodyContains, text)
	}
}

func WithoutBodyContains(text string) BruteforceOption {
	return func(o *BruteforceOptions) {
		o.BodyNotContains = append(o.BodyNotContains, text)
	}
}

func WithHeaderContains(key, value string) BruteforceOption {
	return func(o *BruteforceOptions) {
		if o.HeaderContains == nil {
			o.HeaderContains = make(map[string]string)
		}
		o.HeaderContains[key] = value
	}
}

func WithoutHeaderContains(key, value string) BruteforceOption {
	return func(o *BruteforceOptions) {
		if o.HeaderNotContains == nil {
			o.HeaderNotContains = make(map[string]string)
		}
		o.HeaderNotContains[key] = value
	}
}

func WithCookieContains(name, value string) BruteforceOption {
	return func(o *BruteforceOptions) {
		if o.CookieContains == nil {
			o.CookieContains = make(map[string]string)
		}
		o.CookieContains[name] = value
	}
}

func WithResponseTimeAbove(duration time.Duration) BruteforceOption {
	return func(o *BruteforceOptions) {
		o.ResponseTimeAbove = duration
	}
}

func WithResponseTimeBelow(duration time.Duration) BruteforceOption {
	return func(o *BruteforceOptions) {
		o.ResponseTimeBelow = duration
	}
}

func WithCustomValidator(validator func(*web.Response) bool) BruteforceOption {
	return func(o *BruteforceOptions) {
		o.CustomValidator = validator
	}
}

func AlsoFillFormField(field, value string) BruteforceOption {
	return func(o *BruteforceOptions) {
		if o.ExtraFormFields == nil {
			o.ExtraFormFields = make(map[string]string)
		}
		o.ExtraFormFields[field] = value
	}
}

func evaluateOptions(resp *web.Response, duration time.Duration, opts *BruteforceOptions) bool {
	if opts.RequireCode && resp.StatusCode != opts.ResponseCode {
		return false
	}

	if opts.RequireCode && resp.StatusCode == opts.BadResponseCode {
		return false
	}

	for _, text := range opts.BodyContains {
		if !resp.Contains(text) {
			return false
		}
	}

	for _, text := range opts.BodyNotContains {
		if resp.Contains(text) {
			return false
		}
	}

	for key, value := range opts.HeaderContains {
		if !strings.Contains(resp.GetHeader(key), value) {
			return false
		}
	}

	for key, value := range opts.HeaderNotContains {
		if strings.Contains(resp.GetHeader(key), value) {
			return false
		}
	}

	for name, value := range opts.CookieContains {
		found := false
		for _, cookie := range resp.Cookies {
			if cookie.Name == name && strings.Contains(cookie.Value, value) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if opts.ResponseTimeAbove > 0 && duration < opts.ResponseTimeAbove {
		return false
	}

	if opts.ResponseTimeBelow > 0 && duration > opts.ResponseTimeBelow {
		return false
	}

	if opts.CustomValidator != nil {
		return opts.CustomValidator(resp)
	}

	return true
}

func GetRequestBf(c *web.Client, urlPattern string, options ...BruteforceOption) bruteforce.TestFunc {
	opts := &BruteforceOptions{
		ResponseCode: 200,
		RequireCode:  false,
	}

	for _, option := range options {
		option(opts)
	}

	return func(payload string) (bool, error) {
		fullURL := strings.Replace(urlPattern, "FUZZ", payload, -1)
		if !strings.Contains(urlPattern, "FUZZ") {
			fullURL = urlPattern + payload
		}

		start := time.Now()
		resp, err := c.Get(fullURL)
		if err != nil {
			return false, err
		}
		duration := time.Since(start)

		return evaluateOptions(resp, duration, opts), nil
	}
}

func PostRequestBf(c *web.Client, path string, fieldName string, options ...BruteforceOption) bruteforce.TestFunc {
	opts := &BruteforceOptions{
		ResponseCode: 200,
		RequireCode:  false,
	}

	for _, option := range options {
		option(opts)
	}

	return func(payload string) (bool, error) {
		data := url.Values{}
		data.Set(fieldName, payload)
		if opts.ExtraFormFields != nil {
			for k, v := range opts.ExtraFormFields {
				data.Set(k, v)
			}
		}

		start := time.Now()
		resp, err := c.Post(path, data)
		if err != nil {
			return false, err
		}
		duration := time.Since(start)

		return evaluateOptions(resp, duration, opts), nil
	}
}

func HeaderBf(c *web.Client, path string, headerName string, options ...BruteforceOption) bruteforce.TestFunc {
	opts := &BruteforceOptions{
		ResponseCode: 200,
		RequireCode:  false,
	}

	for _, option := range options {
		option(opts)
	}

	return func(payload string) (bool, error) {
		c.SetHeader(headerName, payload)

		start := time.Now()
		resp, err := c.Get(path)
		if err != nil {
			return false, err
		}
		duration := time.Since(start)

		return evaluateOptions(resp, duration, opts), nil
	}
}

func CookieBf(c *web.Client, path string, cookieName string, options ...BruteforceOption) bruteforce.TestFunc {
	opts := &BruteforceOptions{
		ResponseCode: 200,
		RequireCode:  false,
	}

	for _, option := range options {
		option(opts)
	}

	return func(payload string) (bool, error) {
		c.SetCookie(cookieName, payload)

		start := time.Now()
		resp, err := c.Get(path)
		if err != nil {
			return false, err
		}
		duration := time.Since(start)

		return evaluateOptions(resp, duration, opts), nil
	}
}

func JSONBf(c *web.Client, path string, jsonTemplate string, options ...BruteforceOption) bruteforce.TestFunc {
	opts := &BruteforceOptions{
		ResponseCode: 200,
		RequireCode:  false,
	}

	for _, option := range options {
		option(opts)
	}

	return func(payload string) (bool, error) {
		jsonData := strings.Replace(jsonTemplate, "FUZZ", payload, -1)
		c.SetHeader("Content-Type", "application/json")

		start := time.Now()
		resp, err := c.Post(path, jsonData)
		if err != nil {
			return false, err
		}
		duration := time.Since(start)

		return evaluateOptions(resp, duration, opts), nil
	}
}

func MultiFormBf(c *web.Client, path string, formData url.Values, fuzzField string, options ...BruteforceOption) bruteforce.TestFunc {
	opts := &BruteforceOptions{
		ResponseCode: 200,
		RequireCode:  false,
	}

	for _, option := range options {
		option(opts)
	}

	return func(payload string) (bool, error) {
		data := url.Values{}
		for key, values := range formData {
			for _, value := range values {
				data.Add(key, value)
			}
		}
		data.Set(fuzzField, payload)

		start := time.Now()
		resp, err := c.Post(path, data)
		if err != nil {
			return false, err
		}
		duration := time.Since(start)

		return evaluateOptions(resp, duration, opts), nil
	}
}
