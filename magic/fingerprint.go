package magic

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HashGuess is a possible hash algorithm for a blob, with a rough confidence.
type HashGuess struct {
	Name       string
	Confidence float64
}

// FileType is a guessed file format from magic bytes.
type FileType struct {
	Ext         string
	MIME        string
	Description string
}

// TimeGuess is a plausible interpretation of a numeric blob as a timestamp.
type TimeGuess struct {
	Format string
	Time   time.Time
}

// Fingerprint is the result of Identify: what an opaque blob is likely to be.
type Fingerprint struct {
	Length      int
	Charset     string
	HashGuesses []HashGuess
	Encodings   []string
	FileType    *FileType
	Timestamps  []TimeGuess
}

// Identify inspects a blob and reports likely hash types, encodings, file type
// and timestamp interpretations — an offline hashid + file + base detector.
func Identify(blob []byte) Fingerprint {
	s := strings.TrimSpace(string(blob))
	fp := Fingerprint{Length: len(s)}
	fp.Charset = classifyCharset(s)
	fp.HashGuesses = guessHash(s, fp.Charset)
	fp.Encodings = guessEncodings(blob)
	fp.FileType = guessFileType(blob)
	fp.Timestamps = guessTimestamps(s)
	return fp
}

func classifyCharset(s string) string {
	if s == "" {
		return "empty"
	}
	isHex, isDigit, isB32, isB64c, isBin, isASCII := true, true, true, true, true, true
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			isHex = false
		}
		if c < '0' || c > '9' {
			isDigit = false
		}
		if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') || c == '=') {
			isB32 = false
		}
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '-' || c == '_' || c == '=') {
			isB64c = false
		}
		if c != '0' && c != '1' && c != ' ' {
			isBin = false
		}
		if c > 0x7e || c < 0x20 {
			isASCII = false
		}
	}
	switch {
	case isDigit:
		return "decimal"
	case isBin:
		return "binary"
	case isHex:
		return "hex"
	case isB32:
		return "base32"
	case isB64c:
		return "base64"
	case isASCII:
		return "ascii"
	default:
		return "binary/raw"
	}
}

var hexHashByLen = map[int][]string{
	8:   {"CRC-32", "Adler-32"},
	16:  {"MySQL<4.1", "CRC-64"},
	32:  {"MD5", "MD4", "NTLM", "LM"},
	40:  {"SHA-1", "RIPEMD-160"},
	56:  {"SHA-224", "SHA3-224"},
	64:  {"SHA-256", "SHA3-256", "BLAKE2s", "Keccak-256"},
	96:  {"SHA-384", "SHA3-384"},
	128: {"SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"},
}

func guessHash(s, charset string) []HashGuess {
	var out []HashGuess
	add := func(name string, conf float64) { out = append(out, HashGuess{name, conf}) }

	switch {
	case strings.HasPrefix(s, "$2a$"), strings.HasPrefix(s, "$2b$"), strings.HasPrefix(s, "$2y$"):
		add("bcrypt", 0.99)
	case strings.HasPrefix(s, "$6$"):
		add("sha512crypt", 0.99)
	case strings.HasPrefix(s, "$5$"):
		add("sha256crypt", 0.99)
	case strings.HasPrefix(s, "$1$"):
		add("md5crypt", 0.99)
	case strings.HasPrefix(s, "$argon2"):
		add("argon2", 0.99)
	case strings.HasPrefix(s, "{SSHA}"):
		add("LDAP SSHA", 0.95)
	case strings.HasPrefix(s, "{SHA}"):
		add("LDAP SHA", 0.95)
	case strings.HasPrefix(s, "pbkdf2"), strings.HasPrefix(s, "$pbkdf2"):
		add("PBKDF2", 0.9)
	}

	if charset == "hex" {
		if names, ok := hexHashByLen[len(s)]; ok {
			conf := 0.6 / float64(len(names))
			for _, n := range names {
				add(n, conf+0.2)
			}
		}
	}
	return out
}

func guessEncodings(blob []byte) []string {
	var out []string
	if _, ok := HexDecode(blob); ok {
		out = append(out, "hex")
	}
	if _, ok := B64Decode(blob); ok {
		out = append(out, "base64")
	}
	if _, ok := B32Decode(blob); ok {
		out = append(out, "base32")
	}
	if _, ok := BinaryDecode(blob); ok {
		out = append(out, "binary")
	}
	if _, ok := DecimalDecode(blob); ok {
		out = append(out, "decimal")
	}
	return out
}

type magicSig struct {
	prefix []byte
	ft     FileType
}

var fileSigs = []magicSig{
	{[]byte{0x89, 'P', 'N', 'G'}, FileType{"png", "image/png", "PNG image"}},
	{[]byte{0xFF, 0xD8, 0xFF}, FileType{"jpg", "image/jpeg", "JPEG image"}},
	{[]byte("GIF8"), FileType{"gif", "image/gif", "GIF image"}},
	{[]byte("%PDF"), FileType{"pdf", "application/pdf", "PDF document"}},
	{[]byte("PK\x03\x04"), FileType{"zip", "application/zip", "ZIP archive (or docx/jar/apk)"}},
	{[]byte{0x7F, 'E', 'L', 'F'}, FileType{"elf", "application/x-elf", "ELF executable"}},
	{[]byte{0x1F, 0x8B}, FileType{"gz", "application/gzip", "gzip archive"}},
	{[]byte("BZh"), FileType{"bz2", "application/x-bzip2", "bzip2 archive"}},
	{[]byte{0xFD, '7', 'z', 'X', 'Z', 0x00}, FileType{"xz", "application/x-xz", "XZ archive"}},
	{[]byte("7z\xBC\xAF\x27\x1C"), FileType{"7z", "application/x-7z-compressed", "7-Zip archive"}},
	{[]byte("Rar!\x1A\x07"), FileType{"rar", "application/x-rar", "RAR archive"}},
	{[]byte{'M', 'Z'}, FileType{"exe", "application/x-dosexec", "Windows PE executable"}},
	{[]byte{0xCA, 0xFE, 0xBA, 0xBE}, FileType{"class", "application/java-vm", "Java class file"}},
	{[]byte("OggS"), FileType{"ogg", "audio/ogg", "Ogg media"}},
	{[]byte("ID3"), FileType{"mp3", "audio/mpeg", "MP3 audio (ID3)"}},
	{[]byte("\x25\x21PS"), FileType{"ps", "application/postscript", "PostScript"}},
}

func guessFileType(blob []byte) *FileType {
	for _, sig := range fileSigs {
		if len(blob) >= len(sig.prefix) && string(blob[:len(sig.prefix)]) == string(sig.prefix) {
			ft := sig.ft
			return &ft
		}
	}
	if mime := http.DetectContentType(blob); mime != "application/octet-stream" {
		ft := FileType{MIME: mime, Description: "detected by content sniffing"}
		return &ft
	}
	return nil
}

func guessTimestamps(s string) []TimeGuess {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return nil
	}
	lo := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	hi := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	keep := func(t time.Time) bool { return t.After(lo) && t.Before(hi) }

	var out []TimeGuess
	if t := time.Unix(n, 0).UTC(); keep(t) {
		out = append(out, TimeGuess{"unix seconds", t})
	}
	if t := time.Unix(n/1000, (n%1000)*1e6).UTC(); keep(t) {
		out = append(out, TimeGuess{"unix milliseconds", t})
	}
	if t := time.Unix(n/1e6, (n%1e6)*1e3).UTC(); keep(t) {
		out = append(out, TimeGuess{"unix microseconds", t})
	}
	// Windows FILETIME: 100ns ticks since 1601-01-01.
	if unixSec := n/1e7 - 11644473600; unixSec > 0 {
		if t := time.Unix(unixSec, 0).UTC(); keep(t) {
			out = append(out, TimeGuess{"Windows FILETIME", t})
		}
	}
	return out
}
