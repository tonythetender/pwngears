package pwngears

import (
	"github.com/tonythetender/pwngears/bruteforce"
	"github.com/tonythetender/pwngears/crypto"
	"github.com/tonythetender/pwngears/internal/pwnlog"
	"github.com/tonythetender/pwngears/payloads"
	"github.com/tonythetender/pwngears/process"
	"github.com/tonythetender/pwngears/web"
)

type (
	Tube                  = process.Tube
	Payload               = process.Payload
	Check                 = process.Check
	Exploit               = process.Exploit
	ProcessConn           = process.ProcessConn
	RemoteConn            = process.RemoteConn
	ProcessConnWithLogger = process.ProcessConnWithLogger
	RemoteConnWithLogger  = process.RemoteConnWithLogger
	GDB                   = process.GDB
	TubeLogLevel          = process.TubeLogLevel
	RemoteOption          = process.RemoteOption
	ProcessOption         = process.ProcessOption
)

type (
	WebConn           = web.WebConn
	WebConnWithLogger = web.WebConnWithLogger
	WebConnWithErrors = web.WebConnWithErrors
	Client            = web.Client
	Response          = web.Response
	Session           = web.Session
	Form              = web.Form
	Input             = web.Input
	Element           = web.Element
	ScrapedContent    = web.ScrapedContent
	ScrapeOption      = web.ScrapeOption
	RequestOption     = web.RequestOption
	Fields            = web.Fields
)

type (
	CryptoEngine   = crypto.CryptoEngine
	Cipher         = crypto.Cipher
	Result         = crypto.Result
	Pattern        = crypto.Pattern
	DecryptOption  = crypto.DecryptOption
	XORCipher      = crypto.XORCipher
	CaesarCipher   = crypto.CaesarCipher
	VigenereCipher = crypto.VigenereCipher
)

type (
	Bruteforcer = bruteforce.Bruteforcer
	TestFunc    = bruteforce.TestFunc
	GreaterFunc = bruteforce.GreaterFunc
	CharFunc    = bruteforce.CharFunc
	FuzzHit     = web.FuzzHit
	FuzzFilter  = web.FuzzFilter
	Fuzzer      = web.Fuzzer
)

const (
	LogDebug   = process.LogDebug
	LogInfo    = process.LogInfo
	LogSuccess = process.LogSuccess
	LogWarning = process.LogWarning
	LogError   = process.LogError
)

var (
	Process           = process.Process
	ProcessWith       = process.ProcessWith
	ProcessWithLogger = process.ProcessWithLogger
	Remote            = process.Remote
	RemoteWithLogger  = process.RemoteWithLogger
	RemoteSSL         = process.RemoteSSL
	NewRemote         = process.NewRemote
	SSL               = process.SSL
	WithSSL           = process.WithSSL
	WithSNI           = process.WithSNI
	WithVerifyCert    = process.WithVerifyCert
	WithArgs          = process.WithArgs
	WithEnv           = process.WithEnv
	WithEnvVar        = process.WithEnvVar
	WithProcessLogger = process.WithProcessLogger
	NewExploit        = process.NewExploit
	AttachGDB         = process.AttachGDB
	Pay               = process.Pay
	Flat              = process.Flat
	NewPayload        = process.NewPayload
	RecvContains      = process.RecvContains
	RecvLineContains  = process.RecvLineContains
	Survives          = process.Survives
	Crashed           = process.Crashed
	P8                = process.P8
	P16               = process.P16
	P32               = process.P32
	P64               = process.P64
	U8                = process.U8
	U16               = process.U16
	U32               = process.U32
	U64               = process.U64
	Cyclic            = process.Cyclic
	CyclicFind        = process.CyclicFind
	Contains          = process.Contains
	SolvePoW          = process.SolvePoW
	SIGSTOP           = process.SIGSTOP
	SIGCONT           = process.SIGCONT
	Info              = process.Info
	Success           = process.Success
	Warning           = process.Warning
	Error             = process.Error
	Debug             = process.Debug
	Log               = process.Log
	SetTubeLogLevel   = process.SetLogLevel
)

var (
	Conn            = web.Conn
	ConnWithLogger  = web.ConnWithLogger
	ConnWithErrors  = web.ConnWithErrors
	NewForm         = web.NewForm
	Get             = web.Get
	Post            = web.Post
	PostForm        = web.PostForm
	PostJSON        = web.PostJSON
	PostRaw         = web.PostRaw
	WithParam       = web.WithParam
	WithParams      = web.WithParams
	WithHeader      = web.WithHeader
	WithHeaders     = web.WithHeaders
	WithCookie      = web.WithCookie
	WithCookies     = web.WithCookies
	WithContentType = web.WithContentType
	WithBasicAuth   = web.WithBasicAuth
	WithBearer      = web.WithBearer
	LoadFields      = web.LoadFields
	LoadJSON        = web.LoadJSON
)

var (
	NewCryptoEngine         = crypto.NewCryptoEngine
	WithMaxKeyLength        = crypto.WithMaxKeyLength
	WithFindAllPossibleKeys = crypto.WithFindAllPossibleKeys
	WithTimeout             = crypto.WithTimeout
	WithWorkersCount        = crypto.WithWorkersCount
	WithPatternPrefix       = crypto.WithPatternPrefix
	WithPatternSuffix       = crypto.WithPatternSuffix
	WithPatternRegex        = crypto.WithPatternRegex
	WithExactKeyLength      = crypto.WithExactKeyLength
	WithProgressInterval    = crypto.WithProgressInterval
	WithCustomProgressBar   = crypto.WithCustomProgressBarFunction
	EstimateTotalKeys       = crypto.EstimateTotalKeys
	DefaultProgressBar      = crypto.DefaultProgressBar
)

var (
	NewBruteforcer  = bruteforce.NewBruteforcer
	GenerateCharset = bruteforce.GenerateCharset
)

var (
	Oracle        = web.Oracle
	GreaterOracle = web.GreaterOracle
	CharOracle    = web.CharOracle
	Fuzz          = web.Fuzz
	MatchStatus   = web.MatchStatus
	FilterStatus  = web.FilterStatus
	MatchLength   = web.MatchLength
	FilterLength  = web.FilterLength
	MatchRegex    = web.MatchRegex
	FilterRegex   = web.FilterRegex
)

type (
	Dialect = payloads.Dialect
	SQLi    = payloads.SQLi
)

const (
	MySQL    = payloads.MySQL
	Postgres = payloads.Postgres
	SQLite   = payloads.SQLite
	MSSQL    = payloads.MSSQL
	OracleDB = payloads.OracleDB
)

var (
	AuthBypass    = payloads.AuthBypass
	UnionNull     = payloads.UnionNull
	OrderBy       = payloads.OrderBy
	TimeDelay     = payloads.TimeDelay
	CmdInjection  = payloads.CmdInjection
	PathTraversal = payloads.PathTraversal
	SSTI          = payloads.SSTI
	XSS           = payloads.XSS
	NoSQL         = payloads.NoSQL
)

var NewDefaultLogger = pwnlog.NewDefaultLogger
