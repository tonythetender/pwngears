package process

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

type TubeLogLevel int

const (
	LogDebug TubeLogLevel = iota
	LogInfo
	LogSuccess
	LogWarning
	LogError
)

var currentLogLevel = LogInfo

type Tube interface {
	Send(data interface{}) error
	SendLine(data interface{}) error
	SendAfter(delim, data interface{}) error
	SendLineAfter(delim, data interface{}) error
	Recv(n int) ([]byte, error)
	RecvUntil(delim interface{}) ([]byte, error)
	RecvLine() ([]byte, error)
	RecvString() (string, error)
	RecvLineString() (string, error)
	RecvAll(timeout time.Duration) ([]byte, error)
	RecvAllString(timeout time.Duration) (string, error)
	Interactive() error
	Close() error
	GetPID() int
}

func toBytes(data interface{}) []byte {
	switch v := data.(type) {
	case string:
		return []byte(v)
	case []byte:
		return v
	case byte:
		return []byte{v}
	case int:
		return P32(uint32(v))
	case uint32:
		return P32(v)
	case uint64:
		return P64(v)
	default:
		panic(fmt.Sprintf("unsupported type: %T", v))
	}
}

type baseTube struct {
	reader  *bufio.Reader
	writer  io.Writer
	closer  io.Closer
	buffer  bytes.Buffer
	timeout time.Duration
}

func (t *baseTube) Send(data interface{}) error {
	b := toBytes(data)
	Log(LogDebug, "SEND", hex.Dump(b))
	_, err := t.writer.Write(b)
	return err
}

func (t *baseTube) SendLine(data interface{}) error {
	b := toBytes(data)
	return t.Send(append(b, '\n'))
}

func (t *baseTube) SendAfter(delim, data interface{}) error {
	_, err := t.RecvUntil(delim)
	if err != nil {
		return err
	}
	return t.Send(data)
}

func (t *baseTube) SendLineAfter(delim, data interface{}) error {
	_, err := t.RecvUntil(delim)
	if err != nil {
		return err
	}
	return t.SendLine(data)
}

func (t *baseTube) SendPayload(p *Payload) error {
	return t.Send(p.data)
}

func (t *baseTube) SendPayloadSize(p *Payload) error {
	return t.Send(P32(uint32(len(p.data))))
}

func (t *baseTube) Recv(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(t.reader, buf)
	if err == nil {
		Log(LogDebug, "RECV", hex.Dump(buf))
	}
	return buf, err
}

func (t *baseTube) RecvUntil(delim interface{}) ([]byte, error) {
	delimBytes := toBytes(delim)
	var result []byte
	buf := make([]byte, 1)

	for {
		_, err := t.reader.Read(buf)
		if err != nil {
			return result, err
		}
		result = append(result, buf[0])
		if bytes.HasSuffix(result, delimBytes) {
			Log(LogDebug, "RECV", hex.Dump(result))
			return result, nil
		}
	}
}

func (t *baseTube) RecvLine() ([]byte, error) {
	line, err := t.reader.ReadBytes('\n')
	if err == nil {
		Log(LogDebug, "RECV", hex.Dump(line))
	}
	return line, err
}

func (t *baseTube) RecvString() (string, error) {
	data, err := t.Recv(1024)
	return string(data), err
}

func (t *baseTube) RecvLineString() (string, error) {
	data, err := t.RecvLine()
	return string(data), err
}

func (t *baseTube) RecvAll(timeout time.Duration) ([]byte, error) {
	var result []byte
	done := make(chan bool)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := t.reader.Read(buf)
			if n > 0 {
				result = append(result, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		done <- true
	}()

	select {
	case <-done:
		Log(LogDebug, "RECV", hex.Dump(result))
		return result, nil
	case <-time.After(timeout):
		Log(LogDebug, "RECV", hex.Dump(result))
		return result, nil
	}
}

func (t *baseTube) RecvAllString(timeout time.Duration) (string, error) {
	data, err := t.RecvAll(timeout)
	return string(data), err
}

func (t *baseTube) Interactive() error {
	Log(LogInfo, "Interactive", "Switching to interactive mode")

	go func() {
		io.Copy(os.Stdout, t.reader)
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		t.SendLine(scanner.Text())
	}

	return scanner.Err()
}

func (t *baseTube) Close() error {
	if t.closer != nil {
		return t.closer.Close()
	}
	return nil
}

type GDB struct {
	process *ProcessConn
	pid     int
}

func AttachGDB(tube Tube, script string) (*GDB, error) {
	pid := tube.GetPID()
	if pid <= 0 {
		return nil, fmt.Errorf("cannot attach GDB: invalid PID")
	}

	gdbScript := fmt.Sprintf("attach %d\n%s", pid, script)
	tmpFile := fmt.Sprintf("/tmp/gdb_script_%d.gdb", pid)

	if err := os.WriteFile(tmpFile, []byte(gdbScript), 0o644); err != nil {
		return nil, err
	}

	cmd := exec.Command("x-terminal-emulator", "-e", "gdb", "-x", tmpFile)
	if err := cmd.Start(); err != nil {
		cmd = exec.Command("gnome-terminal", "--", "gdb", "-x", tmpFile)
		if err := cmd.Start(); err != nil {
			cmd = exec.Command("gdb", "-x", tmpFile)
			if err := cmd.Start(); err != nil {
				return nil, err
			}
		}
	}

	time.Sleep(time.Second)

	return &GDB{
		pid: pid,
	}, nil
}

func P8(v uint8) []byte {
	return []byte{v}
}

func P16(v uint16) []byte {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, v)
	return buf
}

func P32(v uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, v)
	return buf
}

func P64(v uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, v)
	return buf
}

func U8(b []byte) uint8 {
	if len(b) < 1 {
		return 0
	}
	return b[0]
}

func U16(b []byte) uint16 {
	if len(b) < 2 {
		return 0
	}
	return binary.LittleEndian.Uint16(b)
}

func U32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

func U64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}

func Cyclic(n int) []byte {
	pattern := make([]byte, n)
	for i := 0; i < n; i++ {
		a := (i / (26 * 26 * 10)) % 26
		b := (i / (26 * 10)) % 26
		c := (i / 10) % 26
		d := i % 10
		pattern[i] = byte('A' + a)
		if i+1 < n {
			pattern[i+1] = byte('a' + b)
		}
		if i+2 < n {
			pattern[i+2] = byte('a' + c)
		}
		if i+3 < n {
			pattern[i+3] = byte('0' + d)
		}
		i += 3
	}
	return pattern[:n]
}

func CyclicFind(pattern []byte) int {
	cyclic := Cyclic(10000)
	idx := bytes.Index(cyclic, pattern)
	if idx == -1 {
		pattern = reverseBytes(pattern)
		idx = bytes.Index(cyclic, pattern)
	}
	return idx
}

func reverseBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i := range b {
		result[i] = b[len(b)-1-i]
	}
	return result
}

func Log(level TubeLogLevel, tag string, msg string) {
	if level < currentLogLevel {
		return
	}

	var prefix string
	switch level {
	case LogDebug:
		prefix = "[DEBUG]"
	case LogInfo:
		prefix = "[*]"
	case LogSuccess:
		prefix = "[+]"
	case LogWarning:
		prefix = "[!]"
	case LogError:
		prefix = "[ERROR]"
	}

	if tag != "" {
		fmt.Printf("%s [%s] %s\n", prefix, tag, msg)
	} else {
		fmt.Printf("%s %s\n", prefix, msg)
	}
}

func SetLogLevel(level TubeLogLevel) {
	currentLogLevel = level
}

func Info(msg string) {
	Log(LogInfo, "", msg)
}

func Success(msg string) {
	Log(LogSuccess, "", msg)
}

func Warning(msg string) {
	Log(LogWarning, "", msg)
}

func Error(msg string) {
	Log(LogError, "", msg)
}

func Debug(msg string) {
	Log(LogDebug, "", msg)
}

type Exploit struct {
	tube        Tube
	connectFunc func() Tube
}

func NewExploit(tube Tube) *Exploit {
	return &Exploit{tube: tube}
}

func (e *Exploit) SetConnectFunc(f func() Tube) {
	e.connectFunc = f
}

func (e *Exploit) Reconnect() Tube {
	if e.connectFunc != nil {
		return e.connectFunc()
	}

	switch t := e.tube.(type) {
	case *RemoteConn:
		newTube, _ := t.Reconnect()
		return newTube
	default:
		return e.tube
	}
}

func (e *Exploit) LeakCanary(bufferSize int, checkFunc func(Tube) bool) ([]byte, error) {
	canary := make([]byte, 8)

	for i := 0; i < 8; i++ {
		Info(fmt.Sprintf("Bruteforcing canary byte %d", i))

		for byteVal := 0; byteVal < 256; byteVal++ {
			tube := e.Reconnect()
			if tube == nil {
				continue
			}

			payload := Pay().
				PadTo(bufferSize).
				AddRaw(canary[:i]).
				P8(uint8(byteVal))

			payload.SendWithSize(tube)

			if checkFunc(tube) {
				canary[i] = byte(byteVal)
				Success(fmt.Sprintf("Found canary byte %d: 0x%02x", i, byteVal))
				tube.Close()
				break
			}

			tube.Close()
		}
	}

	Success(fmt.Sprintf("Full canary: 0x%x", canary))
	return canary, nil
}

func (e *Exploit) LeakAddress(bufferSize int, canary []byte, offset int, checkFunc func(Tube) bool) (uint64, error) {
	leak := make([]byte, 8)

	for i := 0; i < 8; i++ {
		Info(fmt.Sprintf("Bruteforcing address byte %d", i))

		for byteVal := 0; byteVal < 256; byteVal++ {
			tube := e.Reconnect()
			if tube == nil {
				continue
			}

			payload := Pay().
				PadTo(bufferSize).
				Canary(canary).
				Repeat("B", offset).
				AddRaw(leak[:i]).
				P8(uint8(byteVal))

			payload.SendWithSize(tube)

			if checkFunc(tube) {
				leak[i] = byte(byteVal)
				Success(fmt.Sprintf("Found address byte %d: 0x%02x", i, byteVal))
				tube.Close()
				break
			}

			tube.Close()
		}
	}

	addr := U64(leak)
	Success(fmt.Sprintf("Leaked address: 0x%x", addr))
	return addr, nil
}

func (e *Exploit) FindOffset(data interface{}) int {
	b := toBytes(data)
	cyclic := Cyclic(1024)
	e.tube.Send(cyclic)

	response, _ := e.tube.RecvAll(time.Second)

	if idx := bytes.Index(response, b); idx != -1 {
		offset := CyclicFind(response[idx : idx+len(b)])
		Success(fmt.Sprintf("Found offset: %d", offset))
		return offset
	}

	return -1
}

func (e *Exploit) BruteforceChar(prefix string, maxLen int, charset string, testFunc func(Tube, string) bool) (string, error) {
	result := prefix

	for i := len(prefix); i < maxLen; i++ {
		found := false

		for _, char := range charset {
			tube := e.Reconnect()
			if tube == nil {
				continue
			}

			testPayload := result + string(char)

			if testFunc(tube, testPayload) {
				result = testPayload
				found = true
				Success(fmt.Sprintf("Found: %s", result))
				tube.Close()
				break
			}

			tube.Close()
		}

		if !found {
			break
		}
	}

	return result, nil
}

func (e *Exploit) BruteforceByte(prefix []byte, maxLen int, testFunc func(Tube, []byte) bool) ([]byte, error) {
	result := make([]byte, len(prefix))
	copy(result, prefix)

	for i := len(prefix); i < maxLen; i++ {
		found := false

		for byteVal := 0; byteVal < 256; byteVal++ {
			tube := e.Reconnect()
			if tube == nil {
				continue
			}

			testPayload := append(result, byte(byteVal))

			if testFunc(tube, testPayload) {
				result = append(result, byte(byteVal))
				found = true
				Success(fmt.Sprintf("Found byte %d: 0x%02x", i, byteVal))
				tube.Close()
				break
			}

			tube.Close()
		}

		if !found {
			break
		}
	}

	return result, nil
}

func SIGSTOP(pid int) error {
	return syscall.Kill(pid, syscall.SIGSTOP)
}

func SIGCONT(pid int) error {
	return syscall.Kill(pid, syscall.SIGCONT)
}

func Contains(data []byte, substr string) bool {
	return bytes.Contains(data, []byte(substr))
}

func SolvePoW(challenge uint64) uint64 {
	target := uint64(1 << 24)

	gcd := func(a, b uint64) uint64 {
		for b != 0 {
			a, b = b, a%b
		}
		return a
	}

	g := gcd(challenge, target)
	return target / g
}
