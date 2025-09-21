package process

import "bytes"

type Payload struct {
	data []byte
}

func NewPayload() *Payload {
	return &Payload{data: []byte{}}
}

func Pay() *Payload {
	return NewPayload()
}

func (p *Payload) Add(data interface{}) *Payload {
	p.data = append(p.data, toBytes(data)...)
	return p
}

func (p *Payload) AddRaw(data []byte) *Payload {
	p.data = append(p.data, data...)
	return p
}

func (p *Payload) Pad(char byte, length int) *Payload {
	if len(p.data) < length {
		padding := bytes.Repeat([]byte{char}, length-len(p.data))
		p.data = append(p.data, padding...)
	}
	return p
}

func (p *Payload) PadTo(length int) *Payload {
	return p.Pad('A', length)
}

func (p *Payload) P8(v uint8) *Payload {
	p.data = append(p.data, P8(v)...)
	return p
}

func (p *Payload) P16(v uint16) *Payload {
	p.data = append(p.data, P16(v)...)
	return p
}

func (p *Payload) P32(v uint32) *Payload {
	p.data = append(p.data, P32(v)...)
	return p
}

func (p *Payload) P64(v uint64) *Payload {
	p.data = append(p.data, P64(v)...)
	return p
}

func (p *Payload) Repeat(data interface{}, count int) *Payload {
	b := toBytes(data)
	p.data = append(p.data, bytes.Repeat(b, count)...)
	return p
}

func (p *Payload) Canary(canary []byte) *Payload {
	p.data = append(p.data, canary...)
	return p
}

func (p *Payload) Len() int {
	return len(p.data)
}

func (p *Payload) Bytes() []byte {
	return p.data
}

func (p *Payload) Send(tube Tube) error {
	return tube.Send(p.data)
}

func (p *Payload) SendLine(tube Tube) error {
	return tube.SendLine(p.data)
}

func (p *Payload) SendWithSize(tube Tube) error {
	if err := tube.Send(P32(uint32(len(p.data)))); err != nil {
		return err
	}
	return tube.Send(p.data)
}
