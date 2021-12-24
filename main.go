package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"strings"
)

type Header struct {
	TransactionID uint16
	Flags         uint16
	Questions     uint16
	AnswerRRs     uint16
	AuthorityRRs  uint16
	AdditionalRRs uint16
}

func NewHeader() Header {
	return Header{
		TransactionID: 0xFFFF,
		Flags:         0<<15 + 0<<11 + 0<<10 + 0<<9 + 1<<8 + 0<<7 + uint16(0),
		Questions:     1,
		AnswerRRs:     0,
		AuthorityRRs:  0,
		AdditionalRRs: 0,
	}
}

type Query struct {
	Type  uint16
	Class uint16
}

func NewQuery() Query {
	return Query{
		Type:  1,
		Class: 1,
	}
}

type Message struct {
	Header Header
	Domain string
	Query  Query
	Target *net.UDPAddr
}

func NewMessage(domain string, target *net.UDPAddr) *Message {
	return &Message{
		Header: NewHeader(),
		Domain: domain,
		Query:  NewQuery(),
		Target: target,
	}
}

func parseDomain(domain string) ([]byte, error) {
	var (
		buf      bytes.Buffer
		segments = strings.Split(domain, ".")
	)

	for _, segment := range segments {
		err := binary.Write(&buf, binary.BigEndian, byte(len(segment)))
		if err != nil {
			return nil, err
		}
		err = binary.Write(&buf, binary.BigEndian, []byte(segment))
		if err != nil {
			return nil, err
		}
	}

	err := binary.Write(&buf, binary.BigEndian, byte(0x00))
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (m Message) message() ([]byte, error) {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, m.Header)
	if err != nil {
		return nil, err
	}
	domain, err := parseDomain(m.Domain)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buf, binary.BigEndian, domain)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buf, binary.BigEndian, m.Query)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buf, binary.BigEndian, m.Query)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (m Message) Send() error {
	message, err := m.message()
	if err != nil {
		return err
	}
	conn, err := net.Dial("udp", m.Target.String())
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(message)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	message := NewMessage("www.baidu.com", &net.UDPAddr{
		IP:   net.IPv4(223, 5, 5, 5),
		Port: 53,
	})

	err := message.Send()
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("Successfully send...")
}
