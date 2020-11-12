package dnsdumper

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	dst     string
	src     string
	tcp     layers.TCP
	udp     layers.UDP
	dns     layers.DNS
	payload gopacket.Payload
)

type DNSHandler struct {
	buffer *bytes.Buffer
	printer *Printer
}


var printerWaitGroup sync.WaitGroup

func readInterface(iface *net.Interface, iPacket chan<- gopacket.Packet) {
	defer close(iPacket)
	handler, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		//here must be changed to return the proper error
		return
	}
	defer handler.Close()
	src := gopacket.NewPacketSource(handler, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case packet = <-in:
			iPacket <- packet
		}
	}
}

func handleDnsPacket(iPacket *gopacket.Packet) {

		decodedLayers := []gopacket.LayerType{}
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload)
		err := parser.DecodeLayers((*iPacket).Data(), &decodedLayers)
		if err != nil {
			log.Println(err)
		}
		for _, layerT := range decodedLayers {
			if layerT == layers.LayerTypeDNS {
				/*
					for _, query := range dns.Questions {
						fmt.Printf("Type: %s, Class: %s\n Name: %s, Type: %s\n", query.Type.String(), query.Class.String(), string(query.Name), query.Type.String())
					}*/
				for _, answer := range dns.Answers {
					//for not printing all types of dns answers we will only print DNSTypeA
					//https://godoc.org/github.com/google/gopacket/layers#DNSType
					if answer.Type == 1 || answer.Type == 28 {
						fmt.Println(strings.Repeat("=", 10) + "ANSWER" + strings.Repeat("=", 10))
						fmt.Println("Name: ", string(answer.Name))
						fmt.Println("IP: ", answer.IP)
						fmt.Println("Type: ", answer.Type)
						fmt.Println(strings.Repeat("=", 10) + "ANSWER" + strings.Repeat("=", 10))
					}
				}
			}
		}
}

func Run(ifaceName, output string) error {
	iface, err := GetInterface(ifaceName)
	if err != nil {
		return err
	}
	dnsHandler := DNSHandler {
		printer: newPrinter(output),
	}
	iPacket := make(chan gopacket.Packet)

	go readInterface(iface, iPacket)
	for {
		select {
		case actualPacket := <-iPacket:
			if pdns := (actualPacket).Layer(layers.LayerTypeDNS); pdns != nil {
				go handleDnsPacket(&actualPacket)
			}
	}

	dnsHandler.printer.finish()
	printerWaitGroup.Wait()

	return nil
}
