package dnsdumper

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
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

func readInterface(iface *net.Interface, iPacket chan<- gopacket.Packet, stop <-chan os.Signal) {
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
		case <-stop:
			return
		case packet = <-in:
			iPacket <- packet
		}
	}
}

func filterDnsPacket(iPacket *gopacket.Packet) {
	if pApplication := (*iPacket).Layer(layers.LayerTypeDNS); pApplication != nil {
		decodedLayers := []gopacket.LayerType{}
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload)
		err := parser.DecodeLayers((*iPacket).Data(), &decodedLayers)
		if err != nil {
			log.Println(err)
		}
		for _, layerT := range decodedLayers {
			if layerT == layers.LayerTypeDNS {
				for _, query := range dns.Questions {
					fmt.Printf("Type: %s, Class: %s\n Name: %s, Type: %s\n", query.Type.String(), query.Class.String(), string(query.Name), query.Type.String())
				}
			}
		}
	}
}

func Run(ifaceName string) error {
	iface, err := GetInterface(ifaceName)
	if err != nil {
		return err
	}
	fmt.Println("vim-go")
	iPacket := make(chan gopacket.Packet)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go readInterface(iface, iPacket, c)
	fmt.Println("Starting to sniff...")
	for {
		select {
		case actualPacket := <-iPacket:
			go filterDnsPacket(&actualPacket)
		case <-c:
			return errors.New("Program finished by user")
		}
	}
	return nil
}
