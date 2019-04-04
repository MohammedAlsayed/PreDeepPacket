package main

import (
	"io/ioutil"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	_, err := ioutil.ReadDir("./pcaps/")
	if err != nil {
		log.Fatal(err)
	}
	processPcap("./pcaps/youtube2.pcap")
	// for _, f := range files {
	// 	processPcap("./pcaps/" + f.Name())
	// }
}

func processPcap(pacp string) {
	if handle, err := pcap.OpenOffline(pacp); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		i := 1
		for packet := range packetSource.Packets() {
			if i == 110 {
				handlePacket(packet)
			}
			i++
		}
	}
}

func handlePacket(packet gopacket.Packet) gopacket.Packet {
	newPacket := processPacket(packet)
	return newPacket
}

func processPacket(packet gopacket.Packet) gopacket.Packet {
	packetLayers := packet.Layers()
	packetData := make([]byte, 0)
	isAck := false
	isFin := false
	isSyn := false
	isAppLayerEmpty := false
	hasAppLayer := false
	for _, layer := range packetLayers {

		// skip data-link layer
		if isDataLinkLayer(layer) {
			continue
		}
		// remove DNS packet
		if isDNS(layer) {
			return nil
		}
		// if upd header add zeros to the header, so its size becomes 20 bytes (equal to TCP header) instead of 8 bytes
		if isUDPHeader(layer) {
			newUDPHeader := pad12ByteZeros(layer)
			packetData = append(packetData, newUDPHeader...)
			continue
		}
		if isNetworkLayer(layer) {
			isAck = isACK(layer)
			isFin = isFIN(layer)
			isSyn = isSYN(layer)
		}
		if isApplicationLayer(layer) {
			hasAppLayer = true
			isAppLayerEmpty = len(layer.LayerContents()) == 0
		}
		packetData = append(packetData, layer.LayerContents()...)
	}
	// (if ACK or FIN or SYN flags are set to 1) and (it has an empty app layer or it does not have it)
	// in otherwords if the packet's payload is empty, remove the packet.
	// return nil
	if (isAck || isFin || isSyn) && (isAppLayerEmpty || !hasAppLayer) {
		return nil
	}
	newPacket := gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)
	return newPacket
}

func isDataLinkLayer(layer gopacket.Layer) bool {
	return layer.LayerType() == layers.LayerTypeEthernet
}
func isUDPHeader(layer gopacket.Layer) bool {
	return layer.LayerType() == layers.LayerTypeUDP
}
func pad12ByteZeros(layer gopacket.Layer) []byte {
	zeros := make([]byte, 12)
	udpContent := layer.LayerContents()
	return append(udpContent, zeros...)
}
func isACK(layer gopacket.Layer) bool {
	flags := layer.LayerContents()[13]
	ackFlag := byte(0x10)
	if flags&ackFlag == ackFlag {
		return true
	}
	return false
}

func isSYN(layer gopacket.Layer) bool {
	flags := layer.LayerContents()[13]
	synFlag := byte(0x2)
	if flags&synFlag == synFlag {
		return true
	}
	return false
}

func isFIN(layer gopacket.Layer) bool {
	flags := layer.LayerContents()[13]
	finFlag := byte(0x1)
	if flags&finFlag == finFlag {
		return true
	}
	return false
}

func isNetworkLayer(layer gopacket.Layer) bool {
	return layer.LayerType() == layers.LayerTypeTCP
}

func isApplicationLayer(layer gopacket.Layer) bool {
	return layer.LayerType() == gopacket.LayerTypePayload
}

func isDNS(layer gopacket.Layer) bool {
	if isUDPHeader(layer) {
		udpContent := layer.LayerContents()
		for i := 0; i < 4; i++ {
			if udpContent[i] == 53 {
				return true
			}
		}
	}
	return false
}
