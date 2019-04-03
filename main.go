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

func handlePacket(packet gopacket.Packet) gopacket.Packet {
	newData := processPacket(packet)
	newPacket := gopacket.NewPacket(newData, layers.LayerTypeIPv4, gopacket.Default)
	return newPacket
}

func processPcap(pacp string) {
	if handle, err := pcap.OpenOffline(pacp); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		i := 1
		for packet := range packetSource.Packets() {
			// if i == 22 {
			handlePacket(packet)
			// }
			i++
		}
	}
}

func processPacket(packet gopacket.Packet) []byte {
	packetLayers := packet.Layers()
	newPacket := make([]byte, 0)
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
		// if upd header add zeros to the header, so its size becomes 20 bytes (equal to TCP header) instead of 8 bytes
		if isUDPHeader(layer) {
			newUDPHeader := pad12ByteZeros(layer)
			newPacket = append(newPacket, newUDPHeader...)
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
		newPacket = append(newPacket, layer.LayerContents()...)
	}
	// (if ACK or FIN or SYN flags are set to 1) and (it has an empty app layer or it does not have it)
	// in otherwords if the packet is empty.
	// return nil
	if (isAck || isFin || isSyn) && (isAppLayerEmpty || !hasAppLayer) {
		return nil
	}
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
