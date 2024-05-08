package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	for _, iface := range interfaces {
		addr, err := checkInterface(iface)
		if err != nil {
			continue
		}
		fmt.Println(iface.Name, "で", addr, "を使用")
		c := arpCount(&iface, addr)
		fmt.Println("現在の接続端末数：", c)
	}
}

func checkInterface(iface net.Interface) (addr *net.IPNet, err error) {
	if addrs, err := iface.Addrs(); err != nil {
		return nil, err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}
	if addr == nil || addr.IP[0] == 127 || addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return nil, errors.New("")
	}
	return addr, nil
}

func arpCount(iface *net.Interface, addr *net.IPNet) int {
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return -1
	}
	defer handle.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c := make(chan int)
	defer close(c)
	go readARP(handle, iface, ctx, c)
	writeARP(handle, iface, addr)
	count := <-c
	return count
}

func readARP(handle *pcap.Handle, iface *net.Interface, ctx context.Context, c chan int) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	count := 0
	for {
		var packet gopacket.Packet
		select {
		case <-ctx.Done():
			c <- count
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				continue
			}
			if bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
				continue
			}
			count++
			fmt.Println("IP :", net.IP(arp.SourceProtAddress), ", MAC Addr :", net.HardwareAddr(arp.SourceHwAddress))
		}
	}
}

func writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	for _, ip := range getAllIPs(addr) {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func getAllIPs(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	network := num & mask
	broadcast := network | ^mask
	for network++; network < broadcast; network++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], network)
		out = append(out, net.IP(buf[:]))
	}
	return
}
