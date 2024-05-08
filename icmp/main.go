package main

import (
	"context"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type network struct {
	RoomId int
	Ip     string
	Mask   int
}

func main() {
	net := getNetworks()
	for _, v := range net {
		fmt.Println(v)
		c := pingCount(v.Ip, v.Mask)
		fmt.Println("現在の接続端末数：", c)
		fmt.Println("")
	}
}

func getNetworks() []network {
	file, err := os.Open("./network.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	r := csv.NewReader(file)
	rows, err := r.ReadAll()
	if err != nil {
		log.Fatal(err)
	}
	var net []network
	for i, v := range rows {
		if i == 0 {
			continue
		}
		id, _ := strconv.Atoi(v[0])
		mask, _ := strconv.Atoi(v[2])
		n := network{
			RoomId: id,
			Ip:     v[1],
			Mask:   mask,
		}
		net = append(net, n)
	}
	return net
}

func pingCount(ip string, m int) int {
	addr := &net.IPNet{
		IP:   net.ParseIP(ip).To4(),
		Mask: net.CIDRMask(m, 32),
	}
	pc, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
		return -1
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(2 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c := make(chan int)
	defer close(c)
	go readICMP(pc, ctx, c)
	if err := writeICMP(pc, addr); err != nil {
		log.Fatal(err)
		return -1
	}
	count := <-c
	return count
}

func readICMP(pc *icmp.PacketConn, ctx context.Context, c chan int) {
	count := 0
	for {
		select {
		case <-ctx.Done():
			c <- count
			return
		default:
			rb := make([]byte, 1500)
			n, addr, err := pc.ReadFrom(rb)
			if err != nil {
				continue
			}
			rm, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), rb[:n])
			if err != nil {
				continue
			}
			if rm.Type == ipv4.ICMPTypeEchoReply {
				_, ok := rm.Body.(*icmp.Echo)
				if ok {
					fmt.Println(addr.String())
					count++
				}
			}
		}
	}
}

func writeICMP(pc *icmp.PacketConn, addr *net.IPNet) error {
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff,
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return err
	}
	for _, ip := range getAllIPs(addr) {
		if _, err := pc.WriteTo(wb, &net.IPAddr{IP: ip}); err != nil {
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
