# Device Counter

ネットワーク内(Wi-Fi等)のデバイス数をカウントするプログラム\
ICMPを用いたものと、ARPを用いたものの2パターン\
同人誌[ICMPとARPを使って端末数を取得する本 with Golang](https://techbookfest.org/product/grANMCWwaEMshZTvmAjUT2?productVariantID=uZ7ZdHa2Q8ph3eKD9bvWHg)に掲載したプログラム

## 実行方法
ICMP、ARPのどちらの方式でもsudo権限で実行

### ICMP

```sh
$ sudo go run icmp/main.go
```

### ARP

```sh
$ sudo go run arp/main.go
```
