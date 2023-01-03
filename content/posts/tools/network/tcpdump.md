---
title: tcpdump
---

This document explains `tcpdump` advanced filters.

## Basic Syntax

### Filtering Hosts

```
# => Match any traffic involving 192.168.1.1 as destination or source
$ tcpdump -i eth1 host 192.168.1.1

# => As soure only
$ tcpdump -i eth1 src host 192.168.1.1

# => As destination only
$ tcpdump -i eth1 dst host 192.168.1.1
```

### Filtering Ports

```
# => Match any traffic involving port 25 as source or destination
$ tcpdump -i eth1 port 25

# => Source
$ tcpdump -i eth1 src port 25

# => Destination
$ tcpdump -i eth1 dst port 25
```

### Network Filtering

```
$ tcpdump -i eth1 net 192.168
$ tcpdump -i eth1 src net 192.168
$ tcpdump -i eth1 dst net 192.168
```

### Protocol Filtering

```
$ tcpdump -i eth1 arp
$ tcpdump -i eth1 ip
$ tcpdump -i eth1 tcp
$ tcpdump -i eth1 udp
$ tcpdump -i eth1 icmp
```

### Combining Expressions

* **Negation:** `!` or `not`
* **Concatanate:** `&&` or `and`
* **Alternate:** `||` or `or` 

```
# => This rule will match any TCP traffic on port 80 (web) with 192.168.1.254 or 192.168.1.200 as destination host
$ tcpdump -i eth1 '((tcp) and (port 80) and ((dst host 192.168.1.254) or (dst host 192.168.1.200)))'

# => Will match any ICMP traffic involving the destination with physical/MAC address 00:01:02:03:04:05
$ tcpdump -i eth1 '((icmp) and ((ether dst host 00:01:02:03:04:05)))'

# => Will match any traffic for the destination network 192.168 except destination host 192.168.1.200
$ tcpdump -i eth1 '((tcp) and ((dst net 192.168) and (not dst host 192.168.1.200)))'
```

## Advanced Syntax

### Advanced Header Filtering

Before we continue, we need to know how to filter out info from headers

* proto[x:y]    : will start filtering from byte x for y bytes. ip[2:2] would filter bytes 3 and 4 (first byte begins by 0)
* proto[x:y] & z = 0  : will match bits set to 0 when applying mask z to proto[x:y]
* proto[x:y] & z !=0  : some bits are set when applying mask z to proto[x:y]
* proto[x:y] & z = z  : every bits are set to z when applying mask z to proto[x:y]
* proto[x:y] = z    : p[x:y] has exactly the bits set to z
* Operators : >, <, >=, <=, =, !=

### IP option set in the Packet Header

Let's say we want to know if the IP header has options set. We can't just try to filter out the 21st byte
because if no options are set, data start at the 21st byte. We know a "normal" header is usually 20 bytes 
(160 bits) long. With options set, the header is longer than that. The IP header has the header 
length field which we will filter here to know if the header is longer than 20 bytes.

```
  +-+-+-+-+-+-+-+-+
  |Version|  IHL  |
  +-+-+-+-+-+-+-+-+
```

Usually the first byte has a value of 01000101 in binary. Anyhow, we need to divide the first byte in half, like so:

* `0100` = 4 in decimal. This is the IP version.
* `0101` = 5 in decimal. This is the number of blocks of 32 bits in the headers. 5 x 32 bits = 160 bits or 20 bytes.

The second half of the first byte would be bigger than 5 if the header had IP options set. We have two ways of dealing with that kind of filters.

1. Try to match a value bigger than 01000101
2. By "masking" the first half of the byte


**References**

* [tcpdump manpage](http://www.tcpdump.org/tcpdump_man.html)
* [tcpdump filters](https://github.com/SergK/cheatsheat-tcpdump/blob/master/tcpdump_advanced_filters.txt)