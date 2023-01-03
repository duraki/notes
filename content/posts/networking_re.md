---
title: "Network Reverse Engineering"
---

**Using [`wireshark`](/wireshark)** is explained in seperated documentation. Please refer to Wireshark documentation for more extensive cheatsheet.

**using `fritap` to analyse network traffic encapsulated in SSL or TLS**

[fritap](https://github.com/fkie-cad/friTap) is a Python package that can be used to analyze network traffic on SSL/TLS transport layers. Works on SSL/TLS and supports all major operating systems (MacOS, iOS, Linux, Windows, Android). It is based on [frida](/frida), therefore it require `frida-server` to be up and running on the iOS/Android device.

Install fritap with the following command:

```
$ pip3 install fritap
$ friTap -h
  # friTap -m               # attach to Android or iOS process
  # friTap -k <key_path>    # log the keys used for TLS traffic
  # friTap -l               # create a named pipe in /tmp/sharkfin which can be read by wireshark
  # friTap -p <pcap_file>   # name of the PCAP file to write
  # friTap -s               # spawn the executable instead of attaching
  # friTap -v, --verbose    # show verbose output
  # friTap --enable_spawn_gating # catch newly spawned processes
  # friTap <app/pid>        # executable/app whose SSL calls to log
```

Usage examples:

For Linux/Windows/MacOS we can easily attach to a process by entering its name or its PID

```
$ friTap --pcap AppName.pcap AppName  # => store pcap file and trace an application
```

For Mobile applications, we need to append `-m` parameter to indicate attaching/spawning an Android or iOS app.

```
$ friTap -m --pcap AppName.pcap com.durakiconsulting.app  # => store pcap file and trace a mobile application
```

To log keys of the TLS traffic, you can use:

```
$ friTap -m -spawn --keylog AppKeyLogFile.log com.durakiconsulting.app
```

Using fritap in Python as a module:

```
# => from a command-line interface as a module
$ sudo -E python3 -m friTap.friTap --pcap AppName.pcap AppName

# => directly invokation via Bash script
$ which friTap  # => /home/<USER>/.local/bin/friTap
$ sudo -E /home/<USER>/.local/bin/friTap
```

Supported SSL/TLS implementations:

```
| Library                   | Linux         | Windows       | MacOSX   | Android  | iOS          |
|---------------------------|---------------|---------------|----------|----------|--------------|
| OpenSSL                   |     Full      | R/W-Hook only |  TBI     |   Full   | TBI          |
| BoringSSL                 |     Full      | R/W-Hook only |  KeyEo   |   Full   | KeyEo        |
| NSS                       | R/W-Hook only | R/W-Hook only |  TBI     |   TBA    | TBI          |
| GnuTLS                    | R/W-Hook only | R/W-Hook only |  TBI     |   Full   | TBI          |
| WolfSSL                   | R/W-Hook only | R/W-Hook only |  TBI     |   Full   | TBI          |
| MbedTLS                   | R/W-Hook only | R/W-Hook only |  TBI     |   Full   | TBI          |
| Bouncycastle/Spongycastle |     TBA       |    TBA        |  TBA     |   Full   | TBA          |
| Conscrypt                 |     TBA       |    TBA        |  TBA     |   Full   | TBA          |
```

* [Usage Documentation](https://github.com/fkie-cad/friTap/blob/main/USAGE.md)
* [Android TLS Traffic Analysis](https://github.com/fkie-cad/friTap/blob/main/EXAMPLE.md)

**Frida script to intercept encrypted APIs in iOS apps**

[frida-ios-intercept-api](https://github.com/noobpk/frida-ios-intercept-api) is a tool that can help intercept encrypted APIs in iOS apps. Banking Apps are constantly securing their production environments. One of the security measures I've came across is encrypted `request/response` data when communicating with HTTPS services. Some weak encryptions can be decrypted easily, but some stronger encryptions like RSA are difficult to tackle.

During a penetration testing of an iOS mobile application, I usually set a MITM proxy to intercept such traffic, build the API on the fly, and then attacking it. Unfortunately, this is not so easy with banking applications and e-Wallets; infact, most of the time these type of apps. uses end-to-end encrypted API, where the usual proxy interceptor (ie. Portswigger's BurpSuite) can not see what content does the API body contain. This method uses hooking technique to dump functions content that send and receives the network traffic data, right before they are encrypted.

Download and clone the repository to get started:

```
$ git clone https://github.com/noobpk/frida-ios-intercept-api
```

To use this script, first head out to Hopper Disassembler and identify the classes and methods the target iOS app use for network traffic; such is:

* `@class MobileBankingAppRequest` (method: `[sendRequest:]`)
* `@class MobileBankingAppResponse` (method: `[getResponse:]`)

Configure `handlers.js` file

```
# => set the identified classes and methods responsible for req/resp
/*Request Class & Method*/
var search_request_class  = ['MobileBankingAppRequest'];
var search_request_method = ['sendRequest:'];

/*Response Class & Method*/
var search_response_class  = ['MobileBankingAppResponse'];
var search_response_method = ['getResponse:'];`

# => debug the arguments of the method
                              /*DEBUG REQUEST */
console.log(colors.green,"[debug_request] Dump Arugment in method: ",colors.resetColor);
print_arguments(args);
console.log(ObjC.Object(args[3]));
var message1 = ObjC.Object(args[2]);
var message2 = ObjC.Object(args[3]);
var message3 = ObjC.Object(args[4]);

console.log('msg1=' + message1.toString() + ",type: "+ message1.$className);
console.log('msg2=' + message2.toString() + ",type: "+ message2.$className);
console.log('msg3=' + message3.toString() + ",type: "+ message3.$className);

/*                              DEBUG RESPONSE */
console.log(colors.green,"[debug_response] Dump Arugment in method: ",colors.resetColor);
# ...
```

Use **PortSwigger BurpSuite Proxy** with provided Configuration `.json`:

* Load `burpsuite_configuration_proxy.json` in BurpSuite Proxy
* Run `python echoServer.py` which acts as the proxy tunnel 
* Configure and optimize `handlers.js` for your environment
* Run `python burpTracer.py -p com.durakiconsulting.bankapp` # [-n 'BankApp']  

Hopefully, this will yield the traffic in your Terminal $stdout.

**using netstat (xnu) to print TCP entries for a specific PID**

```
$ netstat -anvp tcp | awk '{ if ($9 == PID) print }'

# => ie.
#  $ netstat -anvp tcp | awk '{ if ($9 == 1105) print }'
## tcp4       0      0  192.168.0.25.52952     52.0.253.194.443       ESTABLISHED 131072 131072   1105      0 0x0102 0x00000000
## tcp4       0      0  127.0.0.1.45112        *.*                    LISTEN      131072 131072   1105      0 0x0100 0x00000106
## tcp4       0      0  127.0.0.1.30666        *.*                    LISTEN      131072 131072   1105      0 0x0100 0x00000106
```

**using netstat (xnu) to dump inet, tcp or udp sockets**

```
$ netstat -anvp inet/tcp/udp # => pick one
# => other shorthands: inet,inet6,pfkey,atalk,netgraph,ipx,unix,link,sctp,udp,ddp (man netstat)
```

**using netstat (linux) to match a host to a socket**

```
$ netstat -a -c | grep -i example.com
```

**toolset**

* [fuzzotron](https://github.com/denandz/fuzzotron) - A TCP/UDP based network daemon fuzzer written in C
* [sslsplit](https://github.com/droe/sslsplit) - Transparent SSL/TLS interception 
* [ProtoDump](https://github.com/leptos-null/ProtoDump) - Obtain proto definition files using the Objective-C and Google Protobuf runtimes
* [dwarf_NetworkRequests](https://github.com/iGio90/NetworkRequests) - dwarf script to collect network requests, no need to unpin, hooks on low level functions
* [netzob](https://github.com/netzob/netzob) - Netzob: Protocol Reverse Engineering, Modeling and Fuzzing 