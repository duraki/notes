---
title: "Network Reverse Engineering"
---

**Sniff & Decrypt HTTP/HTTPS Traffic on macOS/iOS**

The [harlogger](https://github.com/doronz88/harlogger) is a simple utlity for sniffing & decrypting HTTP/HTTPS traffic on a macOS/iOS device which is either jailbroken or not based on Apple's not-so-well documented APIs.

**Find broken URLs in Files**

The CLI utility `urlsup` can come handy when you want to find URLs in files, and check whether they are alive, by issuing a `GET` request and checking the response status code. The [simeg/urlsup](https://github.com/simeg/urlsup) is written in Rust, and executes using async requests in multiple threads, making it quite fast.

To install it, use:

```sh
$ cargo install urlsup
```

Usage is simple as:

```sh
$ urlsup `find . -name "*.md"`      # Finding URLs in folder in all files ending in (*.md)
$ urlsup README.md --white-list example.com,sample.tld   # Whitelist all links starting with example.com or sample.tld
$ urlsup README.md --allow 403,429  # Will allow status code errs: 403, 429
```

An alternative CLI app. with similar functionality, called [brok](https://github.com/smallhadroncollider/brok) is also available on GitHub.  

**Get TCP/UDP Socket Stats** - GNU/Linux Only!

Make sure to install [PabloLec/neoss](https://github.com/PabloLec/neoss) which will allow you to sort, refresh and navigate in TUI of the `neoss`. It's similar to `ss`, but has many advantages such is retrieval of protocol definition, states and queues, domain name resolution, detailed PE info, et al. **Supported by GNU/Linux only**, does not support macOS or WindowsNT.

```sh
$ npm install -g neoss
```

To launch, simply type:

```sh
$ neoss
```

**Creating Unix TCP Socket and passing FD Index to Child Process**

A CLI app. [catflap](https://github.com/passcod/catflap) is a small CLI tool for unix-likes that creates a TCP socket at the address you tell it to, then passes its FD index to a child process using an environment variable. The child (or any descendants) can then bind the socket.

```sh
$ cargo install catflap           # Install catflap
$ cargo install --force catflap   # Upgrade
```

To use it, pass the CLI arguments `catflap [options] -- <commands> [args...]`, like so:

```sh
$ catflap -e LISTEN_FDS -- <command> [args...]      # Environment variable that will hold the socket file descriptor
$ catflap -h 0.0.0.0 [--] <command> [args...]       # Any of IPv4/IPv6, but not domain names, to bind the socket to 
$ catflap -p 8000 [--] <command> [args...]          # Port to bind the socket to
```

Usually used in combination with [mitsuhiko/listenfd](https://github.com/mitsuhiko/listenfd) which acts as a support provider for ext. managed file descriptors.

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
* [tapioca](https://github.com/CERTCC/tapioca) - CERT Tapioca for MITM network analysis
