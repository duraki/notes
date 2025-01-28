---
title: "Decrypt IPA from AppStore"
---

Requires `iproxy` and `frida-ios-dump`. File will be generated in current directory with `*.ipa` extension. See [download IPA on macOS](/download-ipa-on-macos) note on how to download and prepare IPA if you don't have a jailbroken iPhone device. It might be possible to downgrade apps from AppStore without jailbroken device [using Charles Proxy](https://github.com/qnblackcat/How-to-Downgrade-apps-on-AppStore-with-iTunes-and-Charles-Proxy).

```
# => Start iproxy
$ iproxy 2222 22

# => Lists App from iOS processes
$ cd ~/util/re/ios/frida-ios-dump
$ python dump.py -l

PID Name Identifier
---
- App Name Here xxx.xxxxxx.xxxxxx.xx

# => Dump App from iOS device
$ ./dump.py xxx.xxxxxx.xxxxxx.xx
...
```

### macOS

A utility [foulplay](https://github.com/meme/apple-tools/tree/master/foulplay) might be used on macOS to decrypt a FairPlay encrypted binaries.
