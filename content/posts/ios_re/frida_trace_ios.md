---
title: "Frida Trace for iOS"
---

You can imagine application as a black box that interacts with the outer world via inputs and outputs. Ordinary mobile application has specific threat model. Particularly, filesystem and network communication are pretty interesting interaction points which can give you a lot of useful information.

**Using `frida-discover` to get some idea where to start**

```
$ frida-discover -U com.iosapp.example
# libcommonCrypto.dylib
#         Calls           Function
#         15              sub_bec0
#         15              sub_bee4
#         8               sub_96f8
#         8               sub_befc
#         3               CCDigest
```

**Using `frida-trace` to find NSURLSession tasks**

```
# via Simulator
$ frida-trace -R Gadget -m '-[NSURLSession dataTaskWithURL:*]'

# via Device
$ frida-trace -U Gadget -m '-[NSURLSession dataTaskWithURL:*]'
```

This will yield, something similar to:

```
Instrumenting functions...
-[NSURLSession dataTaskWithURL:completionHandler:]: Auto-generated handler at "/private/tmp/__handlers__/__NSURLSession_dataTaskWithURL_c_01cef27d.js"
-[NSURLSession dataTaskWithURL:]: Auto-generated handler at "/private/tmp/__handlers__/__NSURLSession_dataTaskWithURL__.js"
Started tracing 2 functions. Press Ctrl+C to stop.
           /* TID 0x303 */
  4206 ms  -[NSURLSession dataTaskWithURL:0x6040002e3b80 completionHandler:0x604000447f80 ]
  ...
```

**ObjC wildcard tracing**

```
$ frida-trace -U -f com.iosapp.example -m "*[AppClassName *]"
```

**Tracing Swift mangled functions**

```
$ frida-trace -U -f com.iosapp.example -m "*[AppName.UserProfileMngr *]"
```

**Tracing C functions on iOS**

```
$ frida-trace -U -f com.iosapp.example -i "getaddrinfo"
```

**Trace entire Module** **`not advised`**

```
// avoid executing this.

/* trace *.dylib */
$ frida-trace -U -f com.iosapp.example -I libsystem_c.dylib

/* trace module name */
$ frida-trace -U -f com.iosapp.example -I UIKit
```

**Trace Files and HTTP/API connections**

```
$ frida-trace -U -f com.iosapp.example -m "-[NSURLRequest initWithURL:]"
$ frida-trace -U -f com.iosapp.example -m "-[NSURL initWithString:]"
$ frida-trace -U -f com.iosapp.example -m "*[NSURL absoluteString]"
```

**Using auto-generated Frida handler for System functions**

```
// Generate Frida handler
$ frida-trace -U -f com.iosapp.example -i "*strcpy"
# Instrumenting functions...                                              
#  _platform_strcpy: Loaded handler at "/.../__handlers__/libSystem.B.dylib/_platform_strcpy.js"
#  Started tracing 1 function. Press Ctrl+C to stop.

// Edit Frida handler
$ vi _platform_strcpy.js
// onEnter: function (log, args, state) {
//     // strcpy(dst, src);
//     console.log("[*] _platform_strcpy()");
//     var src_ptr = args[1].toString();
//     var str_string = Memory.readCString(args[1]);
//     var src_byteary = Memory.readByteArray(args[1], 4);
//     var textDecoder = new TextDecoder("utf-8");
//     var decoded = textDecoder.decode(src_byteary);
// 
//     console.log('[+] src_ptr\t-> ' , src_ptr);
//     console.log('[+] src_string\t-> ' + src_string);
//     console.log('[+] src_byteary\t-> ' + src_byteary);
//     console.log('[+] src_byteary size\t-> ' + src_byteary.byteLength);
//     console.log('[+] src_byteary decoded\t-> ' + decoded);
// }
```

**Describe class members and their values, of each class instance**

```
ObjC.choose(ObjC.classes[clazz], {
  onMatch: function (obj) {
    console.log('onMatch: ', obj);
    Object.keys(obj.$ivars).forEach(function(v) {
        console.log('\t', v, '=', obj.$ivars[v]);
    });
  },
  onComplete: function () {
    console.log('onComplete', arguments.length);
  }
});
```

**Advanced observing and tracing via Frida Scripts**

The following Frida Function will take `ClassName` as an input, and print all observations and recursive calls being executed in the traced method block. To use simply call **`observeClass('Someclass$innerClass');`** from the Frida REPL, after injecting the script into target process. 


```
# observeClass('Someclass$innerClass');
# ...
# Observing Someclass$innerClass - func
# Observing Someclass$innerClass - empty
# (0x174670040,parameterName) Someclass$innerClass - func
# 0x10048dd6c libfoo!0x3bdd6c
# 0x1005a5dd0 libfoo!0x4d5dd0
# 0x1832151c0 libdispatch.dylib!_dispatch_client_callout
# 0x183215fb4 libdispatch.dylib!dispatch_once_f
# RET: 0xabcdef

function observeClass(name) {
    var k = ObjC.classes[name];
    k.$ownMethods.forEach(function(m) {
        var impl = k[m].implementation;
        console.log('Observing ' + name + ' ' + m);
        Interceptor.attach(impl, {
            onEnter: function(a) {
                this.log = [];
                this.log.push('(' + a[0] + ',' + Memory.readUtf8String(a[1]) + ') ' + name + ' ' + m);
                if (m.indexOf(':') !== -1) {
                    var params = m.split(':');
                    params[0] = params[0].split(' ')[1];
                    for (var i = 0; i < params.length - 1; i++) {
                        try {
                            this.log.push(params[i] + ': ' + new ObjC.Object(a[2 + i]).toString());
                        } catch (e) {
                            this.log.push(params[i] + ': ' + a[2 + i].toString());
                        }
                    }
                }

                this.log.push(
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress)
                        .join('\n')
                );
            },

            onLeave: function(r) {
                try {
                    this.log.push('RET: ' + new ObjC.Object(r).toString());
                } catch (e) {
                    this.log.push('RET: ' + r.toString());
                }

                console.log(this.log.join('\n') + '\n');
            }
        });
    });
}
```