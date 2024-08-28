---
title: "C Plus Plus Demangler"
---

Install C++ demangler globally via `npm` using the following command:

```
$ npm i frida-compile demangler-js -g
```

Now in [Frida Script](/iOS-Frida-Scripting) you can use something like this snippet to demangle obfuscated C++ module or library:

```
const demangle = require('demangler-js').demangle;
...
Module.enumerateExportsSync('library.so')
  .filter(x => x.name.startsWith('_Z'))
  .forEach(x => {
    Interceptor.attach(x.address, {
      onEnter: function (args) {
        console.log('[-] ' + demangle(x.name));
      }
    });
  });
```

Compile via `frida-compile`:

```
$ frida-compile script.js -o out.js
```

Run the demangler with Frida as usual, but make sure to include newly compiled script:

```
$ frida -Uf com.app -l out.js
``` 

**References**

* [Reversing C++ QT-based Applications using Ghidra](https://ktln2.org/reversing-c%2B%2B-qt-applications-using-ghidra/)