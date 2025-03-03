---
title: "Frida & Objection Tutorial (Android)"
url: "frida-objection-tutorial-android"
---

## Android Tutorial

### Frida Setup

Make sure to have Android Debugging interface running (`adbd`) on your testing device. For reference, read the [adbd setup](#adbd-setup) first and then continue here.

Install the Frida for [Android](https://frida.re/docs/android/):

```
$ adb root # might be required
$ adb push frida-server /data/local/tmp/
$ adb shell "chmod 755 /data/local/tmp/frida-server"
$ adb shell "/data/local/tmp/frida-server &"
```

Smoke test on Frida setup:

```
$ adb devices -l
$ frida-ps -U
# PID NAME 1590 com.facebook.katana
# 13194 com.facebook.katana:providers
# 12326 com.facebook.orca
# 13282 com.twitter.android
...
```

### `adbd` setup

* Change all SELinux permissions to **Permissable**
* Use SELinuxPermission Android application, which checks for `getenforce` on a system reboot
* In MagiskManager application, enable the [ADB Root](https://github.com/evdenis/adb_root)
* When device is rebooting, USB debugging will not work out of the box
* SSH to Android device, using OpenSSHD
* In SSH shell type the following:

```
# => On Android device (ssh)
% su
% whoami
% adbd

# => On Attackers machine (duh)
$ adb root
$ adb shell
(android) $ whoami # => root
```

## Frida

Get Android Application Context in Frida:

```javascript
Java.perform(function () {
	var currentApplication = Java.use('android.app.ActivityThread').currentApplication();
	var context = currentApplication.getApplicationContext();  
})
```

Get Android Application Implementation Frame:

```javascript
Java.perform(function() {
    var mainActivity = Java.use("com.example.app");
    mainActivity.SomeMethod.implementation = function() {
        console.log("\n Exit Called");
    };
})
```

Hook URL Constructor of Android Application:

```javascript
// url-contructor.js
'use strict';
console.log("[*] Hooking URL constructor");
Java.perform(function(){
    var url = Java.use("java.net.URL");
    url.$init.overload('java.lang.String').implementation = function(url) {
	console.log("URL: "+url);
	return this.$init(url);
    }
});
```

Native Functions Hooking on Android:

```javascript
// native-hook.js
// @author: https://pentest.blog/android-malware-analysis-dissecting-hydra-dropper/
var unlinkPtr = Module.findExportByName(null, 'unlink');
// remove bypass
Interceptor.replace(unlinkPtr, new NativeCallback( function (a){
     console.log("[+] Unlink : " +  Memory.readUtf8String(ptr(a)))
}, 'int', ['pointer']));
var timePtr = Module.findExportByName(null, 'time');
// time bypass
Interceptor.replace(timePtr, new NativeCallback( function (){
    console.log("[+] native time bypass : ")
    return 1554519179
},'long', ['long']));
Java.perform(function() {
    var f = Java.use("android.telephony.TelephonyManager")
    var t = Java.use('java.util.Date')
    //country bypass
    f.getSimCountryIso.overload().implementation = function(){
        console.log("Changing country from " + this.getSimCountryIso() + " to tr ")
        return "tr"
    }
    t.getTime.implementation = function(){
    console.log("[+] Java date bypass ")
    return 1554519179000 
    }
 })
```

Native Library Hooking on Android:

```javascript
// libhook.js

'use strict';
console.log("[*] Hooking native library  ");

Java.perform(function(){
    var library = Java.use("com.android.a");

    library.a.implementation = function(ctx, s) {
	console.log("[+] native.a: s="+s);
	var ret = this.a(ctx,s);
	console.log("[+] native.a returns ret="+ret);
	return ret;
    }

    library.b.implementation = function(ctx, a, s) {
	console.log("[+] native.b: s="+s);
	var ret = this.b(ctx,a,s);
	console.log("[+] native.b returns ret="+ret);
	return ret;
    }
});
```

Hooking Dynamic Class/Methods on Android:

```javascript
// dynamic-hook.js

'use strict';
console.log("[*] Hooking dynamic class / method ");

Java.perform(function(){
    var dexclassLoader = Java.use("dalvik.system.DexClassLoader");
    
    dexclassLoader.loadClass.overload('java.lang.String').implementation = function(name){
        var dyn_class_name = "PUT COMPLETE NAME OF DYNAMICALLY LOADED CLASS";
        var result = this.loadClass(name,false);
        if(name == dyn_class_name){
            var active_classloader = result.getClassLoader();
            var factory = Java.ClassFactory.get(active_classloader);
            var class_hook = factory.use(dyn_class_name);
            class_hook.PUTNAMEOFMETHOD.implementation = function(encrypted) {
                // WRITE HOOK FOR a()
                // HERE
                return decrypted;
	        }

            return result;
        }

        return result;
    }
});
```

Frida script to restore and re-insert logs:

Sometimes, logs have been disabled. The function to log is more or less there but it has been hidden. Or you want to show each time a given function is called. The hook looks as follows.

1. Specify the class you want to hook (my.package.blah.MyActivity)
2. Specify the name of the method to hook (a)
3. If there are several methods with that name, you'll need to tell frida which one to use by using the correct signature. Use overload() for that.
4. The arguments for the function are to be passed in function(..). Here for example the function has one argument mystr

```javascript
// restore-logs.js

console.log("[*] Loading script");

// check if Java environment is available
if (Java.available) {
    console.log("[*] Java is available");

    Java.perform(function() {
        console.log("[*] Starting Frida script to re-insert logs");
	bClass = Java.use("my.package.blah.MyActivity");
	
        bClass.a.overload('java.lang.String').implementation = function(mystr) {
          console.log("[*] method a() clicked: "+mystr);
        }
       console.log("[*] method a() handler modified")
    });
}
```

In-memory Dex Class Dumping:

```javascript
// dex-dump.js
// @author: https://github.com/cryptax/misc-code/blob/master/frida_hooks/dex-dump.js

console.log("[*] DexClassLoader/PathClassLoader/InMemoryDexClassLoader Dump v0.9 - @cryptax");

/* Inspired from https://awakened1712.github.io/hacking/hacking-frida/ */
Java.perform(function () {
    const classLoader = Java.use("dalvik.system.DexClassLoader");
    const pathLoader = Java.use("dalvik.system.PathClassLoader");
    const memoryLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
    const delegateLoader = Java.use("dalvik.system.DelegateLastClassLoader");
    const File = Java.use('java.io.File');
    const FileInputStream = Java.use("java.io.FileInputStream");
    const FileOutputStream = Java.use("java.io.FileOutputStream");
    const ActivityThread = Java.use("android.app.ActivityThread");
    var counter = 0;

    function dump(filename) {
        var sourceFile = File.$new(filename);
        var fis = FileInputStream.$new(sourceFile);
        var inputChannel = fis.getChannel();

        var application = ActivityThread.currentApplication();
        if (application == null) return ;
        var context = application.getApplicationContext();

        // you cannot dump to /sdcard unless the app has rights to!
        var fos = context.openFileOutput('dump_'+counter, 0);
        counter = counter + 1;

        var outputChannel = fos.getChannel();
        inputChannel.transferTo(0, inputChannel.size(), outputChannel);
        fis.close();
        fos.close();

        console.log("[*] Dumped DEX to dump_"+counter);
    }


    classLoader.$init.implementation = function(filename, b, c, d) {
	    console.log("[*] DexClassLoader hook: file="+filename);  
        dump(filename);
        return this.$init(filename, b, c, d);
    }

    pathLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(filename, parent) {
        console.log("[*] PathClassLoader(file="+filename+', parent)');
        dump(filename);
        return this.$init(filename, parent);
    }

    pathLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(filename, librarySearchPath, parent) {
        console.log("[*] PathClassLoader(file="+filename+", librarySearchPath, parent)");
        dump(filename);
        return this.$init(filename, librarySearchPath, parent);
    }

    delegateLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(filename, parent) {
        console.log("[*] DelegateLastClassLoader(file="+filename+', parent)');
        dump(filename);
        return this.$init(filename, parent);
    }

    delegateLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(filename, librarySearchPath, parent) {
        console.log("[*] DelegateLastClassLoader(file="+filename+", librarySearchPath, parent)");
        dump(filename);
        return this.$init(filename, librarySearchPath, parent);
    }

    delegateLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader', 'boolean').implementation = function(filename, librarySearchPath, parent, resourceLoading) {
        console.log("[*] DelegateLastClassLoader(file="+filename+", librarySearchPath, parent, resourceLoading)");
        dump(filename);
        return this.$init(filename, librarySearchPath, parent, resourceLoading);
    }

    memoryLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function(dexbuffer, loader) {
	    var object = this.$init(dexbuffer, loader);

	    /* dexbuffer is a Java ByteBuffer */
	    var remaining = dexbuffer.remaining();
	
        var filename = 'dump_' + counter;
        counter = counter + 1;
	    console.log("[*] Opening file name="+filename+" to write "+remaining+" bytes");

	    const f = new File(filename,'wb');
	    var buf = new Uint8Array(remaining);
	    for (var i=0;i<remaining;i++) {
	        buf[i] = dexbuffer.get();
	        //debug: console.log("buf["+i+"]="+buf[i]);
	    }
	    console.log("[*] Writing "+remaining+" bytes...");
	    f.write(buf);
	    f.close();
	
	    // checking
	    remaining = dexbuffer.remaining();
	    if (remaining > 0) {
	        console.log("[-] Error: There are "+remaining+" remaining bytes!");
	    } else {
	        console.log("[+] Dex dumped successfully in "+filename);
	    }
        return object;
    }

});
```

### Objection Setup

Enter the Objection REPL using the following command:

```
$ objection -g [PACKAGE_NAME] explore
```

Then within the Objection REPL, you can:

```
> android clipboard monitor                     # monitor pasteboard and clipboard changes
> android hooking get current_activity          # get current app activity
> android hooking generate simple classname     # generate a Frida hook
> android hooking list activities               # list all app activities
> android hooking search classes [ClassName]    # list all classes in app containing the string ClassName
> android hooking list class_methods [ClassName]# list methods with-in the class ClassName
> android hooking list classes                  # list all loaded classes from the app
> android hooking watch class_method [METHOD] --dump-args --dump-return     # watch methods in class and dump their params/retval - use `$init` for a contructor
> android hooking watch class [ClassName] --dump-args --dump-return         # watch the whole class and dump the callee params/retval
```

To launch a hook at startup, use Objection's `--startup-command` argument:

```
$ objection --gadget [PACKAGE_NAME] explore --startup-command 'android hooking watch class_method java.net.URL.$init --dump-args --dump-return
```



## Other Resources

* [OWASP MASTG: Objection for Android](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0029/)
* [OWASP MASTG: Frida for Android](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/)