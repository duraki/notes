---
title: "iOS Frida Scripting"
---

Before start, make sure you follow [all of the typical](/ios-static-analysis) [iOS Reverse Engineering](/ios-reverse-engineering) processes, as well as how to [use lldb](/lldb) more professionally. The below Frida snippets will greatly increase your binary instrumentation knowledge.

**Check if Objective-C Runtime is available**

```
if (ObjC.available) { ... }
```

**Get Process ID (PID)**

```
Process.id
```

**Get Process current Thread ID**

```
Process.getCurrentThreadId()
``` 

**Enumerate Modules**

```
# Find Modules via Frida
Process.enumerateModules() 		// Print all loaded Modules
Process.findModuleByName("libboringssl.dylib") 		// Find Module by name, displays the information
Process.findModuleByAddress("0x1c1c4645c")   // Find Module by address, displays the information

# Find Address and Module of an export function name
DebugSymbol.fromAddress(Module.findExportByName(null, 'strstr'))

# Find Address of Export, and use Address to find Module
Module.findExportByName(null, 'strstr') 		// "0x183cb81e8"
Module.getExportByName(null,'strstr')			// "0x183cb81e8"
Process.findModuleByAddress("0x183cb81e8")

# Exports inside a Module
modules = Process.findModuleByName("Reachability")
modules.enumerateExports()
``` 

**Memory Manipulation**

```
Memory.allocUtf8String("Hello") 		// 0x1067ec510
Memory.readUtf8String("0x1067ec510") 	// Hello
ptr(0x1067ec510).readUtf8String(2)		// He

pointerToCString = new NativePointer(ptr(0x1067ec510)) // 0x1067ec510
console.log(pointerToCString.readCString(4)) // Hell
```

**Instance Methods and Static Methods**

```
ObjC.classes.NSString.$ownMethods
ObjC.classes.NSString.$ivars
ObjC.classes.NSUUID.alloc().init()			// 4645BFD2-94EE-413D-9CE5-8982D41ED6AE
ObjC.classes.NSString.stringWithString_("Howdy")	// isKindOfClass(ObjC.classes.NSString) = true
```

**Conversion of NSString to NSData and back to Hex**

```
var str = ObjC.classes.NSString.stringWithString_("Foo");
var nsd = ObjC.classes.NSData

nsd = str.dataUsingEncoding_(1)			// NSASCIIStringEncoding = 1, NSUTF8StringEncoding = 4,
console.log(nsd)						// <666f6f> 		since, foo to hex equals to '666f6f'

var byteHex = nsd.CKHexString()			// array of bytes as hex string
var byteStr = ObjC.classes.NSString.stringWithUTF8String_[nsd.bytes]
```

**Implement a `void(*)` method override**

```
// Example, a method checks if the user license is expired, and exits early in subroutine of it's function block
// - void(*) [AppDelegate checkUserLicenseExpired]

var appDelegateImpl = ObjC.classes.AppDelegate['- checkUserLicenseExpired'];
appDelegateImpl.implementation = ObjC.implement(appDelegateImpl, function() {
	var licensed = ptr(0x1);
	return; // returns from the overriden function block
});

// console.log("completed implementation replace mod")
``` 

**Intercept a Method and Examine the data passed and returned**

```
// Example, a method does mathematical calculations, and you want to see what happens during the execution, 
// you also want to know value of arguments passed, therefore
// - (bool) [UserLicenseRegistration validateSerialKey:withEmail:]

var licenseReg = ObjC.classes.UserLicenseRegistration['- validateSerialKey:withEmail:'];
Interceptor.attach(licenseReg.implementation, {

	/** Important */
	// Do remember that in Objective-C runtime, and the way the language works (ie. by sending Message to a Selector),
	// the first two (2) arguments of any implementation method is fixed on the stack, and they are referencing to
	//
	// #arg0  ->	1st Argument ->			Self			// the first argument is always pointer of self()
	// #arg1 -> 	2nd Argument ->			Msg Selector 	// the second argument is always pointer pointing to message selector, ie. a method called
	//
	// Therefore, it is not needed to examine these two arguments during any analysis phase. 
	/** [onEnter description] */
	onEnter(args) {
		var serialKey = ObjC.Object(args[2]) 	// as seen, as of 2nd parameter, we are getting real data of the method argument value
		var withEmail = ObjC.Object(args[3]) 	// as declared by method signature, this is last argument

		console.log(hexdump(serialKey)); 
	}

	/** [onLeave description] */
	// This callback event is fired whenever the app is leaving the method
	onLeave(retval) { 	 
        var hooking_return_val = ptr(0x1);		// will be BOOL(true)
        retval.replace(hooking_return_val);		// replace original retval with our variable
        console.log("\t [*] New Return Value: " + hooking_return_val);

        // boom :) bypassed serial key
	}

});
```

**Creating a Block (Handler)**

The following will define an Objective-C Block, that will be passed as a handler parameter to `+[UIAlertAction actionWithTitle:style:handler:]`. One important thing when creating Blocks is to respect the original block handler signature, as the blocks are methods on their own. Blocks are typically executed in async thread. 

``` 
/** [Block description] */
/**
 * Define a Block handler, as per Apple's documentation and their signature references.
 * @param {[type]} {    retType: 'void',    argTypes: ['object'],    implementation( [description]
 */
const handler = new ObjC.Block({
    retType: 'void',
    argTypes: ['object'],
    implementation() {
    }
});

// and then to use it;
const dismissAction = alertaction.actionWithTitle_style_handler_('Dismiss', 1, handler);
this.alerthook.addAction_(dismissAction);
```

**Creating a new Object instance**

... *via* allocation of class, and calling its constructor

```
var instance = ObjC.classes.ClassName.alloc().init()
```   

... *via* already allocated instance, directly visible on the Heap

```
var instances = ObjC.choose(ObjC.classes.ClassName)				// multiple instances may be shown
var instance = ObjC.chooseSync(ObjC.classes.ClassName)[0] 		// selecting a single instance from the heap
```

... *via* instance singleton, if class supports instance property

```
# Get a Signleton of the Class
var instance = ObjC.classes.SingletonClass.getInstance().myInterestingInstance()

# Call the method on the Signleton instance 
instance.setSomething()
instance.getSomething()
instance.doSomeTask()
# You may also pass an argument, if the method accepts it (ie. `- setSomething:`)
instance.setSomething_(argument) 	// make sure to use "_" instead of Objective-C's ":" separator
``` 

**Enumerating Type of the Method Arguments and Return Type**

This is great trick when you are lacking real RE environment, and you must know what Types are accepted. Luckly, Frida plays nice in such cases.

... to get **Argument Types** of a Class/Object Method

```
ObjC.classes.UIView['- addSubview:'].argumentTypes
[
    "pointer",
    "pointer",
    "pointer"
]
``` 

... to get **Return Type** of a Class/Object Method

```
ObjC.classes.UIView['- addSubview:'].returnType
"void"
``` 

... to get **low-level encoding** of Types (Internal ObjC)

```
ObjC.classes.UIView['- addSubview:'].types
"v24@0:8@16"
```

**Declare a variable outside of callback scope**

When writing larger scripts, or when the target attack surface is large, you can use `this.` to explicitly note that the variable is scoped to the stack at which the execution started. Otherwise, the local variables can't be reused in other callbacks (such is `onEnter()` and `onLeave()`).

```
Interceptor.attach((...).implementation, {
	onEnter: (...) {
		var callback_local = "Foo"
		this.stack_global = "Bar"
	},

	onLeave: (...) {
		// console.log(callback_local) // will result in error, undefined 'callback_local'
		console.log(this.stack_global) // will print Bar
	}
})
```

**Additional options for `hexdump`**

This small keyword allows you do dump anything residing at specific memory address, native functions, pointer or any other blob data.

```
console.log(hexdump(ptr(this.data))		// dumps this.data in a hexadecimal forma, with default opts

console.log(hexdump(ptr(this.data), {   // dumps this.data but with specific display opts
	length: 1000,	/* max number of chars in hexview */
	header: true,	/* also include table header */
	ansi: true 		/* display in ansi */
})) 
```

## Objective-C

**Using Frida scripting to hook on the Module, and Exports**

```
Interceptor.attach(Module.findExportByName(null, 'tls_record_encrypt'), {
	onEnter: function (args) {
		// ...
	}
})
```

**Using Frida scripting to hook on the NSURLSession completionHandler**

The below snippet is an example on how to utiliese Frida scripting engine, and override the completion handler or a block. The parameters, data, and request will be displayed first, and after that, the original completion handler will continue.

```
stored = null /* a variable that will store/contain original completionHandler block */

Interceptor.attach(ObjC.classes.NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation, { 	// Hook on NSURLSession*completionHandler
	onEnter: function (args) {
		this.object_selector = "-[NSURLSession dataTaskWithRequest:completionHandler:]"
		console.log("onEnter -- " + this.title)

		requestObj = ObjC.Object(args[2]) // args[2] is dataTaskWithRequest:* value
		console.log("Request " + requestObj)

		completionHandler = new ObjC.Block(args[3]) // store the original completion handler
		stored = completionHandler.implementation

		/* (re)use completionHandler method implementation */
		completionHandler.implementation = function (data, response, error) { 	// the block shall respect original implementation
			// print completionHandler Network Response
			console.log("Response: " + requestObj)
			console.log(ObjC.Object(response))

			// Getting ahold of data
			dat = ObjC.Object(data) // 'data' is an NSData object
			datLen = dat.length() // Length of 'data' from the completion
			datBytes = dat.bytes() // Get the data in bytes

			// Displaying data
			console.log(hexdump(dat, {ansi:true, length:len}))
			# alternative:
			# console.log(Memory.readUtf8String(dat))

			// Call original completion block
			return stored(data, response, error)
		}
	},

	onLeave: function (retval) {
		console.log("onLeave -- " + this.title)
	}
})
```

## Swift


### References

- [Crypto Hooks via Frida Scripting](https://github.com/theart42/hack.lu/blob/master/IOS/Notes/05-Crypt/00-crypto-hooks.md)
- [Using Frida Scripting to hijack NSURLSession](https://flippingbitz.com/post/2020-05-12-frida-instrumentation-ios-nsurlsession/) - *doing so, you avoid SSL pins, web proxy, mitm attacks*


