---
title: "iOS Frida Scripting"
---

Before start, make sure you follow [all of the typical](/ios-static-analysis) [iOS Reverse Engineering](/ios-reverse-engineering) processes, as well as how to [use lldb](/lldb-on-ios) more professionally. The below Frida snippets will greatly increase your binary instrumentation knowledge.

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

**List all Classes**

```
// Iterate through all classes
Object.keys(ObjC.classes).forEach(function (className) { ... });

// Iterate through all classes via for-loop
for (var className in ObjC.classes) {
  if (ObjC.classes.hasOwnProperty(className)) { ... }
}

// Iterate without filtering
ObjC.enumerateLoadedClassesSync();
// Iterate with filtering
ObjC.enumerateLoadedClassesSync({
  "ownedBy: someModule"
});

// Count number of classes
Object.keys(ObjC.classes).length;
```

**List all Protocols**

```
// Iterate through all protocols
Object.keys(ObjC.protocols).forEach(function (protocol) { ... });

// Iterate through all protocols via for-loop
for (var protocolName in ObjC.protocols) {
  if (ObjC.protocols.hasOwnProperty(protocolName)) { ... }
}

// Count number of protocols
Object.keys(ObjC.protocols).length;
```

**Enumerate Modules**

```
# Find Modules via Frida
Process.enumerateModules() 				// Print all loaded Modules
Process.findModuleByName("Reachability")  // Find Module by Absolute Module name
Process.findModuleByName("libboringssl.dylib") 		// Find Module by name, displays the information
Process.findModuleByAddress("0x1c1c4645c")   		// Find Module by address, displays the information

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
Memory.readUtf8String("0x1067ec510") 		// Hello
ptr(0x1067ec510).readUtf8String(2)		// He

pointerToCString = new NativePointer(ptr(0x1067ec510)) // 0x1067ec510
console.log(pointerToCString.readCString(4)) 	       // Hell
```

**Instance Methods and Static Methods**

```
ObjC.classes.SomeClass.$ownMethods;    // Class Static Methods
ObjC.classes.SomeClass.$ivars;         // Class Instance Variables
ObjC.classes.NSUUID.alloc().init()			// 4645BFD2-94EE-413D-9CE5-8982D41ED6AE
ObjC.classes.NSString.stringWithString_("Howdy")	// isKindOfClass(ObjC.classes.NSString) = true
```

**Instance and Class kind**

```
ObjC.classes.NSDate.date().$kind;     // "instance" 
ObjC.classes.NSDate.$kind;            // "class" 
ObjC.classes.NSDate.$class.$kind;     // "meta-class" 
```

**Construct an Object from pointer**

```
// NSString * str = [NSString stringWithUTF8String: "Badger"];
var str = new ObjC.Object("0xPTRVAL");
str.toString();   // "badger"
```

**Working with `ArrayBuffer` in Frida**

The `ArrayBuffer` type in Frida does not have a `.length` property, only `.byteLength`. If you want to access individual bytes on the `ArrayBuffer` object, you must declare `Uint8Array` first, and fill it with individual values.

```
var data = new ObjC.Object(obj.$ivars.exampleNSDataVar);
var arrayBuffer = data.bytes().readByteArray(data.length()); // <101a08be 1000ce0a ...>
    /** arrayBuffer instaceof [object ArrayBuffer] */

var arrayBufInt = new Uint8Array(arrayBuffer);
var arrayBufString = "";

for (var i = 0; i < arrayBufInt.length; i++) {
  arrayBufString += (arrayBufInt[i].toString(16) + " ");
}

console.log(arrayBufString); // 10 1a 08 be 10 00 ce 0a ...
``` 

**Construct an NSString**

```
var NSString = ObjC.classes.NSString;
NSString.stringWithUTF8String_(Memory.allocUtf8String("Hello")); // Hello
NSString.stringByAppendingString_("World");   // Hello World
```

**Conversion of NSString to NSData**

```
var str = ObjC.classes.NSString.stringWithString_("Foo");
var data = ObjC.classes.NSData;
data = str.dataUsingEncoding_(1)			// NSASCIIStringEncoding = 1, NSUTF8StringEncoding = 4
console.log(data)				// <666f6f> since, foo to hex equals to '666f6f'
```

**Conversion of NSData to NSString**

```
var data = ObjC.classes.NSData; // alloc + init = <666f6f>
var byteHex = data.CKHexString()      // array of NSData bytes as hex string
    // byteHex.$className = NSTaggedPointerString

var str = ObjC.classes.NSString.stringWithUTF8String_[byteHex.bytes]
```

**Construct an NSMutableDictionary**

```
var dict = ObjC.classes.NSMutableDictionary.alloc.init();
var key  = "ExampleKey";
var value = "ExampleValue";
dict.setObject_forKey_(value, key);   // ["ExampleKey", "ExampleValu"]
```

**Object Superclass and Class**

```
var str = ObjC.classes.NSString.stringWithString_("hello");

str.superclass().toString();      // "NSString"
str.class().toString();           // "NSTaggedPointerString"

ObjC.classes.NSDate.$super.$ClassName    // "NSObject"
ObjC.classes.NSObject.$super    // "null"
``` 

**Retrieve Modules by ObjC class**

```
ObjC.classes.NSString.$moduleName           # /System/Library/Frameworks/Foundation.framework/...
ObjC.classes.NSString.stringWithString_("badger").$moduleName # /System/Library/Frameworks/CoreFoundation.framework/...
``` 

**Using Interceptor to monitor File Open**

```
// Find Export of targeted function
var fileHandler = Module.findExportByName("libsystem_kernel.dylib", "open");

Interceptor.attach(fileHandler, {
  onEnter: function (args) {
    const path = Memory.readUtf8String(this.context.x0);  // x0 = register
    console.log("[*] libsystem_kernel.dylib (open)", path);
  }
});
```

**Serialize an Object to JSON**

```
JSON.parse(JSON.stringify(ObjC.classes.NSObject))
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
  	var serialKey = ObjC.Object(args[2]) 	// as seen, as of 2nd parameter, we are getting real data of the method argument   value
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

... to get **`Argument Types`** of a Class/Object Method

```
ObjC.classes.UIView['- addSubview:'].argumentTypes
[
    "pointer",
    "pointer",
    "pointer"
]
```

... to get **`Return Type`** of a Class/Object Method

```
ObjC.classes.UIView['- addSubview:'].returnType
"void"
```

... to get **`low-level encoding`** of Types (Internal ObjC)

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

**Allocate and initialise a NativeFunction**

```
// Obtain a pointer to a 'malloc' function from the actual library
var mallocPtr = Module.findExportByName("libsystem_c.dylib", "malloc");

// Define a NativeFunction w/ 'malloc' signature, accepting (int)size and
// returning (pointer)addr of allocated memory space
var malloc = new NativeFunction(mallocPtr, "pointer", ["int"]);

Interceptor.replace(mallocPtr, new NativeCallback(function(size) {
  var ptrAddr = malloc(size);
  console.log("[*] Allocated via 'malloc' " + size + " bytes in " + ptrAddr);
  return ptrAddr;
}, 'pointer', ['int']));

# [*] Allocated via 'malloc' 29 bytes in 0x1d4032680
# ...
```

**Viewing and Modifying Registers**

```
var addr = ObjC.classes["ClassName"]["MethodName"].implementation;

Interceptor.attach(addr, {
  onEnter: function (args) {
    /** this.context is a method describing current context thread, */
    /** from with in app. process. as such, one can use it to get   */
    /** more details about the thread/page on the heap. here, we    */
    /** use it to pull registers from the procmap. */

    // Print all registers
    console.log(JSON.stringify(this.context, null, 4), '\n');
    # "pc": "0x102d91d34",
    # "sp": "0x16d3f42d0",
    # "x0": "0x2831e8a80",
    # "x1": "0x1e43ee192",
    # ...

    // Print a register value
    console.log("Register (x14): ", this.context.x14);            // reg(x14) = 0x18
    console.log("Register (x14): ", this.context.x14.toInt32());  // reg(x14) = 24

    // Modify a register value
    this.context.x14 = 63;   // reg(x14) = 0x44
    this.context.x14 = 0x44; // reg(x14) = 63
  }
}); 
```

**Viewing Opcode Instructions at Memory Address**

```
var addr = ObjC.classes["ClassName"]["MethodName"].implementation;

Instruction.parse(addr);          // mov x1, x2
Instruction.parse(addr).mnemonic; // mov
Instruction.parse(addr).opStr;    // x1, x2
```

**Modifying Opcode Instruction at Memory Address**

```
var addr = ObjC.classes["ClassName"]["MethodName"].implementation;
var addrToOverwrite = addr.add(0x0c);

console.log(addr, Instruction.parse(addrToOverwrite)); // add x0, x0

Memory.patchCode(addrToOverwrite, 4, code => {
  const cs = new Arm64Writer(code, { pc: code });
  cs.putNop();
  cs.flush();
});

console.log(addr, Instruction.parse(addrToOverwrite)); // nop
```

**Additional options for `hexdump`**

This small keyword allows you do dump anything residing at specific memory address, native functions, pointer or any other blob data.

```
console.log(hexdump(ptr(this.data))		// dumps this.data in a hexadecimal forma, with default opts

console.log(hexdump(ptr(this.data), {		// dumps this.data but with specific display opts
	length: 1000,			/* max number of chars in hexview */
	header: true,			/* also include table header */
	ansi: true 			/* display in ansi */
})) 
```

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
var stored = null /* a variable that will store/contain original completionHandler block */

Interceptor.attach(ObjC.classes.NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation, { 	// Hook on NSURLSession*completionHandler
  onEnter: function(args) {
    this.object_selector = "-[NSURLSession dataTaskWithRequest:completionHandler:]"
    console.log("onEnter -- " + this.title)

    requestObj = ObjC.Object(args[2]) // args[2] is dataTaskWithRequest:* value
    console.log("Request " + requestObj)

    completionHandler = new ObjC.Block(args[3]) // store the original completion handler
    stored = completionHandler.implementation

    /* (re)use completionHandler method implementation */
    completionHandler.implementation = function(data, response, error) { 	// the block shall respect original implementation
      // print completionHandler Network Response
      console.log("Response: " + requestObj)
      console.log(ObjC.Object(response))

      // Getting ahold of data
      dat = ObjC.Object(data) // 'data' is an NSData object
      datLen = dat.length() // Length of 'data' from the completion
      datBytes = dat.bytes() // Get the data in bytes

      // Displaying data
      console.log(hexdump(dat, { ansi: true, length: len }))
      // alternative:
      // console.log(Memory.readUtf8String(dat))

      // Call original completion block
      return stored(data, response, error)
    }
  },

  onLeave: function(retval) {
    console.log("onLeave -- " + this.title)
  }
})
```

**Using Frida to register a new Objective-C class**

```
const FridaObjC_ClassRegister = ObjC.registerClass({
    name: "PseudoNewClass",
    //super: ObjC.classes.AppAbstractClass, // you can extend Apps class
    //protocols: [ObjC.protocols.PBMessage], // you can implement an App Protocol Class 
    

    methods: {
        '- init': function() {
            const self = this.super.init();
            if (self != null) {
                console.log(this.name + " is registered and loaded.");
            }
            return self;
        },
        '- dealloc': function() {
            ObjC.unbind(this.self); // free the instance
            this.super.dealloc(); // clear the ARC
        },

        // '- callSomeMethod' : function () {}
    }
});

const proxy = FridaObjC_ClassRegister.alloc().init();
proxy.callSomeMethod(); // call a class method
console.log(proxy.$ownMembers); // log the output
proxy.release(); // release the allocated class
```

#### Frida Swift Scripts

**Using Frida Interceptor with mangled Swift functions**

**todo**: *add Swift/Frida Scripting examples*

```
try {
  var targetFunction_ptr = Module.findExportByName("MyAppModule", "$s9YDAppModule17ConfigC33publicKeyVerifyCertsSayypGvpfi");

  if (targetFunction_ptr == null) {
    throw "[*] Target Function not found";
  }

  Interceptor.attach(targetFunction_ptr, {
    onLeave: function (retval) {
      var array = new ObjC.Object(retval);
      console.log("[*] ObjC Class Type: \t", array.$className);
      return retval;
    }
  });

  } catch (err) {
    console.log("[!] Exception: " + err.message);
  }
}
```

### Frida ObjC Runtime Definition

**Frida Objective-C Variable Types**

```
# https://github.com/frida/frida-objc-bridge/blob/main/test/basics.m#L965
# "test('char', 127);"
# "test('char', -128);"
# "test('int', -467);"
# "test('int', 150);"
# "test('short', -56);"
# "test('short', 562);"
# "test('long',  0x7fffffff);"
# ...
```

**Frida Objective-C Defined Properties**

```
# https://opensource.apple.com/source/objc4/objc4-551.1/runtime/objc-runtime-new.h.auto.html
# class specifications
meta-class    // metaclass exists for each class
              /* Reason for existance of meta-class */
/** Operations performed directly from class objects, such as calling static */
/** member functions, do not belong to an instance, so they need to exist in */
/** the class type. When the class itself is subclassed (setSuperClass), the */
/** parent class is not equivalent to the class to which it belongs (isa != superclass) */
/** Similarly, constructing a class requires providing its 'isa'. */

super-class   // parent class
root-class    // root class
selector      // selector is stored as a string, its memory location corresponds to the method, one by one
imp           // ordinary function pointer
id            // generic data type

# objc_reflection
              /* What is reflection? */
/** Objective-C is a reflective language, meaning it can obtain and modify its */
/** own state at runtime. The implementation of it exists in the 'libobjc.A.dylib' */
/** These runtime capabilities come from the more flexible objc class structure */
/** organization, and it provides an interface for manipulating its own struct  */
/** At the same time, there are _OBJC sections in the Mach-O executable file;   */
/** These sections provide sufficient class composition, and debuggers can parse */
/** these structures, making it really fun to RE. */
LC_SEGMENT.__OBJC.__cat_cls_meth
    LC_SEGMENT.__OBJC.__cat_inst_meth 
    LC_SEGMENT.__OBJC.__string_object 
    LC_SEGMENT.__OBJC.__cstring_object 
    LC_SEGMENT.__OBJC.__message_refs 
    LC_SEGMENT.__OBJC.__sel_fixup 
    LC_SEGMENT.__OBJC.__cls_refs 
    LC_SEGMENT.__OBJC.__class 
    LC_SEGMENT.__OBJC.__meta_class
    LC_SEGMENT.__OBJC.__cls_meth 
    LC_SEGMENT.__OBJC.__inst_meth
    LC_SEGMENT.__OBJC.__protocol
    LC_SEGMENT.__OBJC.__category 
    LC_SEGMENT.__OBJC.__class_vars 
    LC_SEGMENT.__OBJC.__instance_vars 
    LC_SEGMENT.__OBJC.__module_info 
    LC_SEGMENT.__OBJC.__symbols

# https://github.com/frida/frida-objc-bridge/blob/main/index.js#L62
ObjC.available
ObjC.api
ObjC.classes
ObjC.protocols
ObjC.Object
ObjC.Protocol
ObjC.Block
ObjC.mainQueue
ObjC.registerProxy
ObjC.registerClass
ObjC.registerProtocol
ObjC.bind
ObjC.unbind
ObjC.getBoundData
ObjC.enumerateLoadedClasses
ObjC.enumerateLoadedClassesSync
ObjC.choose
ObjC.chooseSync
ObjC.enumerateLoadedClasses
ObjC.enumerateLoadedClasses
ObjC.enumerateLoadedClasses

# https://github.com/frida/frida-objc-bridge/blob/main/index.js#L224
registryBuiltins = [
  prototype
  constructor
  hasOwnProperty
  toJSON
  toString
  valueOf
]

# https://github.com/frida/frida-objc-bridge/blob/main/index.js#L428
objCObjectBuiltins = [
  prototype
  constructor
  handle
  hasOwnProperty
  toJSON
  toString
  valueOf
  equals
  $kind
  $super
  $superClass
  $class
  $className
  $moduleName
  $protocols
  $methods
  $ownMethods
  $ivars
]

# https://github.com/frida/frida-objc-bridge/blob/main/index.js#L1110
objCIvarsBuiltins = [
  prototype
  constructor
  hasOwnProperty
  toJSON
  toString
  valueOf
]
```

### References

- [Crypto Hooks via Frida Scripting](https://github.com/theart42/hack.lu/blob/master/IOS/Notes/05-Crypt/00-crypto-hooks.md)
- [Using Frida Scripting to hijack NSURLSession](https://flippingbitz.com/post/2020-05-12-frida-instrumentation-ios-nsurlsession/) - *doing so, you avoid SSL pins, web proxy, mitm attacks*
- [frida-objc-bridge tests](https://github.com/frida/frida-objc-bridge/blob/main/test/basics.m)
- [frida-ios-intercept-api](https://github.com/noobpk/frida-ios-intercept-api)

