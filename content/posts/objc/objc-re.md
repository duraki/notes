---
title: "Objective-C RE"
---

[Quickly go to](#obj-c-re-topics) Objective-C RE tricks, or ObjC's [Development Tips](#development-tips).

From a reverse engineering perspective, Objective-C is a programming language that was originally developed by NeXT and later adopted by Apple for macOS, iOS, watchOS, and tvOS app development. Objective-C is notable for its dynamic runtime, which allows for features like late binding, introspection, and messaging between objects.

In reverse engineering, Objective-C poses unique challenges and opportunities due to its dynamic nature:

**Challenges:**

1. **Dynamic Method Dispatch**: In Objective-C, method calls are determined at runtime, making it harder to statically analyze code flow and dependencies.
2. **Runtime Reflection**: Objective-C supports runtime introspection, making it possible to retrieve class and method names dynamically, potentially making code harder to trace.
3. **Obfuscation**: Reverse engineers can use the dynamic nature of Objective-C to create obfuscated code that's harder to understand and reverse engineer.

**Opportunities:**

1. **Method Swizzling**: Reverse engineers can use method swizzling to modify the behavior of existing methods at runtime, which can be useful for patching or modifying apps.
2. **Runtime Inspection**: Dynamic runtime allows for tools to inspect objects and classes during execution, aiding in reverse engineering efforts.
3. **Dynamic Analysis**: The dynamic nature of Objective-C can help reverse engineers understand how objects and methods interact, potentially revealing hidden functionality.

Taking all above into consideration, Apple-based apps. written in ObjC are quite interesting targets for reverse engineering CTFs and research. Overall, Objective-C's dynamic features add a layer of complexity to reverse engineering efforts. Reverse engineers must deal with runtime method resolution, message passing, and dynamic class loading when analyzing Objective-C code.

## General Objective-C Internals

* Every Objective-C object has a class, and every Objective-C class has a list of methods. Each method has a selector, a function pointer to the implementation, and some metadata. The job of `objc_msgSend` is to take the object and selector that's passed in, find its corresponding method function pointer, and then jump to that function pointer.

* Looking up a method can be extremely complicated. If a method isn't found on a class, then it needs to continue searching in the superclasses. If no method is found at all, then it needs to call into the runtime's message forwarding handlers. If this is the very first message being sent to a particular class, then it has to call that class `+initialize` method.

* Objective-C's solution to finding methods *(@see: above)* conflicts is via **method cache**. *Each class* **has a cache** which **stores methods** as pairs of selectors and function pointers, known in Objective-C as `IMP`s. They're organized as a hash table so lookups are fast. When looking up a method, the runtime first consults the cache container. If the method isn't in the cache, it follows the slow, complicated procedure, and then places the result into the cache so that the next time can be a bit faster.

* The ObjC's `objc_msgSend` is written in assembly for at least two reasons:
  1. It's not possible to write a function which preserves unknown arguments and jumps to an arbitrary function pointer in C. The language just doesn't have the necessary features to express such a thing.
  2. it's extremely important for `objc_msgSend` to be **fast**, so every last instruction of the execution is written by hand, therefore the execution itself is as fast as possible.

* Objective-C message dispatch works by taking the `selector` and the `class` and looking up the `method` in the class that corresponds to that selector. More specifically, it looks up the function (or `IMP`), that actually implements the method, then calls that function.

* Objective-C Message forwarding hooks' right into ObjectiveC's message dispatch system *(@see: above)*. When searching for a function, if no method is found in the class, a special forwarding `IMP` is returned. This `IMP` function takes care of all the potential errs/throws, and other platform-specific details, ie. it handles how to turn a function call into an `NSInvocation` object. Refer to [Generic Block Proxy](#generic-block-proxy) for information on `NSInvocation` and what kind of object message triggers it.

* An Objective-C block is just an Objective-C object with a function pointer in the right place. To call the block, the compiler calls the function pointer and passes the object as the first parameter.

## Development Tips

**ObjC Literals**

A "literal" refers to any value which can be written out directly in source code - therefore `1337` is an Integer literal, and `"~SMOKING~KILLS~"` is a String literal, so is a `x` a Char literal.

Collections are pretty commonly used as well. C originally had no facilities for collection literals, but the ability to initialize variables of a compound data type came pretty close:

```clang
    int array[] = { 1, 2, 3, 4, 5 };
    struct foo = { 99, "string" };
```

Some time after, C99 added compound literals, which allow writing such things directly in code anywhere:

```clang
    MethodCallOnArray((int[]){ 1, 2, 3, 4, 5 });
    MethodCallOnStruct((struct foo){ 99, "string" });
```

In Objective-C, since around ~2012, a container literals were added allowing you to do:

```objc
    @[@{ @"key" : @"obj" }, @{ @"key" : @"obj2" }]      # => Array/Dictionary Collection
```

{{< details "Expand Old Implementation" >}}
```objc
    [NSArray arrayWithObjects:
        [NSDictionary dictionaryWithObjectsAndKeys:
            @"obj", @"key", nil],
        [NSDictionary dictionaryWithObjectsAndKeys:
            @"obj2", @"key", nil],
        nil];
```

> *This is really verbose, to the extent that it's painful to type and obscures what's going on. The limitations of C variable argument passing also require a `nil` sentinel value at the end of each container creation call - which can fail in extremely odd ways when forgotten.*
{{< /details >}}

Additionally, it's also possible to use this syntax for fetching and setting the object key/values - showing an example for `NSArray` below:

```objc
    int carray[] = { 12, 99, 42 };
    NSArray *nsarray = @[ @12, @99, @42 ];

    carray[1]; // 99
    nsarray[1]; // @99
```

It works for setting elements in mutable arrays as well:

```objc
    NSMutableArray *nsarray = [@[ @12, @99, @42 ] mutableCopy];
    nsarray[1] = @33; // now contains 12, 33, 42
```

However, it's not possible to add elements to an array this way, only replace existing elements. If the array index is beyond the end of the array, the call will thrown an error.

It works the same for dictionaries (`NSDictionary`), except the subscript is an `object key` instead of an `index`. Since dictionaries don't have any indexing restrictions, it also works for setting new entries:

```objc
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"suspect"] = @"Colonel Mustard";
    dict[@"weapon"] = @"Candlestick";
    dict[@"room"] = @"Library";
    dict[@"weapon"]; // Candlestick
```

Other literals available in ObjC, some of them extended from its' superscript CLang origin are:

```objc
    char *cstring = "hello, world";         // a C-string Literal (compile-time constant)

            // is same in Cocoa as ...

    NSString *nsstring = @"hello, world";   // an NSString Literal (compile-time constant)
```

---

## Obj-C RE Topics

#### Dissecting ObjC `objc_msgSend` on ARM64

Described in [separate notes](/dissecting-objc-runtime-on-arm64) due to huge content.

#### Generic Block Proxy

Described in [separate notes](/generic-block-proxy) due to huge content.

