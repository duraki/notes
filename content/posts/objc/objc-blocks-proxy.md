---
title: Generic Block Proxy
---

In Objective-C, **it's possible** to *intercept messages*. Any message sent to an object **that isn't implemented** gets an `NSInvocation` object constructed, and that is then sent to `forwardInvocation:`.

Once the object selector is at `forwardInvocation:`, it's possible to do whatever with passed `message`, such is **changing parameters** before passing it to another object, or sending it over the network.

Apple's common use-case for such strange reflection is due to easier implementation and facility of proxy classes which doesn't implement much of anything. Nearly any message sent to this selector will be caught by the forwarding mechanism, and the proxy can then do clever messing with any message, while still mostly acting like the object being proxied (ie. close to `ptr(origin)` instance).

**Block Proxying** is similar to Objective-C's proxy class, but instead of objects, we are intercepting *(logic)* blocks. To do so, we need to wrap an arbitrary block with another block which is able to intercept the call and interfere with it.

This method here, presented originally by [mikeash](https://mikeash.com/pyblog/friday-qa-2011-10-28-generic-block-proxying.html) via his [blog](#), relies on Apple SDK Private APIs, and private quirks of public APIs in combination.

Example code is visible on [mikeash/MABlockForwarding](https://github.com/mikeash/MABlockForwarding) via his [GitHub](#).

**Theory**

Since we know that any message sent to an object that isn't implemented gets an `NSInvocation` object constructed, and if we can obtain the ObjC-internal `IMP` forwarding, then its possible to build a fake block around it - containing the message, and then forward the block as regular to appropriate block.

There are several ways to ask for `IMP`, but we will use `[self methodForSelector: ... ]` message and pass a selector that does not exists in the class. We can construct an Objective-C object with a pointer to the forwarding `IMP` in the right place, and the forwarding handler will execute, building an `NSInvocation`, and then calling our `forwardInvocation:` method.

The forwarding handler needs the method signature of the method being called in order to know how to package the arguments. Recent compilers reasonably provides this information.

* Forwarding handler deals with `messages`, which have two implicit arguments: the `object` and the `selector`.
* Blocks only have one implicit argument: the `block` object.

The second argument to a block can be anything, or not even exist at all (for a block with no parameters). Fortunately, the forwarding function doesn't seem to care about the type of the second parameter, as long as it's present. For blocks that don't have a second parameter, a fake one can be inserted into the signature without screwing things up

**Implementation**

We will try to build this function:

```objc
    typedef void (^BlockInterposer)(NSInvocation *inv, void (^call)(void));
    id MAForwardingBlock(BlockInterposer interposer, id block);
```

`MAForwardingBlock` takes two parameters: 

1. The first is the interposer block, which is the block which is called to handle the invocation. 
2. The second is the original block to wrap. 
   - The interposer gets a block as a parameter, which, when called, will call through to the original block using the `NSInvocation` as the parameters;
   - The function returns a new block which forwards calls to the interposer block passed in.

We need to create a new class which will pretend to be a block. Instances of this class will **act like blocks and will handle proxy workload.** The layout of this class needs to be compatible with the layout of a block. A **block contains five fields** which can then be **followed by other data**.

There's an `isa` field (necessary for it to work as an Objective-C object), flags, some reserved space, the block's function pointer, and a pointer to a block descriptor which contains other useful information about the block.

{{< details "Keep Reading ..." >}}
The `isa` field is already taken care of, and then the rest can be laid out as instance variables. After the block fields are laid out, other data can follow. In this case, the class stores the interposer block and the original block as instance variables after the block fields:

```objc
    @interface MAFakeBlock : NSObject
    {
        int _flags;
        int _reserved;
        IMP _invoke;
        struct BlockDescriptor *_descriptor;

        id _forwardingBlock;
        BlockInterposer _interposer;
    }
```

This class has a single method in its interface, an initializer:

```objc
    - (id)initWithBlock: (id)block interposer: (BlockInterposer)interposer;
```

Everything else happens through block calling conventions and forwarding, so nothing else needs to be done. The implementation for this method copies and stores the two blocks passed in, and then sets the invoke field to the forwarding `IMP` by fetching a method that isn't implemented:

```objc
    - (id)initWithBlock: (id)block interposer: (BlockInterposer)interposer
    {
        if((self = [super init]))
        {
            _forwardingBlock = [block copy];
            _interposer = [interposer copy];
            _invoke = [self methodForSelector: @selector(thisDoesNotExistOrAtLeastItReallyShouldnt)];
        }
        return self;
    }
```

With everything now set up, **whenever an instance of `MAFakeBlock` is called like a block**, it will end up going through the regular Objective-C forwarding handler. There are two steps in the general forwarding path:

1. The runtime fetches the method signature using `methodSignatureForSelector:`
2. It then constructs an `NSInvocation` and calls `forwardInvocation:`

To figure out the method signature to give to the runtime, we first need to get the method signature of the block being wrapped. This is done by delving into that `BlockDescriptor` structure and pulling out the signature.

`NSMethodSignature` provides a method to get a signature object from a C string, `+signatureWithObjCTypes:`. The only issue, sort of, is that the forwarding handler will crash if the provided signature doesn't have at least two objects. To fix that, you need to fake it by adding extra fake `void *` parameters to the signature so that it has at least the required number of parameters. These extra parameters are harmless, although they will be filled with random junk from registers or the stack. 

The `methodSignatureForSelector:` implementation then looks like this:

```objc
    - (NSMethodSignature *)methodSignatureForSelector: (SEL)sel
    {
        const char *types = BlockSig(_forwardingBlock);
        NSMethodSignature *sig = [NSMethodSignature signatureWithObjCTypes: types];
        while([sig numberOfArguments] < 2)
        {
            types = [[NSString stringWithFormat: @"%s%s", types, @encode(void *)] UTF8String];
            sig = [NSMethodSignature signatureWithObjCTypes: types];
        }
        return sig;
    }
```

The implementation of `-forwardInvocation:` is then pretty simple. Change the invocation's target to the original block, then call the interposer:

```objc
    - (void)forwardInvocation: (NSInvocation *)inv
    {
        [inv setTarget: _forwardingBlock];
        _interposer(inv, ^{
```

The call block that gets passed to the interposer is a bit tricky. In its public interface, `NSInvocation` only provides methods to invoke it with a particular selector, which goes through `objc_msgSend`. This is not the best situation for calling a block. Fortunately, there's a private method called `invokeUsingIMP:` which bypasses `objc_msgSend` and simply calls the provided `IMP`. In practice, it will call any arbitrary function pointer, as long as it's compatible with the signature that it has. We can then pass the function pointer for the inner block, and off we go:

```objc
            [inv invokeUsingIMP: BlockImpl(_forwardingBlock)];
        });
    }
```

The use of little helper function here is to deal with internal block structure. `BlockImpl` fetches the function pointer out of a block; therefore, it is used to interpret the object as a block structure and fetches the invoke field.

For this class, we need to implement a dummy implementation of `copyWithZone:` - since blocks are copied a lot. Nothing has to be done for this implementation besides retaining the fake block, since there isn't any mutable state in this class:

```objc
    - (id)copyWithZone: (NSZone *)zone
    {
        return [self retain];
    }
```

Now that this class is complete, all that remains is the implementation of `MAForwardingBlock`. This function has create and return a new instance of the fake block class, properly initialized, like so:

```objc
    id MAForwardingBlock(BlockInterposer interposer, id block)
    {
        return [[[MAFakeBlock alloc] initWithBlock: block interposer: interposer] autorelease];
    }
```

Nice, you did it. `<~ EOF`

**Blocks Proxy Interception**

Now we can proxy ObjC' blocks, using the following example:

```objc
void (^block)(int) = ForwardingBlock(^(NSInvocation *inv, void (^call)(void)) {
    [inv setArgument: &(int){ 4242 } atIndex: 1];
    call();
}, ^(int testarg){
    NSLog(@"%d %d", argc, testarg);
});
block(42);
```

Even though the block is called with `arg(42)` ie. passing a value of `Int:42`, the call actually prints `4242`. That is due to interposing of the block, and the value changes on the argument prior to calling the original block.
{{< /details >}}

The `CoreFoundation` API includes a function which achieves something similar:

```objc
extern id __NSMakeSpecialForwardingCaptureBlock(const char *signature, void (^handler)(NSInvocation *inv));
```

The signature of a block can be obtained using this method call:

```objc
extern const char* _Block_signature(id block);
```

Or from a Protocol class, using the following method call:

```objc
extern const char* _protocol_getMethodTypeEncoding(Protocol* protocol, SEL name, BOOL isRequiredMethod, BOOL isInstanceMethod); 
```

The resulting block object can be passed as a normal block, and once invoked, the provided callback will be called with the invocation object.

