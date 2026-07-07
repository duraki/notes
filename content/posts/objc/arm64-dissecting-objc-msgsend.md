---
title: "Dissecting ObjC Runtime on ARM64"
---

The message send code (`objc_msgSend`) can be divided into two parts: 

1. Via faster alternative in `objc_msgSend` itself, which is written in assembly
2. Via slower alternative implemented in C. 

The assembly part looks up the method in the cache and jump to it if found. If the method is not in the cache, then it calls into the C code to handle message code send.

Therefore, when looking at `objc_msgSend` itself, it does the following:

1. Get the `class` of the `object` passed in
2. Get the `method cache` of that `class`
3. Use the `selector` that is passed, to look up the method in the cache
4. If it's not in the cache at all, call into the C code
5. Finally, jump to the `IMP` for the method *(ie. actual implementation)*

Lets go **Step by Step** in details;

`objc_msgSend` has a few different paths it can take, depending on circumstances. It has a special code for handling things like `messages` to `nil`, `tagged pointers`, and `hash table` collisions.

The easiest one is the most common, straight-line case where a message is sent to a `non-nil`, `non-tagged` pointer and the method is found in the cache without any additional lookups.

Each instruction is preceded by its offset from the beginning of the function. This serves as a counter, and lets you identify jump targets.

---

Few words on `arm64` architecture, specifically its' registers:

The **arm64** architecture has *31 Integer registers* which are `64 bits` wide. They're referred via notation from `x0` to `x30`. It's also possible to access the lower `32 bits` of each register, as if it were a separate register, using `w0` to `w30` registers.

The registers `x0` through `x7` are used to pass the **first eight parameters** to a function. That means that `objc_msgSend` receives the `self` parameter in `x0` and the *selector*'s `_cmd` parameter in `x1`.

| Total .# Registers |     31      | Type(Integer)                       | Size(64bits)                                               | x0-x30 |
| ------------------ | :---------: | :---------------------------------- | ---------------------------------------------------------- | ------ |
|                    |             |                                     |                                                            |        |
| **From**           | **Through** | **Use Case**                        |                                                            |        |
| x0                 |     x7      | First 8 parms. passed to a function |                                                            |        |
| **Where**          |     x0      | `self`                              | `objc_msgSend` receives the `self` param in `x0`           |        |
| **Where**          |     x1      | `_cmd`                              | `objc_msgSend` receives the selectors `_cmd` param in `x1` |        |
| w0                 |     w30     | Lower 32bits registers              |                                                            |        |

---

Head over to [opensource.apple.com](https://opensource.apple.com/source/objc4/objc4-723/runtime/Messengers.subproj/objc-msg-arm64.s.auto.html) which will open `objc-msg-arm64.s` source code. You should see comments explaining a start of `objc_msgSend` entry point like so:

```asm
/********************************************************************
 *
 * id objc_msgSend(id self, SEL _cmd, ...);
 * IMP objc_msgLookup(id self, SEL _cmd, ...);
 *
 * objc_msgLookup ABI:
 * IMP returned in x17
 * x16 reserved for our use but not used
 *
 ********************************************************************/
```

This is the function we are going to explore in depth. Your cursor should sit somewhere around the line directives below:


```asm
# ...

	ENTRY _objc_msgSend
    UNWIND _objc_msgSend, NoFrame
    MESSENGER_START
```

The above excerpt defines entry point for the `objc_msgSend` ObjC Runtime method. Right below are the assembly instructions containing message send runtime logic.

```asm
    cmp	x0, #0
    b.le	LNilOrTagged   // LNilOrTagged = 0x6c
```

This performs a signed comparison of `self` with value of `0` (ie. *nil*), and jumps elsewhere if the value is less than or equal to zero (`0`). The value of zero (0) is `nil` in practice, so this conditional handles the special case of message being `nil`. 

The above also handles [tagged pointers](https://en.wikipedia.org/wiki/Tagged_pointer) - wherein Tagged Pointers on ARM64 are indicated by setting the high-bit of the pointer (unlike `x86_64` where it uses low-bit). If the high-bit is set, then the value is negative when interpreted as a signed integer. Since this is a *common case* of `self` being a normal pointer, the branch is not taken.

```asm
    ldr	x13, [x0]		// x13 = isa
```

This loads the `self`'s `isa` ivar by loading the 64-bit value pointed to by `x0`, which contains `self`. The `x13` register now contains the `isa`.

```asm
    and	x16, x13, #ISA_MASK	// x16 = class, ISA_MASK = #0xffffffff8
```

ARM64 can use non-pointer `isa`s. Traditionally the `isa` points to the `object`'s class, but [`non-pointer isa`](http://www.sealiesoftware.com/blog/archive/2013/09/24/objc_explain_Non-pointer_isa.html) takes advantage of spare bits by cramming some other information into the `isa` as well. The above instruction performs a logical `AND` operand to mask off *all the extra bits*, and leaves the *actual class pointer in x16*.

```asm
    LGetIsaDone:
        CacheLookup NORMAL		// calls imp or objc_msgSend_uncached
                                // see below macro

#macro
    ldp	x10, x11, [x16, #CACHE]	// x10 = buckets, x11 = occupied|mask
```

This `goto` directive retrieves the class's cache information via its' defined assembly macro `.macro CacheLookup`, translated to machine code, it would look like this:

```asm
    0x0010 ldp    x10, x11, [x16, #0x10]
```

{{< details "Expand CacheLookup Assembly" >}}
```asm
.macro CacheLookup
	// x1 = SEL, x16 = isa
	ldp	x10, x11, [x16, #CACHE]	// x10 = buckets, x11 = occupied|mask
	and	w12, w1, w11		// x12 = _cmd & mask
	add	x12, x10, x12, LSL #4	// x12 = buckets + ((_cmd & mask)<<4)

	ldp	x9, x17, [x12]		// {x9, x17} = *bucket
1:	cmp	x9, x1			// if (bucket->sel != _cmd)
	b.ne	2f			//     scan more
	CacheHit $0			// call or return imp

2:	// not hit: x12 = not-hit bucket
	CheckMiss $0			// miss if bucket->sel == 0
	cmp	x12, x10		// wrap if bucket == buckets
	b.eq	3f
	ldp	x9, x17, [x12, #-16]!	// {x9, x17} = *--bucket
	b	1b			// loop

3:	// wrap: x12 = first bucket, w11 = mask
	add	x12, x12, w11, UXTW #4	// x12 = buckets+(mask<<4)

	// Clone scanning loop to miss instead of hang when cache is corrupt.
	// The slow path may detect any corruption and halt later.

	ldp	x9, x17, [x12]		// {x9, x17} = *bucket
1:	cmp	x9, x1			// if (bucket->sel != _cmd)
	b.ne	2f			//     scan more
	CacheHit $0			// call or return imp

2:	// not hit: x12 = not-hit bucket
	CheckMiss $0			// miss if bucket->sel == 0
	cmp	x12, x10		// wrap if bucket == buckets
	b.eq	3f
	ldp	x9, x17, [x12, #-16]!	// {x9, x17} = *--bucket
	b	1b			// loop

3:	// double wrap
	JumpMiss $0

.endmacro
```
{{< /details >}}

Therefore, it would load the class's cache information into `x10` and `x11`. The `ldp` instruction loads *two* registers' worth of data from memory, into the registers named in the first two mnemonics. The third argument describes where to load the data, in this case, the data will load at offset `16 (0x10)` from the `x16` - which is the area of the class which holds the cache information.

The cache container looks like this:

```c
    typedef uint32_t mask_t;

    struct cache_t {
        struct bucket_t *_buckets;
        mask_t _mask;
        mask_t _occupied;
    }
```

After we stepped-out of `ldp` opcode instruction, the register `x10` will contain the value of `_buckets` from `cache_t` struct. The register `x11` will contain `_occupied` in its higher 32bits, and also `_mask` in its lower 32bits.

{{< details "More on _occupied" >}}
`_occupied` specifies how many entries the hash table contains, and plays no role in `objc_msgSend`. The `_mask` is important however: **it describes the size of the hash table as a convenient AND-able mask**. The value of `_mask` is always a power of two minus 1, or in binary terms something that looks like 000000001111111 with a variable number of 1s at the end. This value is needed to figure out the lookup index for a selector, and to wrap around the end when searching the table.
{{< /details >}}

```asm
    and	w12, w1, w11
```

This instruction computes the starting hash table index for the selector passed in. Since `_cmd.x1` contains `_cmd`, therefore `w1` *(the lower 32bit)* contains the bottom of the 32 bits of `_cmd.w11` and also contains `_mask` as described above. This instruction `AND`s the two together and places the result into `w12`. The result is the equivalent of `computing _cmd % table_size` but without the expensive modulo operation.

```asm
    add	x12, x10, x12, LSL #4      // x12 = buckets + ((_cmd & mask)<<4)
```

To start loading data from the cache table, we need the actual address to load from. The above instruction computes that address by adding the table index to the table pointer. It shifts the table index left by 4 bits first, which multiplies it by `16`, because *each table bucket is 16 bytes*. Register `x12` now contains the address of the first bucket to search.

```asm
    ldp	x9, x17, [x12]		        // {x9, x17} = *bucket
```

The `ldp` instruction operand now loads from the pointer at `x12`, which seen from above `add` opcode, points to a bucket to search. Each bucket contains a selector, and `IMP.x9` now contains the selector for the current bucket. The register `x17` contains the `IMP`.

```asm
1:	cmp	x9, x1			// if (bucket->sel != _cmd)
    b.ne	2f			//     scan more
```

These instructions compare the bucket's selector in register `x9` with `_cmd` in `x1`. If they are not equal (`b.ne`), then this bucket does not contain an entry for the selector we are looking for, and in that case we jump to handler `2f` (offset `0x0c`), which handles the non matching buckets. 

If the **selector match** in this bucket, then we've found the entry we're looking for, and execution continues with the macro `CacheHit` defined in `CacheLookup` section, called via `CacheHit $0` which calls or returns `IMP`.

```asm
.macro CacheHit
.if $0 == NORMAL
	MESSENGER_END_FAST
	br	x17			// call imp
.elseif $0 == GETIMP
	mov	x0, x17			// return imp
	ret
.elseif $0 == LOOKUP
	ret				// return imp via x17
```

From here, execution will continue in the actual implementation of the target method, and this is the end of `objc_msgSend`'s fast path. All of the argument registers have been left undisturbed, so the target method will receive all passed in arguments just as if it had been called directly.

There are other conditional branching which are not as fast, such is when looking in a non-matching cache bucket. In this cases, the code will continue with this non-matching conditional in the `CheckMiss` macro directive:

```asm
.macro CheckMiss
; ... redacted ...
.elseif $0 == NORMAL
	cbz	x9, __objc_msgSend_uncached
; ... redacted ...
.endmacro
```

The opcode `cbz` is used to compare register `x9` which contains the selector from the loaded bucket, against zero (0) and jumps to `__objc_msgSend_uncached` if it is. A *zero selector* **indicates an empty bucket**, and an *empty bucket means* that the **search has failed**. The target method isn't in the cache, and it's time to fall back to the C code that performs a more comprehensive lookup. `__objc_msgSend_uncached` handles that. Otherwise, the bucket doesn't match but isn't empty, and the search continues.

```asm
2:	// not hit: x12 = not-hit bucket
	CheckMiss $0			// miss if bucket->sel == 0
	cmp	x12, x10		// wrap if bucket == buckets
	b.eq	3f
```

This instruction compares the current bucket address in `x12` with the beginning of the hash table in `x10`. If they match, the code jumps to block that wraps the search back to the end of the hash table. The handler `3f` (offset `0x40`) handles the wraparound case. Otherwise, execution proceeds to the next instruction.

```asm
2:  ; cont.
    ldp	x9, x17, [x12, #-16]!	// {x9, x17} = *--bucket
```

Agin, `ldp` here is loading the `cache bucket`. It loads the cache bucket from `0x10 = -16` to the address of current bucket. The exclamation point at the end of the address reference is a way to indicate a register write-back flag, which means that the register is updated with the newly computed value. In this case, it's effectively doing `x12 = -16` which makes `x12` point to that new bucket.

```asm
2:  ; cont.
	b	1b			// loop
```

Once we have new bucket loaded, execution can resume with the codeblock that checks to see if the current bucket is a match. This loops back up to the instruction labeled `1b` above, and runs through all of that code again with the new values. If it continues to find non-matching buckets, this code will keep running until it finds a match, an empty bucket, or hits the beginning of the table.

```asm
3:	// wrap: x12 = first bucket, w11 = mask
	add	x12, x12, w11, UXTW #4	// x12 = buckets+(mask<<4)
```

This directive is the target when the search wraps *(completes iteration)*. Register `x12` contains a pointer to the current bucket, which in this case is also the first bucket. The register `w11` contains the table mask, which is the size of the table. The above `add` opcode adds the two together, while also shifting `w11` register to the left by 4 bits, multiplying it by 16. The result of above *addition* is that the register `x12` now points to the end of the table, and the search can resume from there.

```asm
3:  ; cont.
    ldp	x9, x17, [x12]		// {x9, x17} = *bucket
```

The above `ldp` opcode now loads the new bucket (from `x12`) into the `x9` and `x17` registers.

```asm
1:	cmp	x9, x1			// if (bucket->sel != _cmd)
	b.ne	2f			//     scan more
	CacheHit $0			// call or return imp
```

This code checks to see if the bucket matches the selector and jumps to the bucket's `IMP`. It's a duplicate of the above code.

**That's the end of the main body of `objc_msgSend`.** Some more details are also available [here](https://mikeash.com/pyblog/friday-qa-2017-06-30-dissecting-objc_msgsend-on-arm64.html).

**See Also:**
* [Apple objc_msgSend Docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)
* [Apple `IMP` Docs](https://developer.apple.com/documentation/objectivec/objective-c_runtime/imp)