---
title: "Binary File Decoding and Reverse Engineering"
url: /re/binary-file-decoding-and-reverse-engineering
---

## Scenario 1: Dumping chip contnets of an Insturment Cluster 

In this scenario, we will try to dump a coding plug chip and the DATA of it, which was taken out of a [BMW E34 Instrument Cluster](), and evnetually figuring out the DATA correct offset and vartypes, in essence understanding its binary file content.

![](/bin-file-decoding-1.png)

We will try reading out the Part ID No. as defined in above reversed bookmark containing binary structure and their representation values. This selected "Part ID" lenght at specific offset represents the DUT original part ID num, the one that should therefore match the sticker on the IC itself.

### Reading and parsing BMW E34 Coding Plug extracted DATA - `Programatically` in #GO

**Loading a file**

Using go, start by creating a new `main.go` in a `e34_low-ic-coding-plug_decompile` directory. This file should contain the `main()` function that will load the hardcoded filename.

```
package main

import (
    "fmt"
    "log"
    "os
)

func main() {
    path := "data/coding-plug.bin"    // set to a filepath of the eprom bin dump or binary dat 

    file, err := os.Open(path)        // try to open the fh for the given file 
    if err != nil {
        log.Fatal("Error while opening/reading file", err) // ret early on failure
    }

    defer file.Close()      // 'defer' is used to ensure the 'file.Close()' to be 
                            // called once the function exits itself, no matter if 
                            // fails or suceeds


    fmt.Printf("%s opened\n", path);  // fh is ready
}
```

**Check if the correct chip plug has been provided**

The 1st six bytes of the `bin` seems to always contain `0x00 0x00 0x00 0x00 0x00 0x00`, therefore, there are no magic bytes present here. Instead; we can check if the filesize equals to 256 bytes total (ie. since the layout is handling region `0x0000000-0x00000100` if `byte(0x00)...byte(0x0F)`) and confirm this to corrrespond to always-zeroed 1st six bytes (although eight) we are sure about.

Lets do this using the following:

```
func main() {
    // ...

    emptySixByteStartPadding := readNextBytes(file, 6) // 0x00 (6 bytes)
    fmt.Printf("Checking (6-bytes) at offset 0x00000000-0x00000005: must always equalt to `0x00` => %s\n", emptySixByteStartPadding))

    if string(emptySixByteStartPadding) != "\x00\x00\x00\x00\x00" {
        log.Fatal("Provided binary file is not in the correct format: must conform to 0x00")
    }
}

/**
 *
 * readNextBytes(fileptr, numOfBytesToRead)
 * 
 * Init a slice of bytes to store the reading results,
 * defining 'bytes' variable, with an array equivalent 
 * to a fixed size of numOfBytesToRead 'number'. Then,
 * we put in the slice as many bytes as we can using the
 * 'file.Read' function.
 *
 */
func readNextBytes(file *os.File, number int) []byte {
    bytes := make([]byte, number)

    _, err := file.Read(bytes)
    if err != nil {
        log.Fatal(err)
    }

    return bytes
}
```

Next, we define a structure to store all the parsed attributes, as per our definition of matching bookmark patterns in the shown screenshot of ImHex - a `Hexadecimal Editor`.

To deifne a struct, we can do:

```
type Header struct {
//    StartOffsetNullbytePaddingMaxSize uint32    // @0x00000000-0x00000007: must be zeroed out (0x00) size of 6-byte
    _[8]byte                                    // OffsetNullbyte        : must be zeroed out (0x00) @0x00000000-0x00000007
    _[8]byte                                    // <Unknown>             : tacho divider + something else?
    _[8]byte                                    // OffsetNullbyte        : must be zeroed out (0x10) @0x00000010-0x00000017
    PartNumberIDDataSize [6]byte                // @0x00000018-0x0000001D: data size of part no, 6-byte ie. 00 00 08 35 93 61 eq. partno# `8 359 361`
    _[1]byte                                    // @0x0000001E           : <unknown>
    InstrumentClusterMemoryRange [225]byte      // @0x0000001F-0x000000FF: remaining 225 byte of coding plug bin data 

    // TachoDividerByteDesignationOffset uint32    // @0x00000007           : represents the tacho divider byte offset
}
```

* Take a note to the `_` attribute, which means we don't care about these signature bytes right now. As we got `8+8+8` unknown bytes,m it is important to pinpoint this offset but not parse it for the struct. We simply move the cursor (`24=(8*3)`) 24-bytes forward, at which the cursor offset now contains 6-byte part number hexadecimal values (defined as `PartNumberIDDataSize` having 6-byte large buffer), which from hexadec literlay translates to Part No, ie. `00 00 08 35 93 61` would read as `[00 000] 8 359 361`. After it comes a single unknown byte, alongside the remaining ROM size.

**Reading out Part ID form `*.bin`**

The changes in the code used to read out Part ID number from the file is outlined below:

* Imports additional `bytes`, and `encoding/binary` package requirements
* Define a new `Header{}` struct and set it to `header` variable
* Sets the `data` variable to read whole bin data (ie. `bytes=255`)
* Create a `buffer(NewBuffer)`, using the `bytes.NewBuffer(withData: data)` package function
* Reads out the buffer data in a binary format, with specified [`Endianess`](https://en.wikipedia.org/wiki/Endianness) of expected data
* Using `binary.LittleEndiand` as a pecified second argument, we make sure the least significant byte is stored in the smallest address, at the end of a given sequence
* Finally, we check for errors and if all is correct, we parse/print `header` variable contents

```
import (
    // ...
    "bytes",
    "encoding/binary"
)

func main() {
    // ...
    
    header := Header{}
    data := readNextBytes(files, 255) // 255 = max size of the prom bin data buff

    buffer := bytes.NewBuffer(data)
    err := binary.Read(buffer, binary.LittleEndian, &header)

    if err != nil {
        log.Fatal("binary.Read failed", err)
    }

    fmt.Printf("Parsed *.bin data of Instrument Cluster Coding Plug:\n%+v\n", header)
}
```
