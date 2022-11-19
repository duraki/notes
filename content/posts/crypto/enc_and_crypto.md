---
title: "Encryption and Cryptography"
---

## Quick Decode(s)

* For **JWT** use `jwt.io`, paste your token and enjoy formatted results
* When having `base64` encoded string, simply:
	- `echo "<string>" | base64 --decode`. 
* When having `md5` or equivalent (one-way hash), use `hashcat`

## Decoding Unknown Chipers
To decode unknown chipers, you will need to take the binary that engages on the encryption/decryption mechanism, and understand the logic flow. It's similar to when you are bypassing a license, except the figurative data is usually hard to understand.

**Automated Decryption**
You can try using **Ciphey**, automated decryption/decoding/cracking tool using natural language processing & artificial intelligence. It's [open source](https://github.com/Ciphey/Ciphey) and [nicely documented](https://github.com/Ciphey/Ciphey/wiki).


```
$ ciphey

Usage: ciphey [OPTIONS] [TEXT_STDIN]

  Ciphey - Automated Decryption Tool

  Documentation: https://github.com/Ciphey/Ciphey/wiki
											    ...

  Examples:
      Basic Usage: ciphey -t "aGVsbG8gbXkgbmFtZSBpcyBiZWU="

Options:
  -t, --text TEXT            The ciphertext you want to decrypt.
  -q, --quiet                Decrease verbosity
  -g, --greppable            Only print the answer (useful for grep)
	
# => use -h to display full output
```

**Manual Decryption**
Head over to [CyberChef](https://gchq.github.io/CyberChef/) from  `gchq@gov`, and manually craft your chiper recipe or combination. This takes some time, but the chances are much greated then using automated tasks.

## Toolset

* [carmaa/interrogate](https://github.com/carmaa/interrogate) - proof-of-concept tool for identification of cryptographic keys in binary material