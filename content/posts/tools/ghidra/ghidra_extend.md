---
title: "Ghidra Scripts"
---

## Apple-related Scripts

* [SwizzlingDetector](https://github.com/LaurieWired/iOS_Reverse_engineering/blob/main/SwizzlingDetector.py) - Detect whether an app is using swizzling
* [SwiftNameDemangler](https://github.com/LaurieWired/iOS_Reverse_Engineering/blob/main/SwiftNameDemangler.py) - Demangle Swift class, functions, and vars
* [RenameObjCStubs](https://github.com/level3tjg/ghidra_scripts) - An Objective-C Stub decoder

## Replica - Analysis Enhancer

* [reb311ion/replica](https://github.com/reb311ion/replica) **{{< sup_a " installation guide" "https://github.com/reb311ion/replica#-installation" >}}**  `=> replica is Ghidra's Analysis Enhancer plugin`

This is the typical script that I use, basically do-it-all with appropriate database that resolves to method signatures and other [Ghidra](/ghidra-and-related) components. Some things it does: disass. missed ops, detect missed funcs., use MSDN API on WinNT, detect wrapper functions, and much more.

{{< notice >}}
Important Information
{{< /notice >}}
{{< callout emoji="🐉" text="The file in '~/.config/ghidra/ghidra_scripts/' should be available via dotdrop synced files. This also contains Replica." >}}

```
$ ls ~/.config/ghidra/ghidra_scripts/reb311ion_replica
# data.py db.json replica.py ...
```

{{< imgcap title="Running REPLICA via Ghidra Script Manager"  src="https://user-images.githubusercontent.com/22657154/73777200-bcb48a80-4791-11ea-8f8c-7dec1aadc5d7.png" >}}

## Plugin List

* [coloring_call_jmp.py](https://github.com/AllsafeCyberSecurity/ghidra_scripts#coloring_call_jmppy)
* [py-findcrypt-ghidra](https://github.com/AllsafeCyberSecurity/py-findcrypt-ghidra#py-findcrypt-ghidra)
* [binwalk.py](https://github.com/ghidraninja/ghidra_scripts#binwalkpy)
* [yara.py](https://github.com/ghidraninja/ghidra_scripts#yarapy)
* [swift_demangler.py](https://github.com/ghidraninja/ghidra_scripts#swift_demanglerpy)
* [golang_renamer.py](https://github.com/ghidraninja/ghidra_scripts#golang_renamerpy)
* [ghidra-fidb-repo](https://github.com/threatrack/ghidra-fidb-repo#ghidra-function-id-dataset-repository)
* [replace-constants](https://github.com/0xb0bb/pwndra#replace-constants)
* [annotate-syscalls](https://github.com/0xb0bb/pwndra#annotate-syscalls)
* [goto-main](https://github.com/0xb0bb/pwndra#goto-main)
* [operator](https://github.com/tacnetsol/ghidra_scripts/blob/master/readmes/operator.md)
* [analyzeocmsgsend.py](https://github.com/PAGalaxyLab/ghidra_scripts#analyzeocmsgsendpy)
* [fox](https://github.com/federicodotta/ghidra-scripts/tree/main/FOX)
* [rhabdomancer.java](https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java)
* [ghidra_stack_strings](https://github.com/zxgio/ghidra_stack_strings)

Additionally, there is [ghidra-snippets](https://github.com/HackOvert/GhidraSnippets) repository that may be usable as a reference to various Ghidra functions and their signatures.

## Themes + Tweaks

The user [zackelia](https://github.com/zackelia/) implemented a {{< color "#000" "Dark Theme" "#fff" >}} for Ghidra titled [ghidra-dark](https://github.com/zackelia/ghidra-dark).
