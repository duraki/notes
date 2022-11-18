---
title: "DYLD iOS Injection"
---

**Inject `dylib` (Library) into iOS process**

```
$ cat SomeLibrary.c
# ... SomeLibrary codebase ...

$ gcc -dynamiclib SomeLibrary.c -o SomeLibrary.dylib -Wall		// Compile iOS dylib
$ DYLD_INSERT_LIBRARIES=SomeLibrary.dylib cat 1					// Works only on CLI programs, not Apps.
```

