---
title: "DYLD MacOS Injection" 
---

**Tracing MacOS app. via CLI**

```
$ dtruss /Application/AppName.app/Contents/MacOS/AppName
$ dtrace /Application/AppName.app/Contents/MacOS/AppName
```

**Print MacOS Logs from Terminal**

```
$ idevicesyslog
```

**Inject `dylib` (Library) into MacOS process**

```
$ gcc -dynamiclib SomeLibrary.c -o SomeLibrary.dylib 		# compile dylib 
$ DYLD_INSERT_LIBRARIES=SomeLibrary.dylib /Application/AppName.app/Contents/MacOS/AppName
```  

**Analyse MacOS binary for ObjC runtime/environ variables**

```
$ OBJC_HELP=1 ./build/Debug/HelloWorld

## More Below:
# objc: OBJC_HELP: describe Objective-C runtime environment variables
# objc: OBJC_PRINT_OPTIONS: list which options are set
# objc: OBJC_PRINT_IMAGES: log image and library names as the runtime loads them
```

**Anti-debugging techniques implemented in XNU/OSX environments**

* via `sysctl()` & `P_TRACED` flag detected (can detect debugger and tracer, but not injection and cycript)
* via `isatty()` which returns '1' if the given file descriptor is attached to the debugger, otherwise '0'
* via `task_get_exception_ports`, which detects debuggers exception port
* via `Restricted` section of an executable (`setgid` bits are set, `__restrict` section), prohibits dylib injection

**Bypass `Restricted` section name to allow DYLIB injection**

```
$ ldid -S #APP
$ codesign ...
```

**Bypass `ptrace` based anti-debugging of a MacOS app.** (Easy)

```
#import <dlfcn.h>
#import <sys/types.h>
typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);

#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif  // !defined(PT_DENY_ATTACH)

void disable_debugging() {
	void* handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);
	ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");
	ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
	dlclose(handle);
}

/** to bypass the above 'ptrace' syscall, we can abuse the MacOS DYLD_INSERT_LIBRARIES */
/** @see below (the dylib works for both easy/hard impls.)  */
```

**Bypass `ptrace` based anti-debugging of a MacOS app.** (Hard)

```
// pseudo-code of an MacOS app. that triggers 'ptrace' (PT_DENY_ATTACH) (31)
int start(int a1)
{
	...
	v1 = a1;
	v2 = dlopen(0LL, 0xA);
	v3 = v2;
	v4 = dlsym(v2, "ptrace");
	((void (__fastcall *)(signed __int64, _QWORD, _QWORD, _QWORD))v4)(31LL, 0LL, 0LL, 0LL);
	dlclose(v3);
	...
	return 0LL;
}

/** to bypass the above 'ptrace' syscall, we can abuse the MacOS DYLD_INSERT_LIBRARIES */
/** which can be injected using LD_PRELOAD on Linux and Unix. Hooking is possible right */
/** from the library code we will inject */
// gcc -dynamiclib hook.c -o hook.dylib
// DYLD_INSERT_LIBRARIES=hook.dylib /Application/AppName.app/Contents/MacOS/AppName
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef long int (*org_ptrace)(int, pid_t, void *, void *); 	// original ptrace signature

long int ptrace(int request, pid_t pid, void *addr, void *data) {
	printf("ptrace [request]: %d\n", request);
	if (request == 31) { // detect PT_DENY_ATTACH request
		return 0; 		 // early exit
	}

	org_ptrace pt = (org_ptrace)dlsym(RTLD_NEXT, "ptrace");
	puts("org_ptrace call");
	return pt(request, pid, addr, data); // otherwise call original ptrace
}
```