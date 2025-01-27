---
title: "Cycript"
---

*Tips and Tricks for Cycript*

**Remote connection to Cycript**

```
hcy = dlopen("libcycript.dylib", 1)
CYListenServer=(typedef void(short)) (dlysym(hcy, "CYListenServer"))
CYListenServer(55000)
tcprelay -t 55000:55000
cycript -r 127.0.0.1:55000
```

**Get loaded dyld modules**

```
cy# utils.get_dyld_info()
cy# ObjectiveC.images
```

**Inject `LOAD_DYLIB` from Cycript**

```
cy# dlopen("/usr/lib/test.dylib", 1)
```

**Tap an UIButton programatically**

```
[#0x000000000 sendActionsForControlEvents:UIControlEventTouchUpInside]
```

**Get pasteboard/clipboard items**

```
[UIPasteboard generalPasteboard].items
```

**Get UI elements dump**

```
[[UIApp keyWindow] recursiveDescription]
```

**Remove a SubView of a SuperView**

```
[0x000000000 removeFromSuperview]
```

**Bypass undismissable UIAlertController**, *(ie. Jailbreak Detected, Trial Ended, etc.)*

```
# Dump iOS UI, via Objection
	com.xxxxxxxxxxx.app on (iPhone: xx.x.x) [usb] # ios ui dump

# Dump iOS UI, via Cycript
	[[UIApp keyWindow] recursiveDescription]

	# Note down memory pointer addresses, referencing to UIAlert[View|Controller], and/or 
	# any bottom-up threads on Stack indicating SuperView(s), containing the undissmisable 
	# UIAlert*, such is 'UITransitionView'. @see below:
	# 
	# example ui:
	# <UIWindow: 0x143dxxxxx; ...> 					# app. main thread
	# <UILayoutContainerView: 0x143exxxxx; ...> 	# the 'view' that is unreachable
	# 	... [redacted] ...
	# <UITransitionView: 0x143exxxxx; ...> 			# the 'view' containing UIAlert* subview
	# 	<_UIAlertControllerView: 0x1440xxxxx; ..-> 	# the 'view' of UIAlert* controller
	# 
	# therefore, you'd either patch ptr(0x143exxxxx:UITransitionView) and ptr(0x1440xxxxx:UIAlertController)
	# or only patching ptr(0x1440xxxxx:UIAlertController) if no super-view is present.

# Use Cycript to hide UIAlert[View|Controller], and/or any other top-level view(s) 
# containing this UIAlert; as explained in above snippet.

	[#0x1440xxxxx setHidden:YES]
	[#0x143exxxxx setHidden:YES]
``` 

**Syslog Macros**

```
# => common.cy
@import com.saurik.substrate.MS
NSLog_ = dlsym(RTLD_DEFAULT, "NSLog")
NSLog = function() { var types = 'v', args = [], count = arguments.length; for (var i = 0; i != count; ++i) { types += '@'; args.push(arguments[i]); } new Functor(NSLog_, types).apply(null, args); }
```

Load the macro into Cycript: 

```
$ cycript -p App common.cy
$ cycript -p App
```

Read syslog for log lines:

```
socat - UNIX-CONNECT:/var/run/lockdown/syslog.sock
watch
```


