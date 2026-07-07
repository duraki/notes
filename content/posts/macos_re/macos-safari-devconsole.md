---
title: "Safari DevConsole Internals"
---

#### Function Dump (#internal)

When inside the Safari Development Console, use `[Class].prototype` ie. using MDN [docs method call](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/storage) for `Navigator.storage` from within DevConsole tool, which will reveal return types and methods to referenced calls.

{{< imgcap title="Safari DevTools - Dumping Functions" src="/posts/images/devtools.png" >}}

	>>> Make sure to enable Development Tools in Safari Setting's.

#### Dump Indexed Database's (DBIndex)

The file is a bit longer therefore it sits on my Gists. Thanks to M. Puric for the giveaway.

```
async function getIndexedDBData(databaseName, objectStoreName) {
	// https://gist.github.com/duraki/36cf7a2e040d7de9fe39bca382ec0189
})();
```

#### Safari Snippets

**Bypassing (Server/Client) Process Environments**

Useful when reversing Electron based "applications". Force it via `node`.

```
const DEBUG = process.env.DEBUG; // read from environment
# ...
# function log(...items){
# // ...

# 		exec as ...
$ DEBUG=true node scripts.js
```

**Proper `log(*)` function with multiple ARGS**

```
function log(...items){   //console.log can take multiple arguments!
  if(typeof DEBUG !== 'undefined' && DEBUG === true){
	console.log(...items)
  }
}
```

**Extended Logging via key-assigned `log(*)`**

```
function log(key, ...items){
  if(typeof DEBUG !== 'undefined' && DEBUG.includes(key)){
	console.log(...items)
  }
}

log('database','results recieved');             // using database key
log('http','route not found', request.url);     // using http key
```

#### Inspecting WebView(s) in MacOS Native Apps

Interestingly, the macOS "System Preferences" app is also a WebView-based app, shipped with the OS in a native feel and look typical graphical interface design you'd normally expect in Apple UI Kit/design guidelines for Desktop applications.

Nevertheless, it is possible to inspect the WebView(s) in the "System Preferences" app using the techniques described below:

```bash
# First, enable WebKit Developer Extras in the global domain, this will enable the Web Inspector in all WebView-based apps
# on MacOS systems running Safari or other WebView-based implementations
#
$ defaults write NSGlobalDomain WebKitDeveloperExtras -bool true
$ defaults write -g WebKitDeveloperExtras -bool YES
```

After enabling WebKit Developer Extras, you can use the Web Inspector to inspect the WebView(s) in the "System Preferences" app (and other WebView-based apps running on your Mac) by right-clicking on the window/element and selecting "Inspect Element" from the context menu as is the typical case with ie. _Safari_ browser.

{{< imgcap title="System Preferences - Context Menu allowing to _Inspect Element_" src="/posts/images/macos-web-inspector-family-sharing-music-context-menu.png" >}}

This triggers the Safari Web Inspect and provides inspection of the view like a browser. These Web-views in macOS shows how engineers at Apple are leveraging _non-standard CSS_ attributes in Webkit to _mimic UIs of the macOS_ which are otherwise built with native system APIs. More details have been provided in the [blog post](https://blog.jim-nielsen.com/2022/inspecting-web-views-in-macos/) by Jim Nielsen back in _y22_ - feel free to poke around and learn more.
