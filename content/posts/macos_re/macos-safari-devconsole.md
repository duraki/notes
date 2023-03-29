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
