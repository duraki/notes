---
title: "Frida"
---

## Frida Internals

[frida-gum](https://github.com/frida/frida-gum) is a cross-platform instrumentation and introspection library written in C. This library is consumed by frida-core through its JavaScript bindings, GumJS. See [official documentation](https://github.com/frida/frida-gum#gum) for more details and possible providers. The [following example](https://github.com/oleavr/ios-inject-custom) shows how to use `frida-gum` for standalone injection; specifically [via iOS dylib injection](/dyld-for-ios).

## Prototyping with Fermion

[Fermion](https://github.com/FuzzySecurity/Fermion) is an electron application that wraps `frida-node` and `monaco-editor`. It offers a fully integrated environment to prototype, test and refine Frida scripts through a single UI. With the integration of Monaco come all the features you would expect from Visual Studio Code: Linting, IntelliSense, keybindings, etc. In addition, Fermion has a TypeScript language definition for the Frida API so it is easy to write Frida scripts.

## Frida Scripting

It's recommended to develop Frida scripts using TypeScript, which contains code auto-completion and instant type-checking feedback. The TypeScript is typically compiled to a final Javascript file `agent.js`.

```
$ git clone https://github.com/oleavr/frida-agent-example.git my-new-script
$ cd my-new-script/
$ npm install
$ npm run watch
$ frida -U -f com.durakiconsulting.com --no-pause -l _agent.js
```

**Scripts Directory**

* [FridaLib](https://github.com/4ch12dy/FridaLib) - iOS/android frida library for reversing 
* [Android/Windows Scripts](https://github.com/apkunpacker/FridaScripts) - Random Frida scripts for Android and WinNT

## Frida Stalker

**Scripts Dictionary**

* [Interruptor](https://github.com/FrenchYeti/interruptor) - Human-friendly interrupts hook library based on Frida's Stalker

## Tools of Trades

* [vscode-frida](https://github.com/ChiChou/vscode-frida) is recommended if you are using VSCode