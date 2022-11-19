---
title: "Bash in simple words"
---

Although in some cases it's better to use a systems language like C or Go, Bash is an ideal systems language for smaller POSIX-oriented tools or command line tasks. Why you may ask?

* It's everywhere. No, really .. it is.
* It's easy. Everyone can learn it.
* It's ready for interop. Write complex parts in C, use them in Bash.

**Bash scripting**

The first two statements of your Bash script should always be:

```
#!/usr/bin/env bash
set -euo pipefail
```

The first statement is a Unix/Linux portable way of finding the location of the `bash` interpreter. The second statement combines:

* `set -e` - ensures that your script stops on first command failure
* `set -u` - ensures that your script exits on the first unset variable encountered
* `set -o pipefail` - ensures that failed piped commands is also exit status

**Bash Rules**

* [Always double quote](http://mywiki.wooledge.org/Quotes) variables, including subshells. No naked `$` signs
* All code goes in a functions, yes, even `main`, just remeber to call it
* Avoid global variables in the script
* Always call the main function via `main "$@"`
* Always use `local` when setting a variable
* Variables should be lowercased, except when exported to environment
* Always use `set -eo pipefail`; early exits on failures, exit codes awareness
* Force exit code non-zero with `|| true`, in case needed
* Function are defined as `myFunc() { .. }`, not `function myFunc() { ... }`
* Use `[[` instead of `[` or `test`
* Never use backticks to execute command, instead use `$( ... )`
* Prefer absolute paths -- ie. `$PWD`, combined with relative path `./SomeFile.txt`
* Use `declare` and name variable arguments at the top of the function `declare arg1="$1" arg2="$2"`
* Use `mktemp` for temporary files, make sure to clean them up with `trap`
* Warnings and erros go to `$stderr`, and anything else to `$stdout`

**Bash Tips**

* Use Bash variable substituion, before leveraging `awk/sed/?`
* Generally use double quotes, unless when single quotes are needed
* Use `&&` and `||` for conditionals
* Use `printf` instead of `echo`
* In `if/do/?`-expressions, put `then`, `do` on the same line
* Skip `[[ ... ]]` if you can test for exit code instead
* Use `.sh` or `.bash` extension if file is meant to be included, but never on the executable script 
* Complex one-lines such is `sed`, `ruby`, `awk` goes into its own function with descriptive name
* Good idea to include `[[ "$TRACE" ]] && set -x`
* Use subcommands for necessary different "modes"
* If possible, define a method description at the top of the function `declare desc="description"`
* If you added `desc` declaration, you can query it using reflection `eval $(type FUNCTION_NAME | grep 'declare desc=') && echo "$desc"`
* Use hard tabs, `heredocs` ignore leading tabs, allowing better indentation

**Examples**

Regular function with named arguments:

```
regular_func() {
  declare arg1="$1" arg2="$2" arg3="$3"

  # ...
}
```

Variadic functions:

```
variadic_func() {
  local arg1="$1"; shift
  local arg2="$1"; shift
  local rest="$@"

  # ...
}
```

Conditionals:

```
# Test for exit code (-q mutes output)
if grep -q 'foo' somefile; then
  ...
fi

  # ... or ...

# Test for output (-m1 limits to one result)
if [[ "$(grep -m1 'foo' somefile)" ]]; then
  ...
fi
```

**Bash Boilerplate**:

```
# Author:     Halis Duraki <h@durakiconsulting.com>
# License:    durakiconsulting (c) <year> all rights reserved
# Usage:      
#             $ shexc

#!/bin/sh 
set -euo pipefail

log() {
    printf '\033[32m->\033[m %s\n' "$*"
}

die() {
    log "$*" >&2
    exit 1
}

usage() {
    echo "${0##*/} ARGS
    desc
    "
    exit 0
}

main() {
  usage()
}

main "$@"
```

**Reference**

* [Bash Hackers](http://wiki.bash-hackers.org/scripting/start) and [common pitfalls](http://wiki.bash-hackers.org/scripting/newbie_traps)
* [Interactive Bash](http://samrowe.com/wordpress/advancing-in-the-bash-shell/)
* [Google's Bash styleguide](https://google.github.io/styleguide/shell.xml)
* [shellcheck](https://github.com/koalaman/shellcheck) to lint and detect erros
