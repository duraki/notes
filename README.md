<p align="center"><b>~ notes</b></p>

The `~ notes` is a dedicated repository for my [digital garden](https://github.com/MaggieAppleton/digital-gardeners#what-is-digital-gardening). These notes are published via [Hugo](https://gohugo.io) and it uses custom theme which presents these notes in stacked view; meaning each note is stacked side by side, similar to [Obsidian](https://obsidian.md/), [Bangle](https://bangle.io/) and [Dendron](https://www.dendron.so/). Read these [~notes](http://notes.durakiconsulting.com) or start contributing. You can check my theme [haxor-notes](./themes/haxor-notes), included in this repository.

## Inspiration

* Check: [docs/CREDITS](notes/docs/CREDITS.md) for shortcodes, tutorials & inspiration

## Contributing 😇

The build phase uses parameters (such is `[params.styles]`) defined in `config.toml`. It’s possible to deploy **dark** version as well, read more in bundled `*.css`. The User Interface theme used in `~notes` is matching that of my [blog](https://duraki.github.io). The site is largely inspired by Andy’s notes, while credits for original theme goes to Justin. My [hard fork](./themes/haxor-notes) fixes many bugs and also adds number of enhancements to the Hugo theme. My [haxor-notes](./themes/haxor-notes) theme is bundled in this repository.

**Usage Prerequisites**

First install [Hugo](https://gohugo.io) and try printing version information. This repository has been tested on MacOS.

```
$ brew install hugo
$ hugo version # => hugo v0.98.0+extended darwin/amd64
```

## Quick Usage

**Development Oneliner:**

```
$ hugo server
## Start building sites …
## Web Server is available at http://localhost:1313/ (bind address 127.0.0.1)
```

**Production Oneliner** (*[push to GitHub](/.github/workflows/hugo.yml) `master` for deploy*)**:**

```
$ hugo
## Start building sites …
```

Start reading Hugo's documentation for [Functions](https://gohugo.io/categories/functions), [Templates](https://gohugo.io/templates/) and [Variables](https://gohugo.io/variables/) to get the feel of it.

### Full Usage

**Publish to GitHub**

The following line compiles content of `~notes`, commits a new release, and deploys it to `master` branch. If your GitHub is setup to serve as a [Pages](https://docs.github.com/en/pages) then you are good to.

```
$ hugo && git add . && git commit -m "Release 🥳" && git push origin master
```

### CSS Editing

Edit the SCSS (`*.scss`) from within the themes directory (ie. `themes/haxor-notes/assets/css`) located in this repository. The `hugo server` automatically compiles the SCSS to CSS and updates the rendering results using hotreload while running local development server.

```scss
// notes/themes/haxor-notes/assets/css/index.scss

/* ... [REDACTED] ... */
/* add other CSS class stylings */
```

This file compiles automatically to `*.css` asset files upon saving the file; as evident by the `hugo server` Terminal output below:

```sh
Change detected, rebuilding site (#75).
2024-11-28 04:24:39.967 +0100
Asset changed /css/index.scss
Web Server is available at http://localhost:1313/ (bind address 127.0.0.1)
Total in 273 ms
```

The changes should reflect instantly on the `~notes` webpages, or if not, refresh manually.

### Development Environment 🎉

**Repository Hooks**

This repository implements a *pre-commit* hook located in `.git/hooks/pre-commit`. This *pre-commit* hook is using [`htmltest`](https://github.com/wjdp/htmltest) to verify and make sure all links in markdown are valid. If the  content in these markdown files have a broken URLs linked, it will report back these errors in your tty (Terminal) and stops you from commiting the changes on [GitHub](https://github.com/duraki/notes). In case you need to skip this commit and push to remote accordingly, use `--no-verify` flag when using `git commit`.

**TODO:**
- [ ] Replace [htmltest](https://github.com/wjdp/htmltest) with [lychee](https://github.com/lycheeverse/lychee)
- [ ] Fix this *pre-commit* script to support [lychee](https://github.com/lycheeverse/lychee)

```bash
$ cat .git/hooks/pre-commit

#!/bin/sh
#
if ls -l './public/'; then
  echo "Directory [/public] found, cont. ... [YES]"
else
  hugo -D $(pwd)/config.toml -d $(pwd)/public
fi

RESULT="1"
$(pwd)/bin/htmltest -c $(pwd)/bin/.htmltest.yml
set $RESULT="$?"

if [ "$RESULT" == "0" ]; then
  echo "Error with links"
  exit
fi

# Redirect output to stderr.
exec 1>&2
```


**Engine Debugger**

Sometimes, Hugo breaks. Don't we all? 😔 During the design and implementation of the theme used, I've added a few shortcodes and quick references to quickly dump debug information from the templating pages. I use custom (fork) version of [hugo-debugprint](https://github.com/kaushalmodi/hugo-debugprint) which is bundled in this repository, or call `{{ partial "console_log" }}` to dump the variables directly in the Web Console. [Log Example](/content/debug/dbg.md) are also part of the notes.

Using `hugo-debugprint` is easy, and you can do so via:

```
# => using partial
{{ partial "debugprint.html" site }}    # => works only for themes/*

# => using shortcodes
{{< debug param="myParam" var="1" >}}   # => works both for themes/* and the hugo site
{{< debug site >}}                      # => dump "site" variable
```

Using `console_log` to log in Web Console:

```
{{ partial "console_log" ( site ) }}            # => dump .site variable to the web console
{{ partial "console_log" (. | plainify) }}      # => in case of errors, 'plainify' your data
```

**Local Server**

Obviously, clone the repository:

```
$ git clone git@github.com:duraki/notes.git && cd notes/
$ hugo server       # uses config.toml
```

~Then use Hugo command-line interface to start debugging:~

<details><summary>OLD WAY</summary>
<p>

```
$ hugo server --bind 127.0.0.1 --port 8800 --baseURL="http://127.0.0.1:8800/notes" -d docs/ --config cfg/local.toml --verboseLog  # [ --minify ]

# => bring Hugo server and output log more verbosly
$ hugo server [..] --config cfg/[local|prod].toml --verboseLog
```

</p>
</details>

---

<p align="center"><small>📝</small><br>by <a href="https://twitter.com/0xduraki">0xduraki</a></p>
