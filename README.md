<p align="center"><b>~ notes</b></p>

The `~ notes` is a dedicated repository for my [digital garden](https://github.com/MaggieAppleton/digital-gardeners#what-is-digital-gardening). These notes are published via [Hugo](https://gohugo.io) and it uses custom theme which presents these notes in stacked view; meaning each note is stacked side by side, similar to [Obsidian](https://obsidian.md/), [Bangle](https://bangle.io/) and [Dendron](https://www.dendron.so/). Read these [~notes](http://notes.durakiconsulting.com) or start contributing. You can check my theme [haxor-notes](./themes/haxor-notes), included in this repository.

## Inspiration

* [Nikita Voloboev](https://wiki.nikiv.dev/)
* [digital-gardeners](https://github.com/MaggieAppleton/digital-gardeners)

## Contributing 😇

The build phase uses parameters (such is `[params.styles]`) defined in `config.toml`. It’s possible to deploy **dark** version as well, read more in bundled `*.css`. The User Interface theme used in `~notes` is matching that of my [blog](https://duraki.github.io). The site is largely inspired by Andy’s notes, while credits for original theme goes to Justin. My [hard fork](./themes/haxor-notes) fixes many bugs and also adds number of enhancements to the Hugo theme. My [haxor-notes](./themes/haxor-notes) theme is bundled in this repository.

**Usage Prerequisites**

First install [Hugo](https://gohugo.io) and try printing version information. This repository has been tested on MacOS.

```
$ brew install hugo
$ hugo version # => hugo v0.98.0+extended darwin/amd64
```

## Development Environment 🎉

**Engine Debugger**

Sometimes, Hugo breaks. Don't we all? 😔 During the design and implementation of the theme used, I've added a few shortcodes and quick references to quickly dump debug information from the templating pages. I use custom (fork) version of [hugo-debugprint](https://github.com/kaushalmodi/hugo-debugprint) which is bundled in this repository, or call `{{ partial "console_log" }}` to dump the variables directly in the Web Console. [Log Example](https://duraki.github.io/notes/debug/dbg) are also part of the notes.

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
$ git clone git@github.com:duraki/notes.git
$ cd notes/
```

Then use Hugo command-line interface to start debugging:

```
# => bring Hugo server at http://127.0.0.1:8880
$ hugo server --bind 127.0.0.1 --port 8800 --baseURL="http://127.0.0.1:8800/" -d docs/ --config config.toml # [--minify]

# => bring Hugo server and output log more verbosly
$ hugo server [..] --config config.toml --verboseLog 
```

**Production Environment**

```
# => builds to 'docs/' using defined config, and minifies the final build
$ hugo -D --config config.toml -d docs/ --enableGitInfo --minify        # => only docs/ should be deployed
```

**Publish to GitHub**

The following line compiles content of `~notes`, commits a new release, and deploys it to `master` branch. If your GitHub is setup to serve as a [Pages](https://docs.github.com/en/pages) then you are good to.

```
$ hugo -D --config config.toml -d docs/ --minify && git add . && git commit -m "Release 🥳" && git push origin master
```

<p align="center"><small>📝</small><br>by <a href="https://twitter.com/0xduraki">0xduraki</a></p>

