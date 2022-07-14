# ~ notes

A `~ notes` is a dedicated page of my knowledgebase and oneliners for multiple purposes, as well as explaining my toolset and directory. You can observe or change those notes following Hugo notation. It is implemented due to speed and support of notes themeing option. The notes idea are taken from Andy's note-taking samples on his site.

### Setup Prerequisites

First install Hugo and try building config.toml manually like so:

```
$ brew install hugo
$ hugo version
```

### Development Environment

```
# => serves at http://127.0.0.1:8880 ...
$ hugo server --minify --bind 127.0.0.1 --port 8800 --baseURL="http://127.0.0.1:8800/"
```

### Production Environment

```
# => builds to docs/ ...
$ hugo -D --config config.toml -d docs/ --enableGitInfo --minify 
```

### Release

```
$ git add . && git commit -m "Release :party:" && git push origin master
``` 