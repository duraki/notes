# makefile for ~duraki/notes

# Defaults
.DEFAULT_GOAL := help

# Variables
HUGO_CMD = hugo
BRANCH := $(shell git rev-parse --abbrev-ref HEAD) # Current branch
HASH := $(shell git rev-parse HEAD) # Current HEAD

# Targets
.PHONY: help dev prod

help:
	@echo "Available commands:"
	@echo "	make help	- Show this help"
	@echo "	make dev 	- Run Hugo development server"
	@echo "	make prod 	- Build the static Hugo website for production"
	@echo "	make push 	- Commit and push the tracked files on current branch"

dev:
	$(HUGO_CMD) server --disableFastRender --ignoreCache --noHTTPCache --gc 

prod:
	$(HUGO_CMD)

push:
	git commit -m "[makefile] - mkf-assisted branch changes commit+push" --no-verify
	git push origin $(BRANCH) --no-verify
