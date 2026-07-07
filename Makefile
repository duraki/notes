# makefile for ~duraki/notes

# Defaults
.DEFAULT_GOAL := help

# Variables
HUGO_CMD = hugo
BRANCH := $(shell git rev-parse --abbrev-ref HEAD) # Current branch
HASH := $(shell git rev-parse HEAD) # Current HEAD

# Targets
.PHONY: help dev prod push deps

help:
	@echo "Available commands:\n"
	@echo "	make help	- Show this help message"
	@echo "	make dev 	- Run Hugo development server"
	@echo "	make prod 	- Build the static Hugo website for production"
	@echo "	make push 	- Commit and push the tracked files on current branch"
	@echo " \t--"
	@echo "	make deps	- Prepare project dependencies to run the [dev/prod] builds"

dev:
	@make deps
	$(HUGO_CMD) server --disableFastRender --ignoreCache --noHTTPCache --gc

prod:
	$(HUGO_CMD)

push:
	git commit -m "[makefile] - mkf-assisted branch changes commit+push" --no-verify
	git push origin $(BRANCH) --no-verify

deps:
	@echo "Preparing dependencies..."
	@brew tap-new local/hugo 2>/dev/null || true
	@cp $(PWD)/.github/.deps/hugo_0.98.0.rb "$$(brew --repo local/hugo)/Formula/hugo.rb"
	brew install --build-from-source local/hugo/hugo -y
	@echo "\nForcing dev-oriented Hugo tag: 0.98.0 ~\n\t"
	hugo version
