#!/usr/bin/env sh

# Common setup for both Appveyor and Circle CI

REPO_ROOT=$(shell git rev-parse --show-toplevel)
OPAMROOT=$(REPO_ROOT)/_build/opam
OPAMFLAGS=MACOSX_DEPLOYMENT_TARGET=$(MACOSX_DEPLOYMENT_TARGET) \
	  OPAMROOT="$(OPAMROOT)" \
	  OPAMYES=1 OPAMCOLORS=1

mkdir -p $(OPAMROOT)
$(OPAMFLAGS) opam init -n --comp=$(OPAM_COMP) --switch=$(OPAM_COMP) \
	local "$(OPAM_REPO)"
$(OPAMFLAGS) opam update -u -y
$(OPAMFLAGS) opam install depext -y
$(OPAMFLAGS) opam install depext-cygwinports -y || true

$(OPAMFLAGS) OPAMBUILDTEST=1 opam depext -u slirp
# Don't run all the unit tests of all upstream packages in the universe
# for speed
$(OPAMFLAGS) opam install $(shell ls -1 $(OPAM_REPO)/packages/upstream) -y
$(OPAMFLAGS) OPAMVERBOSE=1 opam install --deps-only slirp -y
# ... but install tcpip with tests enabled
$(OPAMFLAGS) OPAMVERBOSE=1 opam reinstall tcpip -y -t

$(OPAMFLAGS) OPAMVERBOSE=1 make
$(OPAMFLAGS) OPAMVERBOSE=1 make OSS-LICENSES
$(OPAMFLAGS) OPAMVERBOSE=1 make COMMIT
$(OPAMFLAGS) OPAMVERBOSE=1 make test
