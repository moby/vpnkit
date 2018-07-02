The target `make OSS-LICENSES` in the root Makefile iterates through all
the package dependencies, extracting any `LICENSE`, `LICENSE.md`, `COPYING`
files from the source .tar. If a package does not contain one of these files,
it must be manually included in this directory. Use either

- LICENSE.<foo>.skip: the license should not be included because it is
  not linked into the final executable (e.g. used for building only)
- LICENSE.<foo>: the license for <foo>

