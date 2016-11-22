#!/usr/bin/env sh

set -e

REPO_ROOT=$(git rev-parse --show-toplevel)
OPAM_ROOT=${REPO_ROOT}/_build/opam

# Collect the license metadata in a central place
OUTPUT=${REPO_ROOT}/repo/licenses/

if [ $# = 0 ]; then
  echo "Usage:"
  echo "$0 <package0> ... <packageN>"
  echo "  -- look up license terms for a list of packages"
fi

for DEP in "$@"; do
  echo "Calculating transitive dependencies required by $DEP"
  opam list --required-by "$DEP" --recursive --installed | tail -n +2 > "dependency.$DEP.raw"
  awk '{print $1"."$2}' < "dependency.$DEP.raw" > "dependency.$DEP"
  rm "dependency.$DEP.raw"
done
cat dependency.* | sort | uniq > all-packages.txt
rm -f "dependency.*"

rm -f "*.extracted"
while read -r PACKAGE; do
  echo "looking for license for ${PACKAGE}"
  URL=$(opam info --field upstream-url "$PACKAGE")
  rm -f "/tmp/opam.out"
  if [ -z "${URL}" ]; then
    echo "$PACKAGE has no source: skipping"
    continue
  fi
  if [ -e "$OUTPUT/LICENSE.$PACKAGE.skip" ]; then
    echo "$PACKAGE is not linked: skipping"
    continue
  fi
  # if a file has a manually-edited override, use it
  if [ ! -e "$OUTPUT/LICENSE.$PACKAGE" ]; then
    rm -f "$PACKAGE.files"
    KIND=$(opam info --field upstream-kind "$PACKAGE")
    if [ "$KIND" = git ] || [ "$KIND" = local ]; then
      # there is an entry under the system switch packages.dev if pinned
      PROJECT=$(echo "$PACKAGE" | sed -n 's/^\([^.]*\).*/\1/p')
      if [ -e "$OPAM_ROOT/system/packages.dev/$PROJECT" ]; then
        DIR=$OPAM_ROOT/system/packages.dev/$PROJECT
      else
        DIR=$OPAM_ROOT/packages.dev/$PACKAGE
      fi
      echo "$DIR"
      ls "$DIR" | grep LICENSE >> "$PACKAGE.files" || true
      ls "$DIR" | grep COPYING >> "$PACKAGE.files" || true
      if [ -z "$(cat "$PACKAGE.files")" ]; then
        echo "No LICENSE or COPYING file found in $DIR; please write LICENSE.$PACKAGE yourself"
        exit 1
      fi
      # extract all the license files we found
      rm -f "$OUTPUT/LICENSE.$PACKAGE.extracted"
      xargs -I % cp "$DIR"/% . < "$PACKAGE.files"
      while read -r i; do
        echo "$i:" >> "$OUTPUT/LICENSE.$PACKAGE.extracted"
        cat "$i" >> "$OUTPUT/LICENSE.$PACKAGE.extracted"
        rm "$i"
      done < "$PACKAGE.files"
      rm -f "$PACKAGE.files"
    else
      FILE=$OPAM_ROOT/packages.dev/$PACKAGE/$(basename "$URL")
      if [ ! -e "$FILE" ]; then
        echo "$FILE doesnt exist"
        exit 1
      fi
      echo "$FILE"
      rm -f "$PACKAGE.files"
      # NB lwt's LICENSE file references the COPYING file
      tar -tf "$FILE" | grep LICENSE >> "$PACKAGE.files" || true
      tar -tf "$FILE" | grep COPYING >> "$PACKAGE.files" || true
      if [ -z "$(cat "$PACKAGE.files")" ]; then
        echo "No LICENSE or COPYING file found in $FILE; please write LICENSE.$PACKAGE yourself"
        exit 1
      fi
      # extract all the license files we found
      rm -f "$OUTPUT/LICENSE.$PACKAGE.extracted"
      tar -xf "$FILE" -T "$PACKAGE.files"
      while read -r i; do
        echo "$i:" >> "$OUTPUT/LICENSE.$PACKAGE.extracted"
        cat "$i" >> "$OUTPUT/LICENSE.$PACKAGE.extracted"
        rm "$i"
      done < "$PACKAGE.files"
      for i in $(sort -r "$PACKAGE.files"); do
        DIR=$(dirname "$i")
        if [ -e "$DIR" ]; then
          rmdir -p "$DIR"
        fi
      done
      rm -f "$PACKAGE.files"
    fi
  fi
done < all-packages.txt
