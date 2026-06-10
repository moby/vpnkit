#!/usr/bin/env sh
set -e

# echo $OPAM_SWITCH_PREFIX
echo $1

pkg=(
    $(opam list -s --installed --required-by=vpnkit --recursive --columns package --nobuild --color=never)
)

dir="sbom_temp"
mkdir "$dir"

cp vpnkit.opam "$dir"

for p in ${pkg[@]}; do
  echo $p >> "$1"
  cp -r "$OPAM_SWITCH_PREFIX/.opam-switch/packages/$p" "$dir/$p"
done

touch vpnkit.spdx.json
docker run --rm \
    -v ./$dir:/vpnkit \
    -v ./vpnkit.spdx.json:/out/vpnkit.spdx.json \
    -e BUILDKIT_SCAN_SOURCE=/vpnkit \
    -e BUILDKIT_SCAN_DESTINATION=/out \
    -e BUILDKIT_SCAN_EXTRA_SCANNERS=opam-cataloger \
    docker/scout-sbom-indexer:1.15

# Fix the relationships and file to point to the binary
mv vpnkit.spdx.json vpnkit.spdx
jq -c --arg uid "${$(uuidgen)//-/}" '
"SPDXRef-File-\($uid)" as $fileId
| .predicate
| del(.files[])
| .files |= . + [
    {
        "SPDXID": $fileId,
        "fileName": "vpnkit.exe",
        "licenseConcluded": "NOASSERTION"
    }
]
| .relationships[] |= (
     select(.relationshipType == "OTHER").relatedSpdxElement |= $fileId
)
' vpnkit.spdx > vpnkit.spdx.json

rm -rf sbom_temp
