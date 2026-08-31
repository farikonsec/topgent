#!/usr/bin/env bash
# Refresh the vendored IP-to-ASN table.
#
# The table names the country and the announcing network for every endpoint an
# agent reaches. It is a snapshot, published daily, and it goes stale: networks
# are reassigned and an address that resolved to one operator last year may
# resolve to another now.
#
# Run this deliberately. It replaces a vendored file that the build compiles
# into the binary, which is a supply-chain input, so the diff is worth reading
# and the tests are worth running afterwards.
set -euo pipefail

source="https://iptoasn.com/data/ip2asn-combined.tsv.gz"
target="crates/topgent-ui/data/ip2asn-combined.tsv.gz"

cd "$(dirname "$0")/.."
[ -f "$target" ] || { echo "run this from a checkout: $target is missing" >&2; exit 1; }

echo "fetching $source"
curl --fail --show-error --silent --location --output "$target.new" "$source"

# A truncated download must not replace a working table.
if ! gzip -t "$target.new"; then
  rm -f "$target.new"
  echo "the download is not valid gzip; the vendored table is unchanged" >&2
  exit 1
fi
lines=$(gzip -dc "$target.new" | wc -l | tr -d ' ')
if [ "$lines" -lt 100000 ]; then
  rm -f "$target.new"
  echo "the download has only $lines rows; the vendored table is unchanged" >&2
  exit 1
fi

mv "$target.new" "$target"
echo "$lines rows. now run: cargo test -p topgent-ui ownership"
