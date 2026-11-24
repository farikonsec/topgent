#!/usr/bin/env sh
# Remove installed Topgent programs while preserving operator config and state.
set -eu

prefix=${HOME:?HOME is not set}/.local
if [ "${1:-}" = "--prefix" ] && [ "$#" -eq 2 ]; then
  prefix=$2
elif [ "$#" -ne 0 ]; then
  echo "usage: uninstall.sh [--prefix PATH]" >&2
  exit 2
fi

root=$prefix/lib/topgent
for name in topgent topgent-ui; do
  link=$prefix/bin/$name
  if [ -L "$link" ]; then
    target=$(readlink "$link")
    case $target in
      ../lib/topgent/*) rm -- "$link" ;;
    esac
  fi
done
rm -f -- "$prefix/share/applications/topgent.desktop"
rm -f -- "$prefix/share/icons/hicolor/512x512/apps/topgent.png"
if [ -d "$root" ]; then
  rm -rf -- "$root"
fi
echo "Topgent programs removed from $prefix"
echo "Configuration and state were preserved."
