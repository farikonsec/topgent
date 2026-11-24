#!/usr/bin/env sh
# Switch an installed Topgent user package to its previous retained version.
set -eu

prefix=${HOME:?HOME is not set}/.local
if [ "${1:-}" = "--prefix" ] && [ "$#" -eq 2 ]; then
  prefix=$2
elif [ "$#" -ne 0 ]; then
  echo "usage: rollback.sh [--prefix PATH]" >&2
  exit 2
fi

root=$prefix/lib/topgent
if [ ! -L "$root/current" ] || [ ! -L "$root/previous" ]; then
  echo "no previous Topgent version is available" >&2
  exit 2
fi
current=$(readlink "$root/current")
previous=$(readlink "$root/previous")
case $current:$previous in
  *[!A-Za-z0-9._+:-]*) echo "invalid installed version link" >&2; exit 2 ;;
esac
if [ ! -d "$root/$previous" ]; then
  echo "previous Topgent version is missing" >&2
  exit 2
fi
ln -sfn -- "$previous" "$root/current"
ln -sfn -- "$current" "$root/previous"
echo "Topgent rolled back from $current to $previous"
