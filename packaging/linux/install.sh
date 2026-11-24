#!/usr/bin/env sh
# Install one Topgent Linux bundle for the current user, atomically by version.
set -eu

prefix=${HOME:?HOME is not set}/.local
if [ "${1:-}" = "--prefix" ] && [ "$#" -eq 2 ]; then
  prefix=$2
elif [ "$#" -ne 0 ]; then
  echo "usage: ./install.sh [--prefix PATH]" >&2
  exit 2
fi

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
version=$(cat "$here/VERSION")
case $version in
  ""|*[!A-Za-z0-9._+-]*) echo "invalid VERSION in bundle" >&2; exit 2 ;;
esac

root=$prefix/lib/topgent
destination=$root/$version
stage=$root/.install-$$
bindir=$prefix/bin
apps=$prefix/share/applications
icons=$prefix/share/icons/hicolor/512x512/apps

cleanup() { rm -rf -- "$stage"; }
trap cleanup EXIT HUP INT TERM
mkdir -p -- "$root" "$bindir"

if [ -e "$root/current" ] && [ ! -L "$root/current" ]; then
  echo "$root/current exists and is not a Topgent version link" >&2
  exit 2
fi

ui_source=$here/topgent-ui
[ -f "$ui_source" ] || ui_source=$here/Topgent

if [ -d "$destination" ]; then
  for name in topgent topgent-capture topgent-sensor; do
    if [ -f "$here/$name" ]; then
      if [ ! -f "$destination/$name" ] || ! cmp -s -- "$here/$name" "$destination/$name"; then
        echo "$destination already contains a different $name; use a distinct version" >&2
        exit 2
      fi
    fi
  done
  if [ -f "$ui_source" ] \
    && { [ ! -f "$destination/topgent-ui" ] \
      || ! cmp -s -- "$ui_source" "$destination/topgent-ui"; }; then
    echo "$destination already contains a different topgent-ui; use a distinct version" >&2
    exit 2
  fi
else
  mkdir -- "$stage"
  installed=0
  if [ -f "$here/topgent" ]; then
    install -m 0755 -- "$here/topgent" "$stage/topgent"
    installed=1
  fi
  if [ -f "$ui_source" ]; then
    install -m 0755 -- "$ui_source" "$stage/topgent-ui"
    installed=1
  fi
  for name in topgent-capture topgent-sensor; do
    if [ -f "$here/$name" ]; then
      install -m 0750 -- "$here/$name" "$stage/$name"
    fi
  done
  if [ "$installed" -eq 0 ]; then
    echo "bundle contains neither topgent nor topgent-ui" >&2
    exit 2
  fi
  for name in README.md LICENSE NOTICE topgent.png topgent.desktop; do
    [ ! -f "$here/$name" ] || install -m 0644 -- "$here/$name" "$stage/$name"
  done
  mv -- "$stage" "$destination"
fi

old=
if [ -L "$root/current" ]; then
  old=$(readlink "$root/current")
fi
if [ -n "$old" ] && [ "$old" != "$version" ] && [ -d "$root/$old" ]; then
  ln -sfn -- "$old" "$root/previous"
fi
ln -sfn -- "$version" "$root/current"

for name in topgent topgent-ui; do
  if [ -f "$destination/$name" ]; then
    ln -sfn -- "../lib/topgent/current/$name" "$bindir/$name"
  fi
done
install -m 0755 -- "$here/uninstall.sh" "$root/uninstall.sh"
install -m 0755 -- "$here/rollback.sh" "$root/rollback.sh"

if [ -f "$destination/topgent-ui" ] && [ -f "$destination/topgent.desktop" ]; then
  mkdir -p -- "$apps" "$icons"
  if [ -f "$destination/topgent.png" ]; then
    install -m 0644 -- "$destination/topgent.png" "$icons/topgent.png"
  fi
  escaped=$(printf '%s' "$bindir/topgent-ui" | sed 's/[\\"]/\\&/g')
  sed "s|^Exec=.*$|Exec=\"$escaped\"|" "$destination/topgent.desktop" \
    > "$apps/topgent.desktop"
  chmod 0644 "$apps/topgent.desktop"
  command -v update-desktop-database >/dev/null 2>&1 \
    && update-desktop-database "$apps" >/dev/null 2>&1 || true
fi

trap - EXIT HUP INT TERM
echo "Topgent $version installed under $prefix"
echo "Rollback: $root/rollback.sh --prefix $prefix"
echo "Uninstall: $root/uninstall.sh --prefix $prefix"
