#!/usr/bin/env sh
# Reversible package lifecycle test using harmless fixture executables.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
scratch=$(mktemp -d)
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT HUP INT TERM
prefix=$scratch/prefix
mkdir -p "$scratch/v1" "$scratch/v2" "$prefix/state/topgent" "$prefix/config/topgent"
printf 'keep state\n' > "$prefix/state/topgent/sentinel"
printf 'keep config\n' > "$prefix/config/topgent/sentinel"

make_bundle() {
  dir=$1 version=$2
  printf '%s\n' "$version" > "$dir/VERSION"
  for name in topgent topgent-ui topgent-capture topgent-sensor; do
    cat > "$dir/$name" <<EOF
#!/usr/bin/env sh
echo '$name $version'
EOF
    chmod 0755 "$dir/$name"
  done
  cp "$repo/packaging/linux/install.sh" "$repo/packaging/linux/uninstall.sh" \
     "$repo/packaging/linux/rollback.sh" "$repo/packaging/linux/topgent.desktop" "$dir/"
  : > "$dir/topgent.png"
}

make_bundle "$scratch/v1" 1.0.0-test
make_bundle "$scratch/v2" 2.0.0-test
"$scratch/v1/install.sh" --prefix "$prefix" >/dev/null
test "$("$prefix/bin/topgent")" = "topgent 1.0.0-test"
test "$(stat -c %a "$prefix/lib/topgent/1.0.0-test/topgent-capture")" = 750
test "$(stat -c %a "$prefix/lib/topgent/1.0.0-test/topgent-sensor")" = 750

"$scratch/v2/install.sh" --prefix "$prefix" >/dev/null
test "$("$prefix/bin/topgent")" = "topgent 2.0.0-test"
"$prefix/lib/topgent/rollback.sh" --prefix "$prefix" >/dev/null
test "$("$prefix/bin/topgent")" = "topgent 1.0.0-test"

"$prefix/lib/topgent/uninstall.sh" --prefix "$prefix" >/dev/null
test ! -e "$prefix/bin/topgent"
test ! -e "$prefix/bin/topgent-ui"
test ! -e "$prefix/lib/topgent"
test -f "$prefix/state/topgent/sentinel"
test -f "$prefix/config/topgent/sentinel"
echo "linux package lifecycle: install, upgrade, rollback and uninstall passed"
