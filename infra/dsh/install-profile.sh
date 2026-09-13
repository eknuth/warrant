#!/usr/bin/env bash
# Install the Warrant dsh profiles from the copies in this directory.
#
# The live profile at $DSH_HOME/profiles/warrant is the one dsh reads, and it
# is not in version control. This script makes it reproducible from
# infra/dsh/*.patch.yml without ever recreating it: the two placeholder
# variables are substituted from the checkout and the harness home, and the
# live file is replaced wholesale. Nothing here runs
# `dsh --from-default-profile`, so the DeepSeek route, the isolated settings
# document, and the Linear MCP overlay all survive.
#
# Usage: make dsh-profile   (or: bash infra/dsh/install-profile.sh)
# Honours DSH_HOME; defaults to ~/.dsh. Idempotent.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"
DSH_HOME="${DSH_HOME:-$HOME/.dsh}"

if [ ! -d "$DSH_HOME" ]; then
  echo "no harness home at $DSH_HOME: install dsh and boot it once first" >&2
  exit 1
fi

# Substitute both placeholders. LC_ALL=C keeps sed byte-oriented so a path
# with non-ASCII characters cannot trip a locale-aware match.
install_patch() {
  local src="$1" dest="$2"
  sed -e "s|__REPO_ROOT__|$REPO_ROOT|g" -e "s|__DSH_HOME__|$DSH_HOME|g" \
    "$src" > "$dest"
}

mkdir -p "$DSH_HOME/profiles/warrant" "$DSH_HOME/profiles/warrant-sdk"
mkdir -p "$DSH_HOME/profiles/warrant-headless"

# Core rows into all three profiles; the Web-only rows into `warrant` alone.
install_patch "$HERE/core.patch.yml" "$DSH_HOME/profiles/warrant/cordis.patch.yml"
cat "$HERE/web.patch.yml" >> "$DSH_HOME/profiles/warrant/cordis.patch.yml"
echo "installed $DSH_HOME/profiles/warrant/cordis.patch.yml (core + web)"

install_patch "$HERE/core.patch.yml" \
  "$DSH_HOME/profiles/warrant-headless/cordis.patch.yml"
echo "installed $DSH_HOME/profiles/warrant-headless/cordis.patch.yml"

# The SDK profile is created here, not by --from-default-profile: the sdk-app
# bundle ships inside the dsh package and is not published to npm, so
# `dsh plugin add` cannot install it. The manifest and the root cordis.yml are
# the two files `--from-default-profile sdk` would have written.
#
# Both are installed unconditionally. `cp -n` would leave the destination as it
# is, which is what "reproducible from the repository" is supposed to overrule.
cp "$HERE/warrant-sdk.package.json" "$DSH_HOME/profiles/warrant-sdk/package.json"
cat > "$DSH_HOME/profiles/warrant-sdk/cordis.yml" <<'YAML'
# dsh profile root, an empty entry list. See infra/dsh/install-profile.sh.
[]
YAML
install_patch "$HERE/core.patch.yml" "$DSH_HOME/profiles/warrant-sdk/cordis.patch.yml"
echo "installed $DSH_HOME/profiles/warrant-sdk/{package.json,cordis.yml,cordis.patch.yml}"
