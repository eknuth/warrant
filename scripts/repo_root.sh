#!/bin/sh
# Print the main checkout's path for a worktree, or the checkout's own path.
#
# `make worktree` symlinks `.env` and `.linear.toml` from the main checkout, and
# a worktree started from another worktree must still point at the main
# checkout's files rather than at the calling worktree's. `git rev-parse
# --git-common-dir` answers that in one call: in a worktree it is
# `<main>/.git`, and in the main checkout it is `.git`. Reading `.git` by hand
# would be the same rule without git, and this is the one place that needs it.
#
# A directory that is not a repository prints its own resolved path, so the
# Makefile target still produces something usable outside git.
set -eu

here=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
common=$(git rev-parse --git-common-dir 2>/dev/null || echo .)

case "$common" in
    /*) ;;
    *) common="$here/$common" ;;
esac

# `<main>/.git` -> `<main>`. A bare repository, where the common dir is the
# repository itself, has no working tree to take a `.env` from; print the
# checkout we were asked about and let the caller fail loudly on the symlink.
if [ "$(basename "$common")" = ".git" ]; then
    dirname "$common"
else
    printf '%s\n' "$here"
fi
