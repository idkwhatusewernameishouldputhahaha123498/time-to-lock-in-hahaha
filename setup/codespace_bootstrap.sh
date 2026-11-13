#!/usr/bin/env bash
# codespace_bootstrap.sh - one-time setup for the GitHub Codespace workbench.
#
# Why: a Codespace is a full Linux machine driven from a browser tab, so it needs nothing
# installed on a locked-down PC. With Claude Code inside it you get the same agent + plugin as
# on a laptop; challenge files go in by dragging them into the Explorer's challenges/ folder.
#
# Runs automatically after the Codespace is created (see .devcontainer/devcontainer.json).
# Safe to re-run by hand:  bash setup/codespace_bootstrap.sh

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
REPO="$PWD"

echo "== 1/3 CTF tools (apt + pip; takes a few minutes) =="
bash setup/cloud_env_setup.sh

echo "== 2/3 challenges/ drop folder (git-ignored) =="
mkdir -p challenges

echo "== 3/3 flag-hunters plugin =="
if command -v claude >/dev/null 2>&1; then
  claude plugin marketplace add "$REPO" || echo "   (marketplace add failed - run it by hand after 'claude' login)"
  claude plugin install flag-hunters@flag-hunters-arsenal || echo "   (plugin install failed - run it by hand after 'claude' login)"
else
  echo "   claude not on PATH yet - open a new terminal, then run:"
  echo "     claude plugin marketplace add $REPO && claude plugin install flag-hunters@flag-hunters-arsenal"
fi

echo
echo "Ready. Next: run 'claude' in this terminal and sign in (copy the URL, paste the code back)."
echo "Drop challenge files into: $REPO/challenges/"
