#!/usr/bin/env bash
# Regression harness entry point. Runs the self-contained Python test suite.
# Usage:  bash tests/run_tests.sh
exec python3 -I "$(dirname "$0")/run_tests.py" "$@"
