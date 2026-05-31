#!/bin/bash
cd "$(dirname "$0")"
export PYTHONPATH="$(pwd)/src:$PYTHONPATH"
uv run python -m testapp.app

