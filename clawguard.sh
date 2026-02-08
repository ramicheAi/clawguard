#!/bin/bash
# Launch script for ClawGuard

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_PATH="$(which python3)"

if [ -z "$PYTHON_PATH" ]; then
    echo "❌ Python 3 not found. Please install Python 3.8 or higher."
    exit 1
fi

# Activate virtual environment if exists
VENV_PATH="$SCRIPT_DIR/.venv"
if [ -d "$VENV_PATH" ]; then
    source "$VENV_PATH/bin/activate"
fi

# Run ClawGuard
"$PYTHON_PATH" -m clawguard.cli "$@"