#!/bin/bash
set -e

INSTALL_DIR="/usr/local/bin"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "installing argus..."

# symlink so updates to the repo are picked up automatically
sudo ln -sf "$SCRIPT_DIR/argus.py" "$INSTALL_DIR/argus.py"
sudo ln -sf "$SCRIPT_DIR/argus" "$INSTALL_DIR/argus"
sudo chmod +x "$INSTALL_DIR/argus"

echo "done. run 'argus' from anywhere (use sudo for raw socket ops)."
