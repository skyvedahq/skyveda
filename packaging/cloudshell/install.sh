#!/usr/bin/env bash
# Install Skyveda Scan into Azure Cloud Shell (or any Linux shell) from the bundled wheel.
#
#   unzip skyveda-cloudshell-*.zip && bash skyveda-cloudshell/install.sh
#
# Installs into ~/.skyveda (persists in Cloud Shell's home) and links ~/.local/bin/skyveda.
# Needs no admin rights and changes nothing in Azure.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
wheel="$(ls "$here"/skyveda-*.whl | sort -V | tail -n 1)"
venv="$HOME/.skyveda"
bin="$HOME/.local/bin"

if python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))' 2>/dev/null; then
    rm -rf "$venv"
    python3 -m venv "$venv"
    "$venv/bin/python" -m pip install --quiet --upgrade pip
    "$venv/bin/python" -m pip install --quiet "${wheel}[azure]"
else
    # Python here is older than 3.12: uv fetches a private Python 3.12 into the home directory.
    if ! command -v uv >/dev/null 2>&1; then
        curl -LsSf https://astral.sh/uv/install.sh | sh
        export PATH="$bin:$PATH"
    fi
    rm -rf "$venv"
    uv venv --quiet --python 3.12 "$venv"
    uv pip install --quiet --python "$venv/bin/python" "${wheel}[azure]"
fi

mkdir -p "$bin"
ln -sf "$venv/bin/skyveda" "$bin/skyveda"
case ":$PATH:" in
    *":$bin:"*) ;;
    *) echo "export PATH=\"$bin:\$PATH\"" >> "$HOME/.bashrc"; export PATH="$bin:$PATH" ;;
esac

"$bin/skyveda" --version
"$bin/skyveda" validate-checks
cat <<'EOF'

Installed. Next:
  skyveda scopes                      # subscriptions you can read
  skyveda scan --out ~/skyveda-out --pdf   # writes findings.json, report.html and report.pdf

Download ~/skyveda-out/report.pdf with Cloud Shell's "Manage files > Download".
If 'skyveda' is not found, open a new Cloud Shell tab or run: source ~/.bashrc
EOF
