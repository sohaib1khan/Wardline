#!/usr/bin/env bash
# Install Wardline as the `wardline` command (Debian / RHEL / Arch / any Linux).
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/sohaib1khan/Wardline/main/scripts/install.sh | bash
#   ./scripts/install.sh
#   ./scripts/install.sh --system   # also symlink into /usr/local/bin (needs sudo)
set -euo pipefail

REPO_GIT="${WARDLINE_REPO_GIT:-https://github.com/sohaib1khan/Wardline.git}"
SYSTEM=0
for arg in "$@"; do
  case "$arg" in
    --system|-s) SYSTEM=1 ;;
    --help|-h)
      echo "Usage: $0 [--system]"
      echo "  Installs Wardline with uv into ~/.local/bin/wardline"
      echo "  --system  also creates /usr/local/bin/wardline (sudo)"
      exit 0
      ;;
  esac
done

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Wardline targets Linux. Detected: $(uname -s)" >&2
  exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "==> Installing uv (Python toolchain)…"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  # shellcheck disable=SC1091
  [[ -f "$HOME/.local/bin/env" ]] && source "$HOME/.local/bin/env"
  export PATH="$HOME/.local/bin:$PATH"
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "uv not found on PATH after install. Add ~/.local/bin to PATH and re-run." >&2
  exit 1
fi

echo "==> Installing Wardline from ${REPO_GIT}…"
uv tool install --force "git+${REPO_GIT}"

BIN_DIR="${HOME}/.local/bin"
WARD="${BIN_DIR}/wardline"
if [[ ! -x "$WARD" ]]; then
  # uv may place tools under UV_TOOL_BIN_DIR
  WARD="$(command -v wardline || true)"
fi
if [[ -z "${WARD}" || ! -x "${WARD}" ]]; then
  echo "Install finished but 'wardline' was not found on PATH." >&2
  echo "Ensure ${BIN_DIR} is on your PATH, then open a new shell." >&2
  exit 1
fi

echo "==> wardline is at: ${WARD}"
"${WARD}" --version

if [[ "$SYSTEM" -eq 1 ]]; then
  echo "==> Linking into /usr/local/bin/wardline (system-wide)…"
  sudo ln -sfn "${WARD}" /usr/local/bin/wardline
  sudo chmod 755 /usr/local/bin/wardline || true
  echo "System command: /usr/local/bin/wardline"
fi

# PATH hint for interactive shells
case ":${PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *)
    echo
    echo "Add this to your shell profile (~/.bashrc / ~/.zshrc) if 'wardline' is not found:"
    echo "  export PATH=\"${BIN_DIR}:\$PATH\""
    ;;
esac

echo
echo "Next:"
echo "  wardline guide"
echo "  wardline init"
echo "  wardline doctor"
echo "  wardline"
