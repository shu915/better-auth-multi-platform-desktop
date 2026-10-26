#!/usr/bin/env bash
# PostToolUse(Edit|Write|MultiEdit): 編集したファイルだけ検査する(ts は ESLint、rs は rustfmt)
set -u
input=$(cat)
path=$(jq -r '.tool_input.file_path // ""' <<<"$input")
[[ -f "$path" ]] || exit 0
cd "${CLAUDE_PROJECT_DIR:-$PWD}" || exit 0

if [[ "$path" =~ \.(ts|tsx|mts|mjs|js)$ ]]; then
  out=$(npx --no-install eslint --no-warn-ignored "$path" 2>&1) && exit 0
  { echo "ESLint failed: $path"; tail -n 40 <<<"$out"; } >&2
  exit 2
fi

if [[ "$path" =~ \.rs$ ]]; then
  # shellcheck disable=SC1091
  [[ -f "$HOME/.cargo/env" ]] && . "$HOME/.cargo/env"
  out=$(cargo fmt --manifest-path src-tauri/Cargo.toml -- --check 2>&1) && exit 0
  { echo "rustfmt failed (run: cargo fmt --manifest-path src-tauri/Cargo.toml): $path"; tail -n 40 <<<"$out"; } >&2
  exit 2
fi
exit 0
