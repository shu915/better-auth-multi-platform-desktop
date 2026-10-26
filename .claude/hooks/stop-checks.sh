#!/usr/bin/env bash
# Stop: 応答終了時に tsc / lint / test / clippy / cargo test を実行。失敗したら Claude に差し戻す(exit 2)
set -u
input=$(cat)
active=$(jq -r '.stop_hook_active // false' <<<"$input")
cd "${CLAUDE_PROJECT_DIR:-$PWD}" || exit 0
git rev-parse --git-dir >/dev/null 2>&1 || exit 0
# shellcheck disable=SC1091
[[ -f "$HOME/.cargo/env" ]] && . "$HOME/.cargo/env"

# 前回成功時から変更がなければスキップ
state="$(git rev-parse --git-dir)/claude-stop-check"
hash=$({ git status --porcelain; git diff HEAD; git ls-files -o --exclude-standard | xargs shasum 2>/dev/null; } | shasum | cut -d' ' -f1)
[[ -f "$state" && "$(cat "$state")" == "$hash" ]] && exit 0

fails=""
run() { # run <name> <cmd...>
  local name=$1; shift
  local out
  if ! out=$("$@" 2>&1); then
    fails+="### $name failed ($*)"$'\n'"$(tail -n 50 <<<"$out")"$'\n\n'
  fi
}

run tsc npx --no-install tsc --noEmit
run lint npm run lint --silent
run test npm test --silent
# Rust は src-tauri があるときだけ。初回はビルドに数分かかる
if [[ -f src-tauri/Cargo.toml ]] && command -v cargo >/dev/null 2>&1; then
  run fmt cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
  run clippy cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
  run cargo-test cargo test --manifest-path src-tauri/Cargo.toml
fi

if [[ -z "$fails" ]]; then
  echo "$hash" >"$state"
  exit 0
fi
if [[ "$active" == "true" ]]; then
  # 差し戻し後もまだ失敗: ループを止めてユーザーに警告だけ出す
  jq -n --arg m "Stop hook: 差し戻し後も検証が失敗しています。人の確認が必要です。" '{systemMessage:$m}'
  exit 0
fi
{ echo "静的チェックが失敗しました。直してください(テストや設定を弱めて通さない)。"; echo; echo "$fails"; } >&2
exit 2
