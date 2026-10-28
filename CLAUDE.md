# better-auth-multi-platform-desktop

## 概要
Next.js と Better Auth、Go で認証を実装する。これはデスクトップ(Tauri)のクライアント。Web(`better-auth-multi-platform-web`)と Go API(`better-auth-multi-platform-api`)、モバイル(`better-auth-multi-platform-mobile`)は別リポジトリ。
- 認証は Web の Better Auth が担当する。デスクトップは Better Auth でログインし、JWT を取って Go を直接呼ぶ(Go は変えずに済む)
- ログインはマジックリンクが必須。Google などの OAuth は、ログイン済みのユーザーが後から足す任意の手段。パスワードは使わない
- 流れ(予定。モバイルと同じ): マジックリンクのメール → deep link でアプリに戻る(`betterauthmulti://`)→ 1 回限りの `code` + PKCE で `/api/mobile/exchange` に引き換えてセッションを得る → Keychain に保存 → `GET /api/auth/token` に Bearer で JWT をもらう → Go を呼ぶ
- Web 側のルール(Bearer は `/token` だけで受け付ける、`/api/mobile/*` の認証、など)は、Web の `docs/design.md` が正。モバイルの実装(`mobile/src/lib/sign-in-*.ts`)が手本
- 配布は自分の Mac だけ。署名・公証・ストアはやらない

## 使用技術
Tauri 2(Rust)/ React 19 / TypeScript / Vite 8 / Vitest 5 / ESLint 9

## 構成と責務
- `src/`: 画面(React)。**画面だけ**。トークン・Cookie・JWT を JS に持たせない
- `src-tauri/src/`: Rust。**セキュリティの判断はここ**(state、PKCE、deep link の URL 検証、Keychain、Go と Web への HTTP)。判断は純粋な関数に分けて `cargo test` で試す(モバイルの `*-rules.ts` に当たる)。`#[tauri::command]` は薄く保つ
- `src-tauri/tauri.conf.json`: CSP(`default-src 'self'`)と設定。`src-tauri/capabilities/`: WebView に渡す権限。必要最小限にする
- `src-tauri/gen/` は生成物。手で編集しない

## 守るルール(特に壊しやすいもの)
- **秘密は Keychain にだけ置く**。セッション、JWT、`verifier` を、ファイル・ログ・`localStorage`・URL・JS に出さない。`VITE_` 付きの環境変数は WebView から読めるので、秘密を入れない
- **Tauri の権限を広げない**: CSP を外さない、`capabilities/` に `shell` / `fs` / `http` / `process` の権限や remote を足さない(必要なら Rust のコマンドに閉じる)、`dangerous*` と `withGlobalTauri` を使わない。WebView に外部のページを読ませない(ログインは**システムのブラウザ**で行う)
- **deep link は信用しない**: 自分が始めたログインの `state` に合うものだけ受ける。独自スキームは他のアプリも登録できるので、セッションは URL に載せず、1 回限りのコード + PKCE で引き換える
- アプリのスキーム(`betterauthmulti`)は、`tauri.conf.json` の deep-link 設定、Web の `trustedOrigins`、Rust の定数で同じにする
- Rust は `Result` で返し、`unwrap` / `expect` / 添字で落とさない(テストは除く)。警告は直す(`#[allow]` を足さない)。`unsafe` は使わない
- **Google の戻りは、ループバックの受け口で受ける**(`loopback.rs`、RFC 8252): 独自スキームだと、ブラウザが「アプリを開きますか?」を出し、繰り返すと出なくなるため。`127.0.0.1` の空きポートで、ログインごとに 1 つ、1 回だけ受けて閉じる(10 分)。`127.0.0.1` だけで待ち受ける、`Host` が自分のアドレスとポートでなければ断る、入力を返さない固定のページを返す。受けた内容は信用せず、`state` の突き合わせと PKCE は、deep link と同じ処理(`accept_sign_in_link`)が行う。メールのリンクは、アプリが閉じていても起動できる deep link のまま
- macOS では deep link のスキームは**ビルドした `.app` を入れたとき**に登録される。`tauri dev` では届かないことがある

## コマンド
- `npm run tauri dev`: 開発起動(Vite + Rust のビルド。初回は数分)
- `npm run tauri build`: `.app` を作る。**署名を付けて作る**(下の「署名」)。署名なしだと、ビルドごとに Keychain の許可を聞かれる
- `npm run lint` / `npx tsc --noEmit` / `npm test`(Vitest。`src/**/*.test.ts`。ロジックだけ、画面は試さない)
- `cargo fmt --manifest-path src-tauri/Cargo.toml -- --check` / `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` / `cargo test --manifest-path src-tauri/Cargo.toml`
- Rust は `~/.cargo/env` で PATH に入る(hooks も読み込む)
- `better-auth` を足したら Web と同じ版に固定する(`^` なし)。上げるときは Web と同時に。`@tauri-apps/*`(npm)と `tauri*`(cargo)は一緒に上げる(IPC が壊れる)
- 依存を足したあと、`package-lock.json` の `@rolldown/binding-*`(Linux 用を含む)が消えていないか確認する(`grep -c '"node_modules/@rolldown/binding-' package-lock.json` が 0 でないこと)。確認は `npm ci --dry-run`

## 署名(macOS。自分の Mac 専用)
- 目的: Keychain の許可を、ビルドし直しても聞かれないようにする。macOS は許可を、アプリの**署名の身元**と結びつけて覚える。署名なしは、ビルドごとに別のアプリに見えるので、毎回聞かれる。同じ証明書で署名し続ければ、最初の 1 回だけ(署名のとき、codesign が鍵の使用を聞くので「常に許可」)
- 証明書: 無料の **Apple Development** 証明書(Xcode の Settings → Accounts → Manage Certificates → + で作る。有料のアカウントは要らない)。確認: `security find-identity -v -p codesigning` が 1 件出ること
- 0 件のときは、キーチェーンのリセットなどで、**Apple の中間証明書(Worldwide Developer Relations - G3)**が消えている。https://www.apple.com/certificateauthority/ から入れ直す(ログインキーチェーンに追加)。`security find-certificate -c "Apple Development" -p | openssl x509 -noout -issuer` で、必要な世代(G3 など)が分かる
- ビルド: 証明書の名前は、**環境変数で渡し、リポジトリには書かない**(`tauri.conf.json` に書かない)。空のまま進むと、署名なしにフォールバックして、見た目は成功のまま、許可が毎回出る状態に戻る(推測。未確認)ので、**空なら止める**。`Apple Development` が複数あるとき(期限切れ、別のチーム)は、先頭を選んでしまうので、`IDENTITY` を手で指定する
  ```
  IDENTITY=$(security find-identity -v -p codesigning | sed -n 's/.*"\(Apple Development:[^"]*\)".*/\1/p' | head -1)
  [ -n "$IDENTITY" ] || { echo "署名用の証明書がない" >&2; exit 1; }
  APPLE_SIGNING_IDENTITY="$IDENTITY" npm run tauri build -- --debug --bundles app
  codesign --verify --deep --strict "src-tauri/target/debug/bundle/macos/Auth Practice.app" && echo "署名OK"
  ```
- 確認: `codesign -dv --verbose=2 "src-tauri/target/debug/bundle/macos/Auth Practice.app"` に `TeamIdentifier` が出る。`codesign --verify --deep --strict` が通る
- 期限: 無料の Apple Development 証明書は **1 年**で切れる(今の証明書は 2027 年 10 月 27 日)。切れると、署名もビルドも止まる。更新すると、署名の指定要件(証明書の名前)が変わりうる。変わったら、Keychain の許可を、もう一度聞かれる(セッションは消えない)
- 限界: Apple Development 証明書は、自分の Mac でだけ通る。**他の Mac には配れない**(Gatekeeper が止める)。配るには、有料の Developer ID と公証が要る。このプロジェクトは配布しない
- `betterauthmulti://` は、同じ Mac の別のアプリ(モバイルのシミュレーターのアプリ、`target/` の `.app`)にも登録されていることがある。メールのリンクを押しても、画面が変わらないときは、リンクが別のアプリに渡った可能性がある。`/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -B3 -A3 betterauthmulti` で調べ、不要なものは `lsregister -u <.app のパス>` で外す。手動で試すときは、`/Applications` の `.app` だけを残す
- Claude の実行環境からは、ログインキーチェーンが見えないことがある(`find-identity` が 0 件になる)。署名付きのビルドは、人が自分のターミナルで実行する。署名が付いたかの確認(`codesign`)は、Claude もできる

## 退会の限界(受け入れたもの)
- `delete_account` は、画面の操作があったかを確かめない。確認のメールは Web が照合するが、プロフィール画面がメールを表示するので、WebView の JS が侵害されると、ログイン直後の数分は、操作なしで退会できる。完全に止めるには Rust からネイティブの確認ダイアログを出す必要がある(依存と権限が増える)。配布が自分の Mac だけなので、受け入れる
- Keychain の削除に失敗しても `Deleted` を返す(退会は済んでいる)。無効なセッションは、次の 401 で消える
- 20 秒でタイムアウトしても Web の処理は続く。次の試行が 401 なら、画面は「前回の退会が完了していた可能性」と伝える

## 型の方針
- TypeScript は `strict: true`。`any` は使わない
- 型は書くか推論に任せる。黙らせる回避は使わない: `as unknown as X`、`@ts-ignore`、`@ts-expect-error`、`eslint-disable`
- 外部から来るデータ(Go と Web のレスポンス、deep link の URL、`invoke` の戻り値)は `unknown` で受け、検証してから型を付ける
- どうしても回避が要るときは、理由を 1 行のコメントで書く

## 実装後の流れ(生成と評価のループ)
実装は自分、評価は `evaluator` エージェント(`.claude/agents/evaluator.md`)。
1. 実装する。lint・`tsc`・Vitest・`cargo fmt`・`clippy`・`cargo test` は hooks(`.claude/settings.json`)が自動で実行する(編集ごとに ESLint か rustfmt、応答終了時に全部)。失敗したら差し戻されるので直す。`vite build` は hooks の対象外
2. 挙動を変える変更のときは `evaluator` を呼ぶ(ドキュメントやコメントだけの変更では呼ばない)
3. 「要修正」なら「高」「中」の指摘を直して 2 に戻る。最大 5 周で打ち切る
4. 「合格」で終了し、結果を報告する。5 周で合格しなければ、止めて残りの指摘をそのまま報告する(無理に通さない)。同じ指摘が再発したら、上限を待たずに止める
5. 報告には、検証していない範囲と、人間向けの確認手順を必ず書く。人間の返事は待たない
   - `tauri dev`、`.app` のビルドと deep link の登録、Keychain、ブラウザからアプリへの戻りは、このループでは確認できない。画面や deep link を変えたら、必ず未検証として残す
   - 画面のテストはない(ロジックは `npm test` と `cargo test`)

人間の確認(デスクトップでの動作、最終レビュー)はループの外。人間が問題を見つけたら、その内容を新しい goal として回す。goal を書くときは、完了条件(機械で確認できるもの)と、ループの外(人間の作業)を分ける。

### テストを通すための改ざんは禁止
やむを得ず変えるときは、理由を報告に書き、人間の確認を待つ。
- 失敗するテストの削除、`skip` / `only` / `#[ignore]` の追加、`exclude` で外すこと
- 期待値を実装の出力に合わせて弱めること(仕様が変わった場合を除く)
- 型や lint を黙らせる回避を足すこと(`#[allow]` も含む)、tsconfig・ESLint・`[lints]`・clippy の設定を緩めること
- 上限値、タイムアウト、許可リストなどを、通るように緩めること
- `evaluator` の指摘を、直さずにコメントや設定で黙らせること

テストが落ちたら、まず実装が間違っていると考える。テストの側が間違っていると判断するときも、根拠を書く。

## コミットと hooks
- 人が頼むまでコミットしない(未コミットで残し、先に読んでもらう)。push は hook が止めるので人が実行する。`.github/workflows/` の編集は hook では止めない。CI を緩める変更(チェックの削除、など)は改ざんとして扱う
- `main` は GitHub のルールセット `protect-main` で守られている(直接 push 不可、PR 必須、CI の `check` が必須、強制 push と削除は不可)。ブランチを切って PR で入れる
- CI(`.github/workflows/ci.yml`)は、lint、`tsc --noEmit`、Vitest、`vite build`、`cargo fmt --check`、`clippy -D warnings`、`cargo test` を実行する。macOS の `.app` のビルド、deep link の登録、Keychain、実際の動作は CI も見ない
- `.env` 系のファイルは読まない
- PreToolUse でブロック(`.claude/hooks/guard-pre.sh`): `.env` 系の読み取り(`.env.example` は可)、`git push/clean/reset --hard`、`rm -r`(`node_modules`・`dist`・`coverage`・`tmp`・`src-tauri/target` だけ許可。`..`・絶対パス・ワイルドカード・それ以外は不可)、`cargo publish`、`src-tauri/gen/`・`Cargo.lock`・`package-lock.json` の編集、`@ts-ignore` / `eslint-disable` / `as unknown as` / `any` / `#[allow]` / `#[ignore]` / `unsafe` の追加、テストや設定への `skip` / `only` / `strict:false` / ルール `off` / `exclude`、`tauri.conf.json` の CSP 外しと `dangerous*`、`capabilities/` への `shell` / `fs` / `http` / `process` / remote の追加
- ブロックされたら回避せず、理由を報告して人の指示を待つ

## 進捗ファイル
- `claude-progress.txt` に、完了・実行中・これからのタスクを書く。新しいセッションは、最初にこのファイルと CLAUDE.md を読む
- 区切りのたびに、終了時の報告と一緒に更新する
