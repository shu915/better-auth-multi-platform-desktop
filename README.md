# better-auth-multi-platform (desktop)

ひとつのログインを、複数のクライアントで共有するためのサンプルの、デスクトップ(Tauri、macOS)側
です。Web アプリ([Better Auth](https://www.better-auth.com))でログインし、そのトークンで Go API を
**直接**呼びます。Web、モバイルと並ぶ、3 つのクライアントの 1 つです。

**React は画面だけ。** セッション、PKCE、Keychain、Web と Go への通信など、セキュリティに関わる判断は、
すべて Rust にあります。画面には、トークンも Cookie も渡りません。

## 4 つのリポジトリ

| リポジトリ | 役割 |
|---|---|
| [better-auth-multi-platform-web](https://github.com/shu915/better-auth-multi-platform-web) | Next.js。Better Auth でログインを担当し、JWT を発行する。ブラウザの UI。 |
| [better-auth-multi-platform-api](https://github.com/shu915/better-auth-multi-platform-api) | Go の API。JWT を検証して、プロフィール(bio)を読み書きする。 |
| [better-auth-multi-platform-mobile](https://github.com/shu915/better-auth-multi-platform-mobile) | Expo(iOS と Android)のクライアント。 |
| **better-auth-multi-platform-desktop**(これ) | Tauri(macOS)のクライアント。 |

## できること

- **メールのログイン**(マジックリンク)とログアウト。パスワードは使いません。
- **プロフィール**の閲覧と編集(名前は Web、bio は Go)。
- **退会**(確認のメールアドレスの入力が要る。直近 5 分以内のログインが必要)。
- **Google の連携と解除**と、**Google でログイン**(連携済みのユーザーだけ。新規登録はできません)。

## 全体像

```
React (画面だけ)
   │ invoke(コマンド)     ← 返るのは「種類」だけ。秘密は渡らない
   ▼
Rust ── Keychain(セッション、PKCE の verifier)
   │
   ├──▶ Web (Next.js)  : ログイン、JWT、プロフィールの名前、退会、Google の連携
   └──▶ Go API         : bio の読み書き(Web でもらった JWT を Bearer で)
```

**ログインの戻り方は、2 通りです。**

| 方法 | 戻り方 |
|---|---|
| メールのリンク | ブラウザで開くと、ディープリンク(`betterauthmulti://`)でアプリに戻る。アプリが閉じていても起動できる。 |
| Google | アプリが `127.0.0.1` の空きポートで、一時的な受け口を開き、ブラウザがそこへ戻る(RFC 8252 のループバック)。ブラウザの「アプリを開きますか?」のポップアップに頼らない。 |

どちらも、セッションを URL に載せません。戻りのリンクには、1 回限りの**コード**(60 秒)だけを載せ、
アプリが PKCE の verifier を添えて、セッションに引き換えます(`POST /api/mobile/exchange`)。受け取ったセッションは
Keychain にだけ置き、Go を呼ぶときは `GET /api/auth/token` で JWT(5 分)をもらいます。

- 自分が頼んだログインの `state` に合う戻りだけ受けます。受け口は、127.0.0.1 だけで待ち、`Host` を
  確かめ、待っている目印を含む戻りだけを、1 回だけ採用します(`src-tauri/src/loopback.rs`)。
- 認証のルールと、受け入れた限界は、Web の `docs/design.md` が正です。

## 構成

| 場所 | 内容 |
|---|---|
| `src/` | 画面(React)。結果を検査して見せるだけ(`src/lib/*-outcomes.ts`)。 |
| `src-tauri/src/sign_in_rules.rs` | `state`、PKCE、保留中の要求、戻りのリンクの検証(純粋な関数)。 |
| `src-tauri/src/auth.rs` | ログイン、ログアウト、コードの引き換え、Keychain への保存。 |
| `src-tauri/src/profile.rs`、`profile_rules.rs` | プロフィールの読み書き(Web と Go の 2 系統)と、入力の検証。 |
| `src-tauri/src/account.rs` | 退会。 |
| `src-tauri/src/google.rs`、`link_rules.rs` | Google の連携、解除、ログイン。 |
| `src-tauri/src/loopback.rs` | ブラウザの戻りを受ける、一時的な受け口。 |
| `src-tauri/src/secret.rs` | Keychain(macOS)。画面に Keychain を触るコマンドは公開しない。 |
| `src-tauri/src/config.rs` | 接続先の URL(ビルド時に埋め込む)。 |

## 技術スタック

| 分類 | 技術 | バージョン |
|---|---|---|
| アプリ | Tauri | 2 |
| バックエンド | Rust | edition 2024 |
| 画面 | React / TypeScript / Vite | 19 / 6.0 / 8 |
| HTTP | reqwest(rustls。リダイレクトを追わない) | 0.13 |
| 保管 | keyring(macOS の Keychain) | 4 |
| 暗号 | sha2、base64、getrandom | - |
| ディープリンク | tauri-plugin-deep-link | 2.6 |
| テスト | `cargo test`、Vitest | -、5 |
| Lint | clippy(`-D warnings`)、ESLint | -、9 |
| 連携先 | Web(Next.js)、Go API(別リポジトリ) | - |

依存は最小限です。ブラウザを開くのは macOS の `open`、受け口は標準ライブラリだけで書いています。
WebView に渡す権限は、イベントの購読(`listen`)だけで、CSP は厳しく(`default-src 'self'`)しています。

## 手元で動かす

必要なもの: Node.js、Rust、動いている Web と Go API(それぞれのリポジトリを参照)。

```bash
npm ci
npm run tauri dev        # Vite と Rust をビルドして起動(初回は数分)
```

接続先の既定は、Web が `http://localhost:3000`、Go が `http://localhost:8080` です。

**`tauri dev` の限界:** 署名のないバイナリなので、ビルドのたびに Keychain の許可を聞かれます。
メールのリンク(ディープリンク)も、ビルドした `.app` を入れたときだけ届きます。ログインや退会の確認は、
署名つきの `.app` で行ってください。

### 署名つきの `.app`

Keychain の許可は、アプリの**署名の身元**と結びついています。署名なしは、ビルドごとに別のアプリに見える
ので、毎回聞かれます。同じ証明書で署名し続ければ、最初の 1 回だけです。

証明書は、無料の Apple Development 証明書(Xcode の Settings → Accounts → Manage Certificates)です。

```bash
IDENTITY=$(security find-identity -v -p codesigning | sed -n 's/.*"\(Apple Development:[^"]*\)".*/\1/p' | head -1)
[ -n "$IDENTITY" ] || { echo "署名用の証明書がない" >&2; exit 1; }
APPLE_SIGNING_IDENTITY="$IDENTITY" npm run tauri build -- --debug --bundles app
ditto "src-tauri/target/debug/bundle/macos/Auth Practice.app" "/Applications/Auth Practice.app"
open "/Applications/Auth Practice.app"
```

ディープリンクは、`/Applications` に入れた `.app` に届きます。`ditto` を使うのは、署名を保つためです。

### 本番に接続する

接続先は、ビルド時に埋め込みます(実行時には読みません)。リリースビルドは、**https の URL でなければ
ビルドできません**。リリースビルドは、診断のログを何も出しません。

```bash
AUTH_WEB_URL=https://<本番の Web> AUTH_API_URL=https://<本番の Go> \
APPLE_SIGNING_IDENTITY="$IDENTITY" npm run tauri build -- --bundles app
```

本番の DB は別なので、ユーザーは新しく登録し、Google も連携し直します。Render の無料プランは、
スリープ明けの最初の応答が遅くなります。

## コマンド

| コマンド | 内容 |
|---|---|
| `npm run tauri dev` / `build` | 開発起動、`.app` の作成。 |
| `npm run lint` / `npx tsc --noEmit` | ESLint、型チェック。 |
| `npm test` | Vitest(画面側の判断。画面そのものは試さない)。 |
| `cargo fmt --manifest-path src-tauri/Cargo.toml -- --check` | 整形の確認。 |
| `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` | 静的解析(警告はエラー)。 |
| `cargo test --manifest-path src-tauri/Cargo.toml` | Rust のテスト。 |

## テスト

- **Rust**: 判断は純粋な関数(`*_rules.rs`)に分けて試します。通信は、ローカルの偽の Web を立てて通します
  (本物の HTTP、本物の TCP の受け口)。確認するのは、秘密が画面とログに出ないこと、失敗のときに他の
  要求やセッションを巻き込まないこと、偽のリンクや偽の戻りを拒否することです。
- **Vitest**: Rust の答えの検査と、画面に出す文言。
- 画面(コンポーネント)のテストは、入れていません。
- CI(GitHub Actions、Linux)は、型、lint、Vitest、`vite build`、`cargo fmt`、clippy、`cargo test` を行います。
  Keychain に触るテストは、メモリ上の偽物に替えています。

## 制限

- **配布は自分の Mac だけ。** 公証もストアもしません。Apple Development 証明書は、自分の Mac でしか
  通りません(他の Mac には配れません)。証明書は 1 年で切れます。
- macOS だけです(Keychain、`open`)。
- 攻撃者のプロセスが、同じ Mac で受け口のポートを待ち受け、攻撃者の `cc` を付けたログインメールを
  開かせると、コードを受けられる可能性があります(独自スキームと同じ限界)。

設計の判断など、開発者向けの詳しい記述は、`CLAUDE.md` と `claude-progress.txt` にあります。
