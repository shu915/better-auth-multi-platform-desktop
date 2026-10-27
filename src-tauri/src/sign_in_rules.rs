//! マジックリンクのログインで、リンクを受け入れるかどうかの規則。
//!
//! 通信にも Keychain にも触らない純粋な関数だけを置く(`cargo test` で単独に試せる)。
//! pending(自分が始めたログインの一覧)の読み書きは別のモジュールが担当し、ここは判断だけをする。
//! モバイルの `sign-in-rules.ts` に当たる。ログイン CSRF を防ぐ唯一の砦なので、変えたら必ずテストを足す。

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

/// アプリのスキーム。`tauri.conf.json` の deep-link 設定と、Web の `trustedOrigins`
/// (`betterauthmulti://`)で同じにする。
pub const APP_SCHEME: &str = "betterauthmulti";

/// Web のマジックリンクの有効期間(既定 5 分)より少し長くする。
pub const PENDING_MAX_AGE_MS: u64 = 10 * 60 * 1000;

/// 同時に開いておく要求の数。同じ宛先に再送しても Web はメールを送らないことがあり(宛先を探られない
/// ため同じ応答を返す)、受信箱にある古いメールが、「送る」を押し直しても使えなければならない。
pub const MAX_PENDING: usize = 3;

/// 自分が始めたログインの 1 件。`verifier` は PKCE の秘密で、Web には、そのハッシュ(challenge)しか
/// 渡さない。リンクから `code` を盗まれても、`verifier` がなければ使えない。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub state: String,
    pub verifier: String,
    pub created_at: u64,
}

/// RFC 7636: verifier は、使える文字(英数字と `-._~`)の 43〜128 文字。ここでは 32 バイトの乱数を
/// base64url にした 43 文字。
pub fn is_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// 32 バイトの乱数から verifier を作る(padding なしの base64url、43 文字)。乱数は呼び出し側が用意する。
/// 長さを型で固定して、短い乱数で作った verifier が保存後に捨てられる(`is_verifier` を通らない)ことを防ぐ。
pub fn verifier_from_bytes(bytes: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// verifier の SHA-256 を base64url(padding なし)にしたもの(PKCE の challenge)。Web は、
/// 引き換えのときに `verifier` から同じ値を作って突き合わせる。
pub fn challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// 16 バイトの乱数から state を作る(16 進の 32 文字。URL にそのまま載せられる)。空の state は
/// `judge_link` に無視されるので、長さを型で固定する。
pub fn state_from_bytes(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 保存された pending の一覧(JSON)を読む。壊れていたり、形の違う項目は捨てる。
pub fn parse_pending_list(raw: Option<&str>) -> Vec<Pending> {
    let Some(raw) = raw else { return Vec::new() };
    let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    items
        .into_iter()
        .filter_map(|item| serde_json::from_value::<Pending>(item).ok())
        .filter(|p| !p.state.is_empty() && is_verifier(&p.verifier))
        .collect()
}

fn prune(list: &[Pending], now: u64) -> Vec<Pending> {
    list.iter()
        .filter(|p| now.saturating_sub(p.created_at) <= PENDING_MAX_AGE_MS)
        .cloned()
        .collect()
}

/// 新しい要求を足す。期限の切れたものは捨て、新しい方から `MAX_PENDING` 件だけ残す。
pub fn add_pending(list: &[Pending], state: &str, verifier: &str, now: u64) -> Vec<Pending> {
    let mut open = prune(list, now);
    open.push(Pending {
        state: state.to_string(),
        verifier: verifier.to_string(),
        created_at: now,
    });
    let excess = open.len().saturating_sub(MAX_PENDING);
    open.split_off(excess)
}

/// Web に断られた要求(その state のメールは存在しない)を、その 1 件だけ消す。
pub fn remove_pending(list: &[Pending], state: &str) -> Vec<Pending> {
    list.iter().filter(|p| p.state != state).cloned().collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NoRequest,
    Expired,
    Mismatch,
}

impl Refusal {
    pub fn message(self) -> &'static str {
        match self {
            Refusal::NoRequest => "no sign-in was requested from this app",
            Refusal::Expired => "the request has expired",
            Refusal::Mismatch => "state does not match",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Consumed {
    /// `state` は自分のものだった。`rest` からは消えている(同じリンクを使い回せない)。
    Accepted {
        rest: Vec<Pending>,
        pending: Pending,
    },
    Refused {
        reason: Refusal,
        rest: Vec<Pending>,
    },
}

/// リンクは `state` を付けて戻ってくる。開いている要求の state と一致するときだけ受け入れ、その要求は
/// 使い切る。自分のものでない state は、期限切れの掃除以外は何も変えない(他人のリンクで、進行中の
/// ログインを取り消せないようにする)。
pub fn consume_pending(list: &[Pending], state: &str, now: u64) -> Consumed {
    let open = prune(list, now);
    if let Some(index) = open.iter().position(|p| p.state == state) {
        let mut rest = open;
        let pending = rest.remove(index);
        return Consumed::Accepted { rest, pending };
    }
    let reason = if list.is_empty() {
        Refusal::NoRequest
    } else if open.is_empty() {
        Refusal::Expired
    } else {
        Refusal::Mismatch
    };
    Consumed::Refused { reason, rest: open }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LinkVerdict {
    /// ログインのリンクではない。何もしない。
    Ignored,
    Rejected(&'static str),
    /// 試す価値がある。`state` を pending と突き合わせてから、`code` を引き換える。
    Code {
        code: String,
        state: String,
    },
}

enum Param {
    Absent,
    One(String),
    Many,
}

fn param(url: &Url, key: &str) -> Param {
    let mut values = url.query_pairs().filter(|(k, _)| k == key);
    match (values.next(), values.next()) {
        (None, _) => Param::Absent,
        (Some((_, v)), None) => Param::One(v.into_owned()),
        (Some(_), Some(_)) => Param::Many,
    }
}

/// アプリを開いたリンクを、保存先にも通信にも触れる前に判断する。順番は意味があり、テストしている。
///  0. `state` のないリンクは、ログインのためのものではない: 無視する(他のリンクで「失敗」を出さない)。
///  1. セッション(`cookie`)の入ったリンクは断る。セッションをリンクから受け取ることはしない。
///  2. `error` の付いたリンクは断る(Web がログインを断った)。
///  3. `code` のないリンクは、ログインのリンクではない: 無視する。
///  4. 形が Web の送るもの(スキーム、ホストなし、パスなし)でなければ断る。
///
/// `state` の突き合わせは、ここではしない(開いている要求が要る。`consume_pending`)。
pub fn judge_link(link: &str) -> LinkVerdict {
    let Ok(url) = Url::parse(link) else {
        return LinkVerdict::Ignored;
    };
    let state = match param(&url, "state") {
        Param::One(s) if !s.is_empty() => s,
        _ => return LinkVerdict::Ignored,
    };
    if !matches!(param(&url, "cookie"), Param::Absent) {
        return LinkVerdict::Rejected("a link with a session in it is not accepted");
    }
    if !matches!(param(&url, "error"), Param::Absent) {
        return LinkVerdict::Rejected("the web app refused the link");
    }
    let code = match param(&url, "code") {
        Param::One(c) if !c.is_empty() => c,
        _ => return LinkVerdict::Ignored,
    };
    if !has_sign_in_link_shape(&url) {
        return LinkVerdict::Rejected("unexpected link shape");
    }
    LinkVerdict::Code { code, state }
}

/// 戻り先は、ちょうど `<スキーム>:///?state=…&code=…`(ホストなし、パスなし)。
fn has_sign_in_link_shape(url: &Url) -> bool {
    url.scheme() == APP_SCHEME
        && url.host_str().is_none_or(str::is_empty)
        && matches!(url.path(), "" | "/")
        && url.fragment().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 43 文字
    const V2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NOW: u64 = 1_000_000;

    fn pending(state: &str, created_at: u64) -> Pending {
        Pending {
            state: state.to_string(),
            verifier: V1.to_string(),
            created_at,
        }
    }

    // --- verifier / challenge ---

    #[test]
    fn verifier_from_32_bytes_is_43_chars_and_valid() {
        let v = verifier_from_bytes(&[255u8; 32]);
        assert_eq!(v.len(), 43);
        assert!(is_verifier(&v));
        assert!(!v.contains('=') && !v.contains('+') && !v.contains('/'));
    }

    #[test]
    fn verifier_shape_is_checked() {
        assert!(is_verifier(V1));
        assert!(!is_verifier(&"a".repeat(42)));
        assert!(!is_verifier(&"a".repeat(129)));
        assert!(is_verifier(&"a".repeat(128)));
        assert!(!is_verifier(&format!("{}!", &V1[1..])));
        assert!(!is_verifier(""));
    }

    #[test]
    fn challenge_matches_the_rfc7636_example() {
        // RFC 7636 付録 B の例。
        assert_eq!(
            challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn state_is_hex_and_url_safe() {
        let mut bytes = [0u8; 16];
        bytes[1] = 15;
        bytes[2] = 255;
        assert_eq!(state_from_bytes(&bytes), "000fff00000000000000000000000000");
    }

    // --- pending の一覧 ---

    #[test]
    fn parse_pending_list_handles_garbage() {
        assert!(parse_pending_list(None).is_empty());
        assert!(parse_pending_list(Some("not json")).is_empty());
        assert!(parse_pending_list(Some("{}")).is_empty());
        assert!(parse_pending_list(Some("[1, null, \"x\", {}]")).is_empty());
    }

    #[test]
    fn parse_pending_list_keeps_valid_items_only() {
        let raw = format!(
            r#"[{{"state":"s1","verifier":"{V1}","created_at":5}},
               {{"state":"","verifier":"{V1}","created_at":5}},
               {{"state":"s3","verifier":"short","created_at":5}},
               {{"state":"s4","verifier":"{V1}","created_at":"5"}}]"#
        );
        assert_eq!(parse_pending_list(Some(&raw)), vec![pending("s1", 5)]);
    }

    #[test]
    fn pending_list_round_trips_through_json() {
        let list = vec![pending("a", 1), pending("b", 2)];
        let raw = serde_json::to_string(&list).unwrap();
        assert_eq!(parse_pending_list(Some(&raw)), list);
    }

    #[test]
    fn add_pending_drops_expired_and_keeps_the_newest_three() {
        let old = pending("old", NOW - PENDING_MAX_AGE_MS - 1);
        let list = add_pending(
            &[old, pending("a", NOW - 3), pending("b", NOW - 2)],
            "c",
            V2,
            NOW,
        );
        let states: Vec<_> = list.iter().map(|p| p.state.as_str()).collect();
        assert_eq!(states, ["a", "b", "c"]);

        let list = add_pending(&list, "d", V2, NOW);
        let states: Vec<_> = list.iter().map(|p| p.state.as_str()).collect();
        assert_eq!(states, ["b", "c", "d"]);
        assert_eq!(list.last().unwrap().verifier, V2);
    }

    #[test]
    fn remove_pending_removes_only_that_state() {
        let list = [pending("a", 1), pending("b", 2)];
        assert_eq!(remove_pending(&list, "a"), vec![pending("b", 2)]);
        assert_eq!(remove_pending(&list, "zzz").len(), 2);
    }

    // --- state の突き合わせ ---

    #[test]
    fn consume_accepts_our_state_once() {
        let list = [pending("a", NOW - 10), pending("b", NOW - 5)];
        let Consumed::Accepted { rest, pending: p } = consume_pending(&list, "a", NOW) else {
            panic!("expected Accepted");
        };
        assert_eq!(p.state, "a");
        assert_eq!(rest, vec![pending("b", NOW - 5)]);

        // 使い切ったので、同じリンクは 2 回目には通らない。
        assert!(matches!(
            consume_pending(&rest, "a", NOW),
            Consumed::Refused {
                reason: Refusal::Mismatch,
                ..
            }
        ));
    }

    #[test]
    fn consume_refuses_when_nothing_was_requested() {
        assert_eq!(
            consume_pending(&[], "a", NOW),
            Consumed::Refused {
                reason: Refusal::NoRequest,
                rest: vec![]
            }
        );
    }

    #[test]
    fn consume_refuses_an_expired_request() {
        let list = [pending("a", NOW - PENDING_MAX_AGE_MS - 1)];
        assert_eq!(
            consume_pending(&list, "a", NOW),
            Consumed::Refused {
                reason: Refusal::Expired,
                rest: vec![]
            }
        );
    }

    #[test]
    fn a_request_at_exactly_the_age_limit_is_still_open() {
        let list = [pending("a", NOW - PENDING_MAX_AGE_MS)];
        assert!(matches!(
            consume_pending(&list, "a", NOW),
            Consumed::Accepted { .. }
        ));
    }

    #[test]
    fn someone_elses_state_cancels_nothing() {
        let list = [
            pending("a", NOW - 5),
            pending("old", NOW - PENDING_MAX_AGE_MS - 1),
        ];
        let Consumed::Refused { reason, rest } = consume_pending(&list, "evil", NOW) else {
            panic!("expected Refused");
        };
        assert_eq!(reason, Refusal::Mismatch);
        // 期限切れの掃除以外は、進行中の要求をそのまま残す。
        assert_eq!(rest, vec![pending("a", NOW - 5)]);
    }

    // --- リンクの判断 ---

    fn code(c: &str, s: &str) -> LinkVerdict {
        LinkVerdict::Code {
            code: c.to_string(),
            state: s.to_string(),
        }
    }

    #[test]
    fn a_proper_link_is_worth_trying() {
        assert_eq!(
            judge_link("betterauthmulti:///?state=s&code=c"),
            code("c", "s")
        );
        // パスが "/" だけの形も、同じに扱う。
        assert_eq!(
            judge_link("betterauthmulti:/?state=s&code=c"),
            code("c", "s")
        );
    }

    #[test]
    fn query_values_are_decoded() {
        assert_eq!(
            judge_link("betterauthmulti:///?state=a%20b&code=c%2Bd"),
            code("c+d", "a b")
        );
    }

    #[test]
    fn a_link_without_state_is_ignored_whatever_else_it_has() {
        for link in [
            "betterauthmulti:///",
            "betterauthmulti:///?code=c",
            "betterauthmulti:///?cookie=x&code=c",
            "betterauthmulti:///?error=x",
            "betterauthmulti:///?state=&code=c",
            "betterauthmulti:///?state=a&state=b&code=c",
            "not a url",
            "",
        ] {
            assert_eq!(judge_link(link), LinkVerdict::Ignored, "{link}");
        }
    }

    #[test]
    fn a_link_with_a_session_in_it_is_rejected() {
        for link in [
            "betterauthmulti:///?state=s&cookie=x",
            "betterauthmulti:///?state=s&code=c&cookie=x",
            "betterauthmulti:///?state=s&code=c&cookie=",
            "betterauthmulti:///?state=s&code=c&cookie=x&cookie=y",
        ] {
            assert!(
                matches!(judge_link(link), LinkVerdict::Rejected(_)),
                "{link}"
            );
        }
    }

    #[test]
    fn a_link_with_an_error_is_rejected() {
        assert!(matches!(
            judge_link("betterauthmulti:///?state=s&error=missing_challenge"),
            LinkVerdict::Rejected(_)
        ));
    }

    #[test]
    fn a_link_without_a_code_is_ignored() {
        assert_eq!(
            judge_link("betterauthmulti:///?state=s"),
            LinkVerdict::Ignored
        );
        assert_eq!(
            judge_link("betterauthmulti:///?state=s&code="),
            LinkVerdict::Ignored
        );
    }

    #[test]
    fn a_link_of_the_wrong_shape_is_rejected() {
        for link in [
            "betterauthmulti://evil/?state=s&code=c",
            "betterauthmulti:///path?state=s&code=c",
            "betterauthmulti:///?state=s&code=c#frag",
            "https://example.com/?state=s&code=c",
            "otherscheme:///?state=s&code=c",
        ] {
            assert!(
                matches!(judge_link(link), LinkVerdict::Rejected(_)),
                "{link}"
            );
        }
    }

    #[test]
    fn the_session_check_comes_before_the_shape_check() {
        // 形が違っても、まず「セッション入り」として断る(理由の優先順位)。
        assert_eq!(
            judge_link("betterauthmulti://evil/?state=s&code=c&cookie=x"),
            LinkVerdict::Rejected("a link with a session in it is not accepted")
        );
    }
}
