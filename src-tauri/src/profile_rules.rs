//! プロフィールの編集で、画面が下す判断。通信にも Keychain にも触らない純粋な関数だけを置く。
//!
//! 名前と bio の検証は、Web(`web/src/lib/profile-form.ts`)と Go(`internal/profile/store.go`)と同じ
//! 規則にする。サーバーが最終的に決めるが、ここで先に断れば、無駄な通信をしない。数えるのは
//! コードポイント(Go の `utf8.RuneCountInString` と同じ)で、バイト数でも UTF-16 の長さでもない。
//! モバイルの `profile-rules.ts` に当たる。

use serde::Serialize;

pub const NAME_MAX_CHARS: usize = 50;
pub const BIO_MAX_CHARS: usize = 1000;

/// 入力が断られる理由。文言は画面が決める(ここは種類だけ)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FieldProblem {
    Empty,
    TooLong,
    InvalidCharacter,
}

/// 改行は 1 文字にそろえる(`\r\n` と `\r` を `\n` に)。ブラウザやフォームによって、改行の送り方が
/// 違い、文字数が合わなくなるのを防ぐ。
pub fn normalize_newlines(input: &str) -> String {
    input.replace("\r\n", "\n").replace('\r', "\n")
}

/// 名前: 前後の空白を取り、空でなく、50 文字(コードポイント)以下で、NUL を含まない。
/// 通れば、保存する値(空白を取ったもの)を返す。
pub fn check_name(input: &str) -> Result<String, FieldProblem> {
    let name = input.trim();
    if name.is_empty() {
        return Err(FieldProblem::Empty);
    }
    if name.chars().count() > NAME_MAX_CHARS {
        return Err(FieldProblem::TooLong);
    }
    if name.contains('\0') {
        return Err(FieldProblem::InvalidCharacter);
    }
    Ok(name.to_string())
}

/// bio: 空でもよい(消す)。改行をそろえたうえで、1000 文字(コードポイント)以下で、NUL を含まない。
/// 通れば、保存する値(改行をそろえたもの)を返す。前後の空白は、取らない。
pub fn check_bio(input: &str) -> Result<String, FieldProblem> {
    let bio = normalize_newlines(input);
    if bio.chars().count() > BIO_MAX_CHARS {
        return Err(FieldProblem::TooLong);
    }
    if bio.contains('\0') {
        return Err(FieldProblem::InvalidCharacter);
    }
    Ok(bio)
}

/// 今保存されている値と、画面で編集中の値。
pub struct ProfileValues<'a> {
    /// セッションにある名前(今保存されているもの)。
    pub name: &'a str,
    pub name_draft: &'a str,
    /// Go が持っている bio(今保存されているもの)。
    pub saved_bio: &'a str,
    pub bio_draft: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavePlan {
    pub send_name: bool,
    pub send_bio: bool,
}

/// 変わったものだけを送る。名前は、前後の空白を取って比べる(Web もそうする)。bio は、改行を
/// そろえて比べる。
pub fn plan_save(values: &ProfileValues) -> SavePlan {
    SavePlan {
        send_name: values.name_draft.trim() != values.name,
        send_bio: normalize_newlines(values.bio_draft) != values.saved_bio,
    }
}

impl SavePlan {
    pub fn has_changes(self) -> bool {
        self.send_name || self.send_bio
    }
}

/// 保存が失敗したときの、扱いの種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FailureKind {
    /// 401: セッション(または JWT)がもう有効でない。ローカルのセッションを消して、ログイン画面へ。
    SessionEnded,
    /// 422: サーバーが値を断った。入力は残して、理由を見せる。
    Refused,
    /// それ以外(答えがない、5xx、退会直後の 410 など)。入力は残して、もう一度を促す。
    Other,
}

/// サーバーが答えたときの HTTP ステータス(答えがなければ `None`)から、扱いを決める。
/// Go の 410(退会直後の古いトークン)は、通常の利用では出ないので、`Other` として扱ってよい
/// (Go の設計書の決まり)。
pub fn classify_failure(status: Option<u16>) -> FailureKind {
    match status {
        Some(401) => FailureKind::SessionEnded,
        Some(422) => FailureKind::Refused,
        _ => FailureKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- 名前 ---

    #[test]
    fn a_name_is_trimmed() {
        assert_eq!(check_name("  Alice  ").as_deref(), Ok("Alice"));
        assert_eq!(check_name("\u{3000}花子\u{3000}").as_deref(), Ok("花子"));
    }

    #[test]
    fn an_empty_name_is_refused() {
        for input in ["", "   ", "\t\n", "\u{3000}"] {
            assert_eq!(check_name(input), Err(FieldProblem::Empty), "{input:?}");
        }
    }

    #[test]
    fn a_name_is_counted_in_code_points() {
        assert!(check_name(&"a".repeat(50)).is_ok());
        assert_eq!(check_name(&"a".repeat(51)), Err(FieldProblem::TooLong));
        // 「あ」は 3 バイトだが 1 文字。50 文字ならバイト数が 150 でも通る。
        assert!(check_name(&"あ".repeat(50)).is_ok());
        assert_eq!(check_name(&"あ".repeat(51)), Err(FieldProblem::TooLong));
        // 絵文字(UTF-16 では 2 つ分)も、1 コードポイント。
        assert!(check_name(&"😀".repeat(50)).is_ok());
        assert_eq!(check_name(&"😀".repeat(51)), Err(FieldProblem::TooLong));
    }

    #[test]
    fn the_length_of_a_name_is_checked_after_trimming() {
        assert!(check_name(&format!("  {}  ", "a".repeat(50))).is_ok());
    }

    #[test]
    fn a_name_with_nul_is_refused() {
        assert_eq!(check_name("a\0b"), Err(FieldProblem::InvalidCharacter));
    }

    // --- bio ---

    #[test]
    fn a_bio_may_be_empty_to_clear_it() {
        assert_eq!(check_bio("").as_deref(), Ok(""));
    }

    #[test]
    fn a_bio_keeps_its_spaces_but_not_its_line_break_style() {
        assert_eq!(
            check_bio("  a\r\nb\rc\nd  ").as_deref(),
            Ok("  a\nb\nc\nd  ")
        );
    }

    #[test]
    fn a_bio_is_counted_in_code_points_after_the_line_breaks_are_made_one() {
        assert!(check_bio(&"a".repeat(1000)).is_ok());
        assert_eq!(check_bio(&"a".repeat(1001)), Err(FieldProblem::TooLong));
        assert!(check_bio(&"あ".repeat(1000)).is_ok());
        assert_eq!(check_bio(&"あ".repeat(1001)), Err(FieldProblem::TooLong));
        // 改行 CRLF は、そろえたあと 1 文字として数える: 1000 組で 1000 文字。
        assert!(check_bio(&"\r\n".repeat(1000)).is_ok());
        assert_eq!(check_bio(&"\r\n".repeat(1001)), Err(FieldProblem::TooLong));
    }

    #[test]
    fn a_bio_with_nul_is_refused() {
        assert_eq!(check_bio("a\0"), Err(FieldProblem::InvalidCharacter));
    }

    // --- 何を送るか ---

    fn values<'a>(
        name: &'a str,
        name_draft: &'a str,
        saved_bio: &'a str,
        bio_draft: &'a str,
    ) -> ProfileValues<'a> {
        ProfileValues {
            name,
            name_draft,
            saved_bio,
            bio_draft,
        }
    }

    #[test]
    fn nothing_is_sent_when_nothing_changed() {
        let plan = plan_save(&values("Alice", "Alice", "hi", "hi"));
        assert_eq!(
            plan,
            SavePlan {
                send_name: false,
                send_bio: false
            }
        );
        assert!(!plan.has_changes());
    }

    #[test]
    fn only_what_changed_is_sent() {
        assert_eq!(
            plan_save(&values("Alice", "Alicia", "hi", "hi")),
            SavePlan {
                send_name: true,
                send_bio: false
            }
        );
        assert_eq!(
            plan_save(&values("Alice", "Alice", "hi", "hello")),
            SavePlan {
                send_name: false,
                send_bio: true
            }
        );
        assert!(plan_save(&values("Alice", "Bob", "hi", "hello")).has_changes());
    }

    #[test]
    fn the_name_is_compared_after_trimming() {
        assert!(!plan_save(&values("Alice", "  Alice ", "", "")).send_name);
    }

    #[test]
    fn the_bio_is_compared_after_the_line_breaks_are_made_one() {
        assert!(!plan_save(&values("A", "A", "a\nb", "a\r\nb")).send_bio);
        // 前後の空白は、bio では変更として数える(取らないため)。
        assert!(plan_save(&values("A", "A", "a", "a ")).send_bio);
    }

    #[test]
    fn clearing_the_bio_is_a_change() {
        assert!(plan_save(&values("A", "A", "hi", "")).send_bio);
    }

    // --- 失敗の扱い ---

    #[test]
    fn failures_are_told_apart_by_status() {
        assert_eq!(classify_failure(Some(401)), FailureKind::SessionEnded);
        assert_eq!(classify_failure(Some(422)), FailureKind::Refused);
        for status in [
            Some(400),
            Some(403),
            Some(410),
            Some(429),
            Some(500),
            Some(502),
            None,
        ] {
            assert_eq!(classify_failure(status), FailureKind::Other, "{status:?}");
        }
    }
}
