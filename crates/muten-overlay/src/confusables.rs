//! Homoglyph ("confusable") folding for scam-title matching.
//!
//! ## Why this exists
//!
//! muten's title blocklist is the reliable detection path on real
//! hosts (the behavioural heuristic is weak when the OS helper can't
//! determine origin/modality — see `docs/OVERLAY_BLOCKING.md`). But a
//! plain ASCII substring match is trivially evaded with **homoglyphs**:
//! swapping a Latin letter for a visually identical character from
//! another script. "your computer is infected" becomes "your computer
//! is іnfected" (Cyrillic і, U+0456) — pixel-identical to a human,
//! invisible to `str::contains`.
//!
//! Macharia, Spirin, et al. and the broader literature (e.g. Macko et
//! al., "Authorship Obfuscation in Multilingual MGT Detection",
//! arXiv:2401.07867) find homoglyph substitution to be among the most
//! effective evasions of text-based detectors. Microsoft, Google Safe
//! Browsing, and the Unicode Consortium's UTS #39 "confusables" data
//! all target the same problem.
//!
//! ## What we do (and don't)
//!
//! We fold the homoglyphs that actually appear in scam/phishing text —
//! the Cyrillic and Greek letters that look like Latin a/c/e/i/o/p/x…,
//! plus full-width forms and a few common lookalike symbols — back to
//! their ASCII skeleton before matching. This is a focused subset of
//! UTS #39 (the same "focused subset, not the whole spec" philosophy
//! as the blocklist and the calendar parser), chosen to stay
//! dependency-free, offline, and `forbid(unsafe_code)`. It is not a
//! complete confusables implementation and isn't meant to be; it
//! raises the cost of the cheapest, most common evasion.
//!
//! Folding is idempotent and never lengthens the string (each char
//! maps to exactly one ASCII char or itself), so it's safe to apply
//! before lower-casing and substring matching.

/// Map a single character to its ASCII "skeleton" if it is a known
/// confusable, else return it unchanged. Covers the high-frequency
/// Cyrillic/Greek look-alikes, full-width Latin, and a few symbols.
#[must_use]
pub fn fold_char(c: char) -> char {
    match c {
        // ── Cyrillic look-alikes (lower) ──
        'а' => 'a', // U+0430
        'е' => 'e', // U+0435
        'о' => 'o', // U+043E
        'р' => 'p', // U+0440
        'с' => 'c', // U+0441
        'х' => 'x', // U+0445
        'у' => 'y', // U+0443
        'і' => 'i', // U+0456 (Ukrainian/Belarusian i)
        'ј' => 'j', // U+0458
        'ѕ' => 's', // U+0455
        'н' => 'h', // U+043D (visually h-ish)
        'к' => 'k', // U+043A
        'м' => 'm', // U+043C
        'т' => 't', // U+0442 (lowercase looks like t in some fonts)
        'в' => 'b', // U+0432
        'г' => 'r', // U+0433 (loose)
        'ѳ' => 'o',
        // ── Cyrillic look-alikes (upper) ──
        'А' => 'a',
        'В' => 'b',
        'Е' => 'e',
        'К' => 'k',
        'М' => 'm',
        'Н' => 'h',
        'О' => 'o',
        'Р' => 'p',
        'С' => 'c',
        'Т' => 't',
        'Х' => 'x',
        'У' => 'y',
        'І' => 'i',
        'Ј' => 'j',
        // ── Greek look-alikes ──
        'α' => 'a',
        'ο' => 'o',
        'ρ' => 'p',
        'ε' => 'e',
        'ν' => 'v',
        'χ' => 'x',
        'ι' => 'i',
        'κ' => 'k',
        'Α' => 'a',
        'Β' => 'b',
        'Ε' => 'e',
        'Ζ' => 'z',
        'Η' => 'h',
        'Ι' => 'i',
        'Κ' => 'k',
        'Μ' => 'm',
        'Ν' => 'n',
        'Ο' => 'o',
        'Ρ' => 'p',
        'Τ' => 't',
        'Υ' => 'y',
        'Χ' => 'x',
        // ── Latin diacritics commonly used to dodge filters ──
        'á' | 'à' | 'â' | 'ä' | 'ã' | 'å' => 'a',
        'é' | 'è' | 'ê' | 'ë' => 'e',
        'í' | 'ì' | 'î' | 'ï' => 'i',
        'ó' | 'ò' | 'ô' | 'ö' | 'õ' => 'o',
        'ú' | 'ù' | 'û' | 'ü' => 'u',
        'ç' => 'c',
        'ñ' => 'n',
        // ── a couple of symbol look-alikes ──
        '\u{0131}' => 'i', // dotless i
        '0' => '0',        // (kept; digits handled elsewhere)
        _ => {
            // Full-width ASCII block U+FF01..U+FF5E maps to U+0021..U+007E.
            let u = c as u32;
            if (0xFF01..=0xFF5E).contains(&u) {
                if let Some(ascii) = char::from_u32(u - 0xFEE0) {
                    return ascii;
                }
            }
            c
        }
    }
}

/// Fold every confusable in `s` to its ASCII skeleton. Length in
/// `char`s is preserved (1:1 mapping), so byte length never grows
/// beyond the original char count.
#[must_use]
pub fn fold_confusables(s: &str) -> String {
    s.chars().map(fold_char).collect()
}

/// Host-specific confusable fold. In addition to [`fold_char`]'s
/// script look-alikes, it folds the digit/letter look-alikes used in
/// **typosquatting** domains: `0→o`, `1→l`, `5→s`, `3→e`. A general
/// fold leaves digits alone (phone detection needs them), but in a
/// hostname `micros0ft` / `paypa1` / `goog1e` are pure evasion of an
/// ASCII blocklist — there's no legitimate reason a domain relies on
/// `0` vs `o` to differ from a blocked one. Applied only to host
/// matching, never to titles or phone scanning.
///
/// Note: this is for *blocklist matching only*. Folding a benign host
/// can at worst make it match a block rule that happens to equal its
/// folded form — vanishingly unlikely since block rules are known-bad
/// brands, not arbitrary strings.
#[must_use]
pub fn fold_host_confusables(s: &str) -> String {
    s.chars()
        .map(fold_char)
        .map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '5' => 's',
            '3' => 'e',
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_cyrillic_lookalikes() {
        // "іnfected" with Cyrillic і → ascii "infected"
        assert_eq!(fold_confusables("іnfected"), "infected");
        // "mіcrоsоft" (Cyrillic і, о) → "microsoft"
        assert_eq!(fold_confusables("mіcrоsоft"), "microsoft");
        // "vіrus" → "virus"
        assert_eq!(fold_confusables("vіrus"), "virus");
    }

    #[test]
    fn host_fold_handles_digit_typosquat() {
        // The classic typosquat digits collapse to their letter.
        assert_eq!(fold_host_confusables("micros0ft.com"), "microsoft.com");
        assert_eq!(fold_host_confusables("paypa1.com"), "paypal.com");
        assert_eq!(fold_host_confusables("goog1e.com"), "google.com");
        assert_eq!(fold_host_confusables("5ecure.example"), "secure.example");
    }

    #[test]
    fn host_fold_also_handles_script_lookalikes() {
        // Cyrillic о in a host folds like elsewhere, plus digit fold.
        assert_eq!(fold_host_confusables("micrоs0ft.com"), "microsoft.com");
    }

    #[test]
    fn plain_host_fold_unchanged() {
        assert_eq!(fold_host_confusables("example.com"), "example.com");
    }

    #[test]
    fn folds_greek_lookalikes() {
        // Greek ο, α → o, a
        assert_eq!(fold_confusables("ραѕѕword"), "password");
    }

    #[test]
    fn folds_fullwidth() {
        // Full-width "ALERT" → "ALERT"
        assert_eq!(
            fold_confusables("\u{FF21}\u{FF2C}\u{FF25}\u{FF32}\u{FF34}"),
            "ALERT"
        );
    }

    #[test]
    fn folds_diacritics() {
        assert_eq!(fold_confusables("ínféctéd"), "infected");
    }

    #[test]
    fn leaves_plain_ascii_unchanged() {
        let s = "your computer is infected - call 1-800-555-0100";
        assert_eq!(fold_confusables(s), s);
    }

    #[test]
    fn idempotent() {
        let once = fold_confusables("mіcrоsоft аlert");
        let twice = fold_confusables(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn preserves_non_confusable_unicode() {
        // Japanese text isn't a confusable for Latin; leave it be.
        let s = "ウイルス検出";
        assert_eq!(fold_confusables(s), s);
    }

    #[test]
    fn char_count_preserved() {
        let s = "mіcrоsоft";
        assert_eq!(fold_confusables(s).chars().count(), s.chars().count());
    }
}
