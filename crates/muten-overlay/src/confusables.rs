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
            let u = c as u32;
            // Full-width ASCII block U+FF01..U+FF5E → U+0021..U+007E.
            if (0xFF01..=0xFF5E).contains(&u) {
                if let Some(ascii) = char::from_u32(u - 0xFEE0) {
                    return ascii;
                }
            }
            // Enclosed/circled Capital Latin Letters Ⓐ(U+24B6)..Ⓩ(U+24CF).
            // Used in phishing to bypass text filters: ⓟⓐⓨⓟⓐⓛ → paypal.
            // Both uppercase (24B6-24CF) and lowercase (24D0-24E9) blocks fold to
            // their a-z counterpart (1:1; char count preserved).
            if (0x24B6..=0x24CF).contains(&u) {
                // Ⓐ→a … Ⓩ→z  (25 chars, same offset for both blocks)
                if let Some(ascii) = char::from_u32(u - 0x24B6 + b'a' as u32) {
                    return ascii;
                }
            }
            if (0x24D0..=0x24E9).contains(&u) {
                // ⓐ→a … ⓩ→z
                if let Some(ascii) = char::from_u32(u - 0x24D0 + b'a' as u32) {
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

/// The UTS #39 "skeleton" of a host label: fold every confusable
/// (including the digit/letter typosquat look-alikes) to its ASCII
/// prototype and lower-case. Two strings that *look* the same collapse
/// to the same skeleton, so `skeleton("раура1") == skeleton("paypal")`.
/// This is muten's focused, dependency-free equivalent of the UTS #39
/// confusable skeleton, used for brand-homograph detection.
#[must_use]
pub fn skeleton(s: &str) -> String {
    fold_host_confusables(s).to_ascii_lowercase()
}

/// True if `c` is a zero-width, formatting, or BiDi-control character.
///
/// These are invisible to a human but split a word for a naive
/// substring matcher: `"in\u{200B}fected"` renders as "infected" yet
/// `str::contains("infected")` fails. Attackers also use BiDi
/// overrides (U+202A..U+202E, U+2066..U+2069) to reorder displayed
/// text. We strip them before matching. (IMPROVEMENT_ROADMAP C8-5/C8-9.)
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{200B}' | '\u{200C}' | '\u{200D}' | // ZWSP / ZWNJ / ZWJ
        '\u{2060}' |                            // word joiner
        '\u{FEFF}' |                            // ZWNBSP / BOM
        '\u{00AD}' |                            // soft hyphen
        '\u{180E}' |                            // Mongolian vowel separator
        '\u{200E}' | '\u{200F}' |               // LRM / RLM
        '\u{202A}'..='\u{202E}' |               // LRE/RLE/PDF/LRO/RLO
        '\u{2066}'..='\u{2069}'                 // LRI/RLI/FSI/PDI
    )
}

/// Remove zero-width / formatting / BiDi-control characters. Never
/// lengthens the string (it only drops chars).
#[must_use]
pub fn strip_invisibles(s: &str) -> String {
    s.chars().filter(|&c| !is_invisible(c)).collect()
}

/// True if `s` contains a BiDi **directional override** — `U+202D`
/// (LRO) or `U+202E` (RLO). These force a reading direction and are the
/// classic "Trojan Source" / filename-extension spoofing vector
/// (arXiv:2111.00169): the displayed text can be made to read entirely
/// differently from the logical bytes. Unlike the LRM/RLM marks and the
/// directional *isolates* (which legitimate RTL text and modern apps do
/// use), an explicit override has essentially no honest use in a window
/// title — so its mere presence is a high-confidence, low-false-positive
/// spoofing tell. Evaluated on the **raw** string, before stripping.
#[must_use]
pub fn has_bidi_override(s: &str) -> bool {
    s.chars().any(|c| matches!(c, '\u{202D}' | '\u{202E}'))
}

/// The (confusable-bearing) script of a character. Only the three
/// scripts that supply Latin look-alikes are named; everything else —
/// digits, punctuation, **and CJK / Kana / Hangul** — is `Other` and
/// ignored. That last point is the false-positive guard for the
/// Japanese market: a legitimate "ウイルス Alert" title contains both
/// Japanese and Latin, but Japanese is `Other`, so it is *not* flagged
/// as mixed-script. Only Latin mixed with Cyrillic/Greek inside one
/// token is the homoglyph-evasion tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    /// ASCII + Latin-1/Extended-A/B letters.
    Latin,
    /// Cyrillic block (U+0400–U+04FF).
    Cyrillic,
    /// Greek and Coptic block (U+0370–U+03FF).
    Greek,
    /// Everything else (CJK, Kana, Hangul, digits, punctuation, …).
    Other,
}

/// Classify a character into a confusable-bearing [`Script`], or
/// [`Script::Other`].
#[must_use]
pub fn script_of(c: char) -> Script {
    match c as u32 {
        0x41..=0x5A | 0x61..=0x7A => Script::Latin, // ASCII letters
        0x00C0..=0x024F => Script::Latin,           // Latin-1 Suppl. + Extended-A/B
        0x0370..=0x03FF => Script::Greek,           // Greek and Coptic
        0x0400..=0x04FF => Script::Cyrillic,        // Cyrillic
        _ => Script::Other,
    }
}

/// True if `s` contains an enclosed/circled Latin letter (Ⓐ–Ⓩ /
/// ⓐ–ⓩ, U+24B6–U+24E9). These are used in phishing titles to evade
/// plain-text blocklist matching — `ⓟⓐⓨⓟⓐⓛ` is invisible to
/// `str::contains("paypal")` but looks like "paypal" to a human.
/// `normalize_for_match` now folds them (via [`fold_char`]), so blocklist
/// matching catches them; this function allows detecting their mere
/// *presence* in a raw title as a high-confidence, low-FP evasion tell.
/// Enclosed letters have essentially no legitimate use in a window title
/// (contrast with the circled *numerals* ①②③ which appear in lists).
#[must_use]
pub fn has_compat_alpha(s: &str) -> bool {
    s.chars().any(|c| matches!(c as u32, 0x24B6..=0x24E9))
}

/// True if any single whitespace-delimited token consists entirely of
/// letters from one confusable script (Cyrillic or Greek) where every
/// letter folds to an ASCII counterpart — i.e. the whole word is
/// *designed* to look Latin but contains no Latin characters at all.
/// This is the "whole-script confusable" blind spot of mixed-script
/// detection: `ѕсоре` (all Cyrillic) fools `mixed_script` because there
/// are no Latin letters to trigger a cross-script mix, yet it looks
/// exactly like "scope" to a human (UTS #39 §5).
///
/// The FP guard: legitimate Cyrillic text (Russian, Ukrainian, …)
/// almost always contains Cyrillic letters that do *not* have ASCII
/// confusable mappings in muten's table (e.g. `п`, `и`, `л`, `д` …).
/// `привет` will not fire because `п` has no ASCII fold. Evaluated on
/// the **raw** string before normalization erases the evidence.
#[must_use]
pub fn has_whole_script_confusable(s: &str) -> bool {
    'token: for token in s.split_whitespace() {
        let mut script = Script::Other; // the single non-Latin script seen so far
        let mut has_letter = false;

        for c in token.chars() {
            let sc = script_of(c);
            match sc {
                Script::Other => continue, // digits, punctuation — skip for script analysis
                Script::Latin => {
                    // Any Latin letter means mixed-script already covers it,
                    // or it's genuinely Latin — not a whole-script confusable.
                    continue 'token;
                }
                Script::Cyrillic | Script::Greek => {
                    has_letter = true;
                    if script == Script::Other {
                        script = sc;
                    } else if script != sc {
                        // Mixed Cyrillic+Greek in one token — unusual; skip.
                        continue 'token;
                    }
                    // Key guard: does this letter have an ASCII confusable?
                    // If not, the word uses non-confusable Cyrillic/Greek and
                    // is likely legitimate text, not a disguise.
                    if !fold_char(c).is_ascii_alphabetic() {
                        continue 'token;
                    }
                }
            }
        }

        if has_letter && script != Script::Other {
            return true;
        }
    }
    false
}

/// True if any single whitespace-delimited token mixes Latin with
/// Cyrillic or Greek letters — e.g. `"раypаl"` (Cyrillic р,а + Latin
/// y,p,l) or `"miсrosoft"` (Cyrillic с among Latin). This is a strong
/// disguise tell (UTS #39 mixed-script confusables; NDSS 2015
/// typosquatting). Run on the **raw** string: [`fold_confusables`]
/// erases the evidence by folding everything to Latin, so the score
/// must read this before folding for matching.
///
/// A pure-Cyrillic word (legitimate Russian) does *not* fire — only a
/// within-token *mix* does.
#[must_use]
pub fn has_confusable_mixed_script(s: &str) -> bool {
    for token in s.split_whitespace() {
        let mut latin = false;
        let mut confusable = false;
        for c in token.chars() {
            match script_of(c) {
                Script::Latin => latin = true,
                Script::Cyrillic | Script::Greek => confusable = true,
                Script::Other => {}
            }
            if latin && confusable {
                return true;
            }
        }
    }
    false
}

/// Map a single leetspeak digit to the letter it stands in for. Only
/// the unambiguous substitutions used to dodge text filters.
fn fold_leet_digit(c: char) -> char {
    match c {
        '0' => 'o',
        '1' => 'i',
        '3' => 'e',
        '4' => 'a',
        '5' => 's',
        '7' => 't',
        other => other,
    }
}

fn push_leet_token(token: &str, out: &mut String) {
    // Only de-leet a token that *contains a letter* — `v1rus`→`virus`,
    // `1nfected`→`infected`. A pure-digit token (`1800`, `0100`, a
    // year, a count) is left untouched so phone numbers and quantities
    // survive. This keeps leet-folding from corrupting numeric text.
    if token.chars().any(|c| c.is_ascii_alphabetic()) {
        out.extend(token.chars().map(fold_leet_digit));
    } else {
        out.push_str(token);
    }
}

/// Fold leetspeak digit substitutions back to letters, but only inside
/// alphanumeric tokens that already contain a letter (see
/// `push_leet_token`). Separators and pure-digit runs are preserved
/// verbatim. (IMPROVEMENT_ROADMAP C8-6.)
#[must_use]
pub fn fold_leet_in_words(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut token = String::new();
    for c in s.chars() {
        if c.is_alphanumeric() {
            token.push(c);
        } else {
            push_leet_token(&token, &mut out);
            token.clear();
            out.push(c);
        }
    }
    push_leet_token(&token, &mut out);
    out
}

/// The single normalized form used for **blocklist title matching**:
/// strip invisibles → fold confusables → fold leetspeak → lowercase.
/// Idempotent. This is intentionally *not* applied to the
/// phone-number scan (which needs the original digits).
#[must_use]
pub fn normalize_for_match(s: &str) -> String {
    let stripped = strip_invisibles(s);
    let folded = fold_confusables(&stripped);
    fold_leet_in_words(&folded).to_ascii_lowercase()
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

    #[test]
    fn strips_zero_width_chars() {
        // "in<ZWSP>fected" → "infected"; the bare word now matches.
        assert_eq!(strip_invisibles("in\u{200B}fected"), "infected");
        assert_eq!(strip_invisibles("a\u{200C}b\u{FEFF}c\u{00AD}d"), "abcd");
        // BiDi controls are stripped too.
        assert_eq!(strip_invisibles("ab\u{202E}cd"), "abcd");
    }

    #[test]
    fn strip_invisibles_leaves_plain_text() {
        let s = "your computer is infected";
        assert_eq!(strip_invisibles(s), s);
    }

    #[test]
    fn mixed_script_detects_within_token_mix() {
        // Cyrillic а/р mixed with Latin in one token.
        assert!(has_confusable_mixed_script("раypаl"));
        // Cyrillic с among Latin "mi rosoft".
        assert!(has_confusable_mixed_script("miсrosoft alert"));
        // Greek ο among Latin.
        assert!(has_confusable_mixed_script("g\u{03BF}ogle"));
    }

    #[test]
    fn mixed_script_does_not_fire_on_single_script() {
        assert!(!has_confusable_mixed_script("your computer is infected"));
        // Pure Cyrillic (legitimate Russian) is not a *mix*.
        assert!(!has_confusable_mixed_script("привет мир"));
        // Japanese + Latin in *separate* tokens: Japanese is `Other`,
        // so this legitimate JP title must NOT flag (FP guard).
        assert!(!has_confusable_mixed_script("ウイルス Alert"));
        assert!(!has_confusable_mixed_script("お知らせ Windows Update"));
    }

    #[test]
    fn leet_folds_in_words_only() {
        assert_eq!(fold_leet_in_words("v1rus"), "virus");
        assert_eq!(fold_leet_in_words("1nfected"), "infected");
        assert_eq!(fold_leet_in_words("s3cur3"), "secure");
        // Pure-digit tokens (a phone number) survive untouched.
        assert_eq!(
            fold_leet_in_words("call 1-800-555-0100"),
            "call 1-800-555-0100"
        );
    }

    #[test]
    fn normalize_for_match_runs_full_pipeline() {
        // ZW split + Cyrillic homoglyph + leetspeak, all collapsed.
        assert_eq!(
            normalize_for_match("Y\u{200B}our C\u{043E}mputer is 1nfected"),
            "your computer is infected"
        );
    }

    #[test]
    fn normalize_for_match_is_idempotent() {
        let once = normalize_for_match("V1rus DETECTED оn paypа1");
        let twice = normalize_for_match(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn whole_script_confusable_fires_on_all_cyrillic_lookalike() {
        // ѕсоре — all Cyrillic, every letter folds to ASCII (s,c,o,p,e).
        // Crucially: NO Latin letters → mixed_script would miss this.
        assert!(
            has_whole_script_confusable("ѕсоре"),
            "ѕсоре looks like 'scope'"
        );
        // Same lookalike in a longer sentence (other tokens are Latin, but
        // the per-token check only needs one whole-script token to fire).
        assert!(has_whole_script_confusable("detected ѕсоре found"));
    }

    #[test]
    fn whole_script_does_not_fire_on_real_cyrillic_text() {
        // привет — contains п (U+043F), not in fold_char table → fold_char('п')='п'
        // → NOT ascii_alphabetic → continue 'token → no fire. ✓
        assert!(!has_whole_script_confusable("привет мир"));
        // Pure Latin — no Cyrillic/Greek letters at all.
        assert!(!has_whole_script_confusable("your computer is infected"));
        // Mixed-script token (has Latin 'y','p','l') — whole_script hits
        // Latin → continue 'token → no fire; mixed_script catches this.
        assert!(!has_whole_script_confusable("раypаl"));
        // Japanese + Latin — Japanese is Script::Other, Latin is Latin →
        // no fire from whole_script (Latin kills it). mixed_script also OK.
        assert!(!has_whole_script_confusable("ウイルス Alert"));
    }

    #[test]
    fn whole_script_fires_on_all_greek_lookalike() {
        // Α(U+0391)→a, ρ(U+03C1)→p, ρ, Ι(U+0399)→i, ε(U+03B5)→e.
        // All Greek, all fold to ASCII → looks like "apple" → fire.
        assert!(
            has_whole_script_confusable("ΑρρΙε"),
            "'ΑρρΙε' looks like 'apple'"
        );
    }

    #[test]
    fn whole_script_ignores_digits_in_token() {
        // ѕсоре2024 — Cyrillic letters + digits. Digits are Script::Other
        // (ignored for the script analysis). All Cyrillic letters fold to
        // ASCII → the token is still a whole-script confusable.
        assert!(has_whole_script_confusable("ѕсоре2024"));
    }

    #[test]
    fn whole_script_mixed_with_latin_does_not_fire() {
        // A token with both Cyrillic AND Latin letters hits Latin →
        // continue 'token — whole_script doesn't fire (mixed_script does).
        // аlеrт: а,е,т are Cyrillic but l,r are Latin → no whole_script fire.
        assert!(!has_whole_script_confusable("аlеrт"));
    }

    // ── has_compat_alpha / enclosed letters ──────────────────────

    #[test]
    fn fold_char_handles_enclosed_uppercase() {
        // Ⓐ(U+24B6)→'a', Ⓩ(U+24CF)→'z', Ⓟ(U+24C5)→'p'.
        assert_eq!(fold_char('\u{24B6}'), 'a'); // Ⓐ
        assert_eq!(fold_char('\u{24CF}'), 'z'); // Ⓩ
        assert_eq!(fold_char('\u{24C5}'), 'p'); // Ⓟ
    }

    #[test]
    fn fold_char_handles_enclosed_lowercase() {
        // ⓐ(U+24D0)→'a', ⓟ(U+24DF)→'p', ⓩ(U+24E9)→'z'.
        assert_eq!(fold_char('\u{24D0}'), 'a'); // ⓐ
        assert_eq!(fold_char('\u{24DF}'), 'p'); // ⓟ
        assert_eq!(fold_char('\u{24E9}'), 'z'); // ⓩ
    }

    #[test]
    fn fold_confusables_maps_enclosed_letters_to_ascii() {
        // ⓟⓐⓨⓟⓐⓛ folds to "paypal".
        assert_eq!(fold_confusables("ⓟⓐⓨⓟⓐⓛ"), "paypal");
    }

    #[test]
    fn normalize_for_match_collapses_enclosed_letters() {
        assert_eq!(normalize_for_match("ⓟⓐⓨⓟⓐⓛ ALERT"), "paypal alert");
    }

    #[test]
    fn has_compat_alpha_fires_on_enclosed_letters() {
        assert!(has_compat_alpha("ⓟⓐⓨⓟⓐⓛ"));
        assert!(has_compat_alpha("Ⓐ")); // uppercase enclosed
        assert!(has_compat_alpha("normal text ⓩ mixed in"));
    }

    #[test]
    fn has_compat_alpha_does_not_fire_on_plain_text() {
        assert!(!has_compat_alpha("paypal"));
        assert!(!has_compat_alpha(
            "your computer is infected call 1-800-555-0100"
        ));
        // Circled NUMERALS ① ② (U+2460-U+2473) are not enclosed letters — don't fire.
        assert!(!has_compat_alpha("step ① complete ②"));
    }
}
