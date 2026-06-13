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

/// True if `c` is an emoji, pictograph, or decorative symbol that has no
/// role in alphanumeric text but can be inserted mid-word to defeat
/// substring matching ("inf⚠️ected" → "infected" after stripping).
///
/// Ranges stripped:
/// - U+2600–U+26FF Miscellaneous Symbols (⚠️ ☎ ☠ ⚡ ☢ etc.)
/// - U+2700–U+27BF Dingbats (✗ ✘ ☞ ✓ ✔ etc.)
/// - U+FE00–U+FEFF Variation selectors (turn ⚠ into ⚠️)
/// - U+1F000–U+1FFFF Emoji / pictograph blocks
///
/// NOT stripped: U+3000–U+30FF / U+4E00+ (CJK, Kana) — Japanese titles
/// must pass through unaltered.
fn is_emoji_or_symbol(c: char) -> bool {
    matches!(c,
        '\u{2600}'..='\u{27BF}' | // Misc Symbols + Dingbats
        '\u{FE00}'..='\u{FEFF}' | // Variation selectors
        '\u{1F000}'..='\u{1FFFF}' // Emoji / pictograph blocks
    )
}

/// Remove emoji and decorative symbol characters from `s`. Never
/// lengthens the string. Called **before** `strip_invisibles` in
/// `normalize_for_match` so that mid-word emoji insertions (e.g.
/// `"inf⚠️ected"`) are collapsed before any other folding.
///
/// Japanese text (U+3000–U+30FF, U+4E00+) is unaffected.
#[must_use]
pub fn strip_symbols_and_emoji(s: &str) -> String {
    s.chars().filter(|&c| !is_emoji_or_symbol(c)).collect()
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

/// Identify the decimal-digit *numbering system* of `c`, or `None` if
/// `c` is not a decimal digit. Each system is one contiguous 0–9 block.
/// ASCII and full-width digits share the same id (full-width folds to
/// ASCII anyway, and full-width digits appear in legitimate Japanese
/// text) so mixing them is *not* treated as a spoof — the JP false-
/// positive guard. A focused, dependency-free subset of the Unicode
/// decimal-digit blocks that actually appear in spoofing.
#[must_use]
pub fn digit_system(c: char) -> Option<u8> {
    match c as u32 {
        // "Western" Arabic numerals: ASCII *and* full-width forms.
        0x0030..=0x0039 | 0xFF10..=0xFF19 => Some(0),
        0x0660..=0x0669 => Some(1), // Arabic-Indic
        0x06F0..=0x06F9 => Some(2), // Extended Arabic-Indic (Persian/Urdu)
        0x0966..=0x096F => Some(3), // Devanagari
        0x09E6..=0x09EF => Some(4), // Bengali
        0x0BE6..=0x0BEF => Some(5), // Tamil
        0x0E50..=0x0E59 => Some(6), // Thai
        0x2460..=0x2468 => Some(7), // Circled digits ①–⑨ (no 0)
        _ => None,
    }
}

/// True if `c` is a combining mark (a zero-advance diacritic that
/// stacks onto the preceding base character). A focused, dependency-free
/// subset of the Unicode combining-mark blocks: Combining Diacritical
/// Marks and their three extension/supplement/symbol blocks, plus the
/// combining half marks. Enough to spot the abuse this detects; not a
/// complete `Mn`/`Mc` general-category table.
#[must_use]
pub fn is_combining_mark(c: char) -> bool {
    matches!(c as u32,
        0x0300..=0x036F | // Combining Diacritical Marks
        0x1AB0..=0x1AFF | // Combining Diacritical Marks Extended
        0x1DC0..=0x1DFF | // Combining Diacritical Marks Supplement
        0x20D0..=0x20FF | // Combining Diacritical Marks for Symbols
        0xFE20..=0xFE2F   // Combining Half Marks
    )
}

/// True if `s` stacks an **abnormal run of combining marks** on a single
/// base character — three or more in a row — the signature of "Zalgo"
/// text used to obfuscate a title past a substring matcher or to
/// visually corrupt a UI. The threshold of 3 is the false-positive
/// guard: legitimate scripts (Vietnamese, Arabic, Indic, IPA, …) stack
/// at most one or two combining marks on a base, so they never fire. A
/// leading combining mark with no base also counts (malformed/abusive).
/// Evaluated on the **raw** string.
#[must_use]
pub fn has_excessive_combining_marks(s: &str) -> bool {
    let mut run = 0u32;
    for c in s.chars() {
        if is_combining_mark(c) {
            run += 1;
            if run >= 3 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// True if any single whitespace-delimited token mixes decimal digits
/// from **two different numbering systems** — e.g. ASCII `5` next to
/// Arabic-Indic `٥` (U+0665) inside one token. No legitimate number
/// mixes numbering systems (ICU `SpoofChecker.MIXED_NUMBERS`), so this
/// is a near-zero-false-positive spoofing tell. ASCII and full-width
/// digits count as the same system (see [`digit_system`]), so a
/// legitimate Japanese title using full-width digits alongside ASCII is
/// *not* flagged. Evaluated on the **raw** string before folding.
#[must_use]
pub fn has_mixed_number_systems(s: &str) -> bool {
    for token in s.split_whitespace() {
        let mut seen: Option<u8> = None;
        for c in token.chars() {
            if let Some(sys) = digit_system(c) {
                match seen {
                    None => seen = Some(sys),
                    Some(prev) if prev != sys => return true,
                    _ => {}
                }
            }
        }
    }
    false
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
/// strip emoji/symbols → strip invisibles → fold confusables → fold
/// leetspeak → lowercase.  Idempotent.  The emoji step runs first so
/// mid-word insertions (e.g. `"inf⚠️ected"`) are collapsed before any
/// other folding.  Not applied to the phone-number scan (which needs
/// the original digits).
#[must_use]
pub fn normalize_for_match(s: &str) -> String {
    let s = strip_symbols_and_emoji(s);
    let stripped = strip_invisibles(&s);
    let folded = fold_confusables(&stripped);
    fold_leet_in_words(&folded).to_ascii_lowercase()
}

/// Detect ClickFix / fake-CAPTCHA keyboard-instruction patterns in a
/// **pre-normalized** string (i.e. the output of [`normalize_for_match`]).
///
/// ClickFix attacks (also called FakeCAPTCHA / ClearFake / KongTuke) trick
/// users into running attacker-supplied commands by:
///
/// 1. Displaying a fake browser-error, CAPTCHA, or audio-verification page
///    in a full-screen or modal overlay, and
/// 2. Asking the user to press a keyboard shortcut (`Win+R`, `Ctrl+V`) or
///    open a run-dialog to "fix" the page or "prove they are human".
///
/// This function matches the **structural** text patterns shared by all
/// ClickFix variants — keyboard-shortcut references, run-dialog instructions,
/// and CAPTCHA / human-verification framing — independently of exact phrasing,
/// so novel variants not yet in the title blocklist are still detected.
///
/// Call this on pre-normalized text so leet-substitution and homoglyph
/// evasion are defeated before the match (`v3rify` → `verify`,
/// `c4ptcha` → `captcha`).
///
/// Near-zero false-positive rate: keyboard-shortcut execution strings and
/// CAPTCHA-framing phrases essentially never appear in legitimate application
/// window or document titles. The [`crate::classify`] caller adds an
/// `alert_shaped` guard (full-screen / modal / no-close) as an extra FP filter
/// before the `clickfix_instruction` signal fires.
///
/// # Reference
/// Microsoft Security Blog, 2025 — ClickFix surge (+517 % in H1 2025, ~47 %
/// of intrusions). Proofpoint TA571, Sekoia IClickFix, Huntress CrashFix.
#[must_use]
pub fn has_clickfix_instruction(s: &str) -> bool {
    // Keyboard-shortcut execution instructions — the core ClickFix lure.
    // Checked with and without spaces around `+` to match both "win+r" and
    // "windows + r" after normalize_for_match lowercasing.
    let shortcut = s.contains("win+r")
        || s.contains("windows+r")
        || s.contains("windows + r")
        || s.contains("winkey")
        || s.contains("ctrl+v")
        || s.contains("ctrl + v")
        || s.contains("ctrl+r")
        || s.contains("alt+r");

    // Run-dialog / command-execution framing phrases.
    let run_cmd = s.contains("open run")
        || s.contains("run dialog")
        || s.contains("paste the command")
        || s.contains("type this command")
        || s.contains("type the command")
        || s.contains("run the following")
        || s.contains("the following command")
        || s.contains("into the run box");

    // CAPTCHA / human-verification framing.  Both components required for
    // the compound patterns to keep precision high; "captcha" alone is
    // accepted because it has essentially no legitimate window-title use when
    // combined with alert_shaped (the guard applied by classify()).
    let captcha_frame = s.contains("not a robot")
        || s.contains("captcha")
        || (s.contains("verify") && s.contains("human"))
        || (s.contains("confirm") && s.contains("human"));

    // GlitchFix / CrashFix / browser-error variants (Huntress Jan 2026,
    // The Hacker News GlitchFix Jan 2026). These lures present a "browser
    // stopped working" / "font required" / "browser update" dialog and ask
    // the user to paste a clipboard payload — same ClickFix technique.
    let glitchfix = (s.contains("browser") && s.contains("stopped"))
        || (s.contains("browser") && s.contains("abnormally"))
        || (s.contains("font") && (s.contains("required") || s.contains("missing")))
        || (s.contains("update")
            && s.contains("browser")
            && (s.contains("continue")
                || s.contains("required")
                || s.contains("click")
                || s.contains("press")))
        || s.contains("system font");

    shortcut || run_cmd || captcha_frame || glitchfix
}

/// Detect a countdown/timer pattern (`M:SS` or `MM:SS`) combined with an
/// urgency keyword in a normalized window title.
///
/// Scam overlays routinely pair a visible countdown with fear language
/// ("Your session expires in 5:00 — call support now!", "INFECTED! 2:59
/// remaining — activate immediately") to coerce rapid action before the
/// target can think. Legitimate applications that display countdowns (media
/// players, meeting timers) are either user-initiated (suppressed by the
/// `alert_shaped` guard in `classify()`) or contain none of the urgency
/// keywords below.
///
/// The caller is responsible for passing a string already processed through
/// [`normalize_for_match`] so that leet-coded urgency words (`3xp1r3s`) are
/// correctly folded before the keyword search.
///
/// # False-positive guard
///
/// Only fires when the window is `alert_shaped` (full-screen / modal /
/// no-close) in `classify()` — the same guard used for `clickfix_instruction`.
/// A clock app, a media player countdown, or a cooking timer has none of the
/// urgency keywords AND is not alert-shaped.
#[must_use]
pub fn has_urgency_countdown(s: &str) -> bool {
    const URGENCY: &[&str] = &[
        "expir", "warn", "alert", "infect", "block", "lock", "urgent", "critical", "threat",
        "danger", "support", "call",
    ];
    if !URGENCY.iter().any(|kw| s.contains(kw)) {
        return false;
    }
    // Look for M:SS or MM:SS — a countdown timer display.
    // Avoids matching port numbers (host:80 — one or two digits right of colon,
    // but those typically have 4+ digits) and IPv6 (many colons, 4-hex groups).
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    if n < 4 {
        return false;
    }
    // i is the position of the colon; we need chars[i-1] and chars[i+1..=i+2].
    for i in 1..n - 2 {
        if chars[i] != ':' {
            continue;
        }
        // Right side: exactly 2 ASCII digits (not 3+, which would be a port or
        // seconds-within-hours in HH:MM:SS).
        if !chars[i + 1].is_ascii_digit() || !chars[i + 2].is_ascii_digit() {
            continue;
        }
        if i + 3 < n && chars[i + 3].is_ascii_digit() {
            continue;
        }
        // Left side: 1 or 2 ASCII digits (not 3+).
        if !chars[i - 1].is_ascii_digit() {
            continue;
        }
        // Reject if there are 3+ consecutive digits to the left of the colon.
        if i >= 3 && chars[i - 2].is_ascii_digit() && chars[i - 3].is_ascii_digit() {
            continue;
        }
        return true;
    }
    false
}

/// Detect "do not close / turn off / exit / restart" retention instructions in a
/// normalized window title.
///
/// Tech-support scam overlays routinely instruct victims **not** to close the
/// window while the attacker is "helping" — this prevents escape and coerces
/// compliance. Legitimate software almost never puts a "do not close" instruction
/// in a *window title* (it may appear in a dialog body, but titles are labels,
/// not instructions). When found in an `alert_shaped` window (caller's guard in
/// `classify()`), this is a very strong scam indicator.
///
/// Both English and Japanese phrasings are recognized. "この画面を閉じないで
/// ください" (do not close this screen) is the single most iconic phrase in
/// Japanese サポート詐欺 overlays and is explicitly called out in IPA
/// (情報処理推進機構) advisories. `normalize_for_match` uses
/// `to_ascii_lowercase()`, so the CJK passes through untouched.
///
/// The caller passes a string already processed through [`normalize_for_match`]
/// so that homoglyph / leet variants (`dо not ⅽlоse`, `d0 n0t cl0se`) are folded
/// before the substring check.
#[must_use]
pub fn has_forced_retention(s: &str) -> bool {
    // English phrasings.
    let en = s.contains("do not close")
        || s.contains("dont close")
        || s.contains("do not exit")
        || s.contains("do not turn off")
        || s.contains("do not shut down")
        || s.contains("do not restart")
        || s.contains("do not click away")
        || s.contains("keep this window open")
        || s.contains("leave this page open")
        || s.contains("stay on this page")
        || s.contains("this window must remain open");

    // Japanese phrasings (IPA サポート詐欺 corpus). Substring matching covers
    // the polite/plain inflections ("閉じないで", "閉じないでください",
    // "閉じないでね").
    let jp = s.contains("閉じないで")           // do not close
        || s.contains("閉じないでください")     // do not close (polite)
        || s.contains("電源を切らないで")       // do not turn off power
        || s.contains("シャットダウンしないで") // do not shut down
        || s.contains("再起動しないで")         // do not restart
        || s.contains("このページから離れないで") // do not leave this page
        || s.contains("この画面を閉じ")         // (do not) close this screen
        || s.contains("ウィンドウを閉じないで") // do not close the window
        || s.contains("操作を続けないで"); // do not continue operating (lock framing)

    en || jp
}

/// Detect credential-harvest phishing cues in a normalized window title.
///
/// Account-takeover overlays prompt the victim to re-enter their credentials
/// in an alert-shaped popup rather than on the real login page. The phrases
/// below are the canonical credential-phishing instruction/alarm patterns:
/// "verify your account", "confirm your password", "account suspended",
/// "unusual sign-in activity", etc. These are high-specificity phrases —
/// legitimate security notifications appear in the browser's own UI, not in
/// an alert-shaped overlay with no close button.
///
/// Both English and Japanese phrasings are recognized. JP credential-phishing
/// overlays ("アカウントが停止されました", "パスワードを確認してください") are a
/// dominant local variant (IPA / 国民生活センター フィッシング詐欺 advisories).
/// `normalize_for_match` uses `to_ascii_lowercase()`, so CJK passes through
/// untouched.
///
/// Caller must pass a string already processed through [`normalize_for_match`]
/// so that homoglyph variants are folded first.
#[must_use]
pub fn has_credential_harvest_cue(s: &str) -> bool {
    let has = |a: &str| s.contains(a);
    // Account status alarms (word-pair checks tolerate natural English
    // phrasing: "account has been suspended", "account is locked", etc.).
    let account_alarm = (has("account") && has("suspended"))
        || (has("account") && has("locked"))
        || (has("account") && has("disabled"))
        || (has("account") && has("blocked"))
        || (has("account") && has("compromised"))
        || (has("unusual") && has("sign"))
        || (has("suspicious") && has("sign"))
        || (has("unusual") && has("login"))
        || (has("suspicious") && has("login"))
        || (has("suspicious") && has("activity"));
    // Credential entry instructions.
    let cred_instruction = (has("verify") && has("account"))
        || (has("confirm") && has("password"))
        || (has("confirm") && has("identity"))
        || (has("verify") && has("identity"))
        || (has("re-enter") && has("password"))
        || (has("enter") && has("credentials"))
        || (has("update") && has("payment"));

    // Japanese account-alarm + credential-instruction phrasings.
    let jp_account_alarm = (has("アカウント") && has("停止")) // account suspended
        || (has("アカウント") && has("凍結"))                 // account frozen
        || (has("アカウント") && has("ロック"))               // account locked
        || (has("アカウント") && has("無効"))                 // account disabled
        || (has("アカウント") && has("制限"))                 // account restricted
        || has("不審なログイン")                              // suspicious login
        || has("不正なログイン")                              // unauthorized login
        || has("異常なログイン"); // abnormal login
    let jp_cred_instruction = (has("アカウント") && has("確認")) // verify account
        || (has("パスワード") && has("確認"))                    // confirm password
        || (has("パスワード") && has("再入力"))                  // re-enter password
        || has("本人確認")                                       // identity verification
        || has("身元確認")                                       // identity check
        || (has("アカウント") && has("再開")); // reactivate account (phish lure)

    account_alarm || cred_instruction || jp_account_alarm || jp_cred_instruction
}

/// Detect fake-scanner / threat-count language in a normalized window title.
///
/// Rogue-AV and tech-support-scam overlays display fake progress titles like
/// "Scanning for threats…", "4 threats found!", "Removing malware…", or
/// "System repair in progress".  Real OS scanners run as tray apps and never
/// put a progress message in a *window title* while also blocking the desktop.
///
/// Call on the output of `normalize_for_match` to defeat leet/homoglyph
/// evasion; combine with the `alert_shaped` guard in `classify()` to keep
/// FPs to zero for legitimate security software the user deliberately opened.
///
/// Both English and Japanese phrasings are recognized. JP fake-scanner
/// progress overlays ("脅威が見つかりました", "システムを修復しています") are a
/// core サポート詐欺 element. `normalize_for_match` uses `to_ascii_lowercase()`,
/// so CJK passes through untouched. (Note: static infection claims like
/// "ウイルスに感染" are already covered as blocklist titles; this heuristic
/// adds the dynamic scan/threat-count/repair *progress* framing.)
///
/// Patterns grounded in Microsoft Edge Scareware Blocker corpus, Malwarebytes
/// rogue-AV samples, SafetyDetectives 2026 fake-antivirus guide, and IPA
/// サポート詐欺 advisories.
#[must_use]
pub fn has_fake_scanner_cue(s: &str) -> bool {
    let has = |a: &str| s.contains(a);
    // "scanning for viruses / threats / malware / spyware"
    let scanning_lure =
        has("scanning") && (has("virus") || has("threat") || has("malware") || has("spyware"));
    // "N threats / viruses / infections detected / found"
    let threat_count = (has("threat") || has("virus") || has("infection"))
        && (has("detected") || has("found") || has("identified"));
    // "removing virus/malware/spyware" or "malware removed"
    let removal_action = (has("removing") || has("removed"))
        && (has("virus") || has("malware") || has("spyware") || has("threat") || has("infection"));
    // "repair in progress", "repairing your pc/system/computer"
    let repair_lure = (has("repair")
        && (has("progress") || has("your") || has("system") || has("computer") || has("pc")))
        || (has("repairing") && (has("system") || has("computer") || has("pc") || has("file")));
    // "system error detected", "critical system error"
    let system_error =
        has("system") && has("error") && (has("detected") || has("critical") || has("found"));

    // ── Japanese scan/threat-count/repair progress framing ───────────────
    // "スキャン中..." paired with a threat noun.
    let jp_scanning = has("スキャン中")
        && (has("ウイルス") || has("脅威") || has("マルウェア") || has("スパイウェア"));
    // "脅威が見つかりました / 脅威を検出 / N個のウイルスが検出".
    let jp_threat_count = (has("脅威") || has("ウイルス") || has("マルウェア"))
        && (has("見つかりました") || has("検出しました") || has("検出されました"));
    // "マルウェアを削除しています / ウイルスを駆除".
    let jp_removal = (has("削除しています") || has("駆除"))
        && (has("ウイルス") || has("マルウェア") || has("脅威"));
    // "システムを修復しています / 修復中".
    let jp_repair = (has("修復しています") || has("修復中"))
        && (has("システム") || has("pc") || has("コンピュータ") || has("ファイル"));

    scanning_lure
        || threat_count
        || removal_action
        || repair_lure
        || system_error
        || jp_scanning
        || jp_threat_count
        || jp_removal
        || jp_repair
}

/// Detect subscription/license expiry coercion in a normalized window title.
///
/// Lower-intensity scareware ("Your Norton subscription expired — renew now")
/// often retains a close button and scores low on geometry signals alone, so
/// the title text is the primary evidence.  THREAT_INTEL_2026 names this as
/// a distinct scareware family: "scareware subscription / prize scams".  Real
/// software expiry dialogs are user-initiated and closable; the `alert_shaped`
/// guard in `classify()` keeps them out of scope.
///
/// Pattern: (subscription OR license OR protection) AND (expired OR expiring
/// OR expire) AND (renew OR activate OR purchase OR buy OR click OR call).
/// All three word groups must be present to avoid FPs from legitimate renewal
/// reminder emails that get reflected as window titles.
#[must_use]
pub fn has_subscription_lure(s: &str) -> bool {
    let has = |a: &str| s.contains(a);
    let subject = has("subscription") || has("license") || has("protection") || has("membership");
    let expired = has("expired") || has("expiring") || has("expire") || has("expiration");
    let action = has("renew")
        || has("activate")
        || has("purchase")
        || has("buy")
        || has("call")
        || has("click");
    subject && expired && action
}

/// Detect law-enforcement / authority-impersonation language in a normalized
/// window title.
///
/// A class of ransomware-style bluff overlay ("Reveton", "Winlock") and
/// modern tech-support-scam spinoffs lock the screen and impersonate the
/// FBI, police, Interpol, Japanese NPA, or generic "cybercrime unit" to
/// coerce payment or a call.  Titles like "FBI WARNING: Your computer has
/// been locked" or "警察庁サイバー犯罪対策課から警告" (NPA Cybercrime
/// Department Warning).  No current signal catches this because:
///   - `brand_impersonation` checks URL *hosts*, not window titles.
///   - `fake_scanner_cue` covers rogue-AV language, not LEA language.
///   - `phone_number` fires only if a phone number is visible.
///
/// Pattern: an authority-agency token AND a coercion/action token.
/// Both English (FBI/CIA/Interpol/Europol/HMRC/AFP/etc.) and Japanese
/// (警察庁/警視庁/国税庁/消費者庁) agency names are recognized.  Japanese
/// coercion words (警告/違反/ブロック/罰金/逮捕/不正アクセス) are also checked.
/// The `alert_shaped` guard in `classify()` prevents browser tabs showing
/// news headlines ("FBI Warning: New Phishing Attack") from firing, as those
/// are user-initiated and closable.
///
/// Grounded in Symantec Threat Intelligence Reveton/Winlock analysis, FBI
/// IC3 2024 warning on law-enforcement impersonation scams, Europol
/// Operation Strikeback 2025 ransomware-overlay takedowns, and IPA Japan
/// (情報処理推進機構) reports on "サポート詐欺" (tech-support scam) and
/// "警察なりすまし詐欺" (police impersonation scam).
#[must_use]
pub fn has_authority_lure(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // ── English-language agency tokens ────────────────────────────────
    let agency_en = has("fbi")
        || has("cia")
        || has("interpol")
        || has("cybercrime")
        || has("homeland security")
        || has("department of justice")
        || has("national security")
        || has("metropolitan police")
        || has("cyber police")
        || has("law enforcement")
        || has("europol")
        || has("hmrc")                           // UK revenue/customs
        || has("national crime agency")          // UK NCA
        || has("australian federal police")
        || has("afp")                            // Australian Federal Police
        || has("bundeskriminalamt")              // German BKA
        || has("gendarmerie")                    // French Gendarmerie
        || has("internal revenue service")       // US IRS (FTC #2 government impersonator)
        || has("federal trade commission")       // US FTC impersonation
        || has("customs and border protection")  // US CBP impersonation
        || has("social security administration") // US SSA (complement to national_id_alarm)
        || has("secret service")                 // US Secret Service impersonation
        || has("drug enforcement"); // US DEA impersonation

    // ── Japanese-language agency tokens (preserved by normalize_for_match) ─
    // `normalize_for_match` uses `to_ascii_lowercase()` — CJK is untouched.
    let agency_jp = has("警察庁")      // National Police Agency
        || has("警視庁")               // Metropolitan Police Dept (Tokyo)
        || has("国税庁")               // National Tax Agency
        || has("消費者庁")             // Consumer Affairs Agency
        || has("公安委員会")           // Public Safety Commission
        || has("サイバー警察")         // Cyber Police (general)
        || has("デジタル警察")         // Digital Police (generic scam term)
        || has("内閣サイバー")         // Cabinet Cyber Security Center
        || has("財務省")               // Ministry of Finance
        || has("総務省")               // Ministry of Internal Affairs
        || has("法務省")               // Ministry of Justice (impersonated in "arrest warrant" scams)
        || has("検察庁")               // Public Prosecutors Office
        || has("最高裁"); // Supreme Court (fake "court order" scam)

    // ── English coercion / action tokens ─────────────────────────────
    let coercion_en = has("warning")
        || has("notice")
        || has("locked")
        || has("blocked")
        || has("suspended")
        || has("illegal")
        || has("violation")
        || has("fine")
        || has("penalty")
        || has("arrested")
        || has("warrant")   // arrest warrant language (IRS/police impersonation)
        || has("subpoena")  // court-order impersonation
        || has("indicted")  // criminal indictment framing
        || has("charges"); // "criminal charges" framing

    // ── Japanese coercion / action tokens ────────────────────────────
    let coercion_jp = has("警告")      // warning
        || has("違反")                 // violation
        || has("違法")                 // illegal
        || has("ブロック")             // blocked
        || has("ロック")               // locked
        || has("罰金")                 // fine
        || has("逮捕")                 // arrested
        || has("摘発")                 // crackdown
        || has("不正アクセス")         // unauthorized access
        || has("調査中")               // under investigation
        || has("凍結")                 // frozen (account)
        || has("令状")                 // warrant (arrest/search warrant scam)
        || has("差し押さえ")           // seizure / asset freeze
        || has("起訴"); // prosecution / indictment

    (agency_en || agency_jp) && (coercion_en || coercion_jp)
}

/// Detect screen-share / remote-viewing instruction lures in a normalized
/// window title.
///
/// A TSS variant that doesn't name a specific remote-access tool (already
/// caught by `remote_access_lure`) but instead instructs the victim to
/// share their screen with a "support agent": "share your screen with our
/// support team", "allow remote viewing to fix your computer", "enable
/// screen sharing now".  The `alert_shaped` guard in `classify()` keeps
/// legitimate WebRTC / Zoom screen-share prompts (user-initiated and
/// closable) from firing.
///
/// Pattern: a *share* token AND a *target* token (screen/desktop/display).
/// Combined with the agent/support vocabulary if present.
#[must_use]
pub fn has_screen_share_lure(s: &str) -> bool {
    let has = |a: &str| s.contains(a);
    // "share" or "sharing" paired with "screen", "desktop", or "display".
    let share_screen =
        (has("share") || has("sharing")) && (has("screen") || has("desktop") || has("display"));
    // "allow" or "enable" paired with "remote" (catch "allow remote viewing",
    // "enable remote access to fix").
    let remote_enable = (has("allow") || has("enable"))
        && has("remote")
        && (has("view") || has("access") || has("control") || has("fix"));
    // "grant" + "access" + "support" (catch "grant access to our support team").
    let grant_support =
        has("grant") && has("access") && (has("support") || has("agent") || has("technician"));
    share_screen || remote_enable || grant_support
}

/// Detect crypto / Web3 wallet-drain overlay lures (E19).
///
/// Three complementary AND-pair patterns (all run on the normalized title):
/// - **wallet_alarm**: a wallet-brand word paired with an alarm token
///   (compromised, hacked, flagged, suspended, unauthorized, suspicious activity).
/// - **wallet_coerce**: a connect/validate/verify action paired with a wallet brand.
/// - **seed_harvest**: a seed-phrase or private-key word paired with a request
///   token (verify, enter, confirm, required, provide).
///
/// The `alert_shaped` guard in `classify()` blocks news articles and educational
/// content that mention these words but appear in user-opened, closable browser tabs.
#[must_use]
pub fn has_crypto_drain_lure(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // wallet_alarm: wallet-brand word + alarm action
    let wallet_word = has("wallet")
        || has("metamask")
        || has("coinbase")
        || has("web3")
        || has("defi")
        || has("nft");
    let alarm_action = has("compromised")
        || has("hacked")
        || has("flagged")
        || has("suspended")
        || has("unauthorized")
        || (has("suspicious") && has("activity"));
    let wallet_alarm = wallet_word && alarm_action;

    // wallet_coerce: connect/validate/verify/link + wallet brand
    let coerce_verb = has("connect") || has("validate") || has("verify") || has("link");
    let wallet_coerce = coerce_verb && wallet_word;

    // seed_harvest: seed/recovery phrase or private key + request
    let seed_word = (has("seed") && has("phrase"))
        || (has("recovery") && has("phrase"))
        || (has("secret") && (has("phrase") || has("recovery")))
        || (has("private") && has("key"))
        || has("mnemonic");
    let request_token = has("verify")
        || has("enter")
        || has("confirm")
        || has("required")
        || has("provide")
        || has("submit");
    let seed_harvest = seed_word && request_token;

    wallet_alarm || wallet_coerce || seed_harvest
}

/// Detect fake prize / lottery / gift-card overlay lures (E20).
///
/// AND-pair pattern: a *prize word* paired with a *claim/collect action*.
/// - **prize_word**: "won", "winner", "prize", "jackpot", "lottery", "reward",
///   "gift card", "selected", "eligible" (the scam vocabulary).
/// - **claim_action**: "claim", "collect", "verify", "confirm", "redeem",
///   "click here", "expires", "before it expires" (the urgency or action cue).
///
/// The pair requirement prevents stand-alone words from firing: "you won a
/// personal record" has `won` but no claim action, so it stays silent. The
/// `alert_shaped` guard in `classify()` further prevents legitimate e-commerce
/// loyalty-points notifications that appear in user-initiated closable windows.
#[must_use]
pub fn has_prize_lure(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    let prize_word = has("won")
        || has("winner")
        || has("prize")
        || has("jackpot")
        || has("lottery")
        || has("reward")
        || has("gift card")
        || has("selected")
        || has("eligible");

    let claim_action = has("claim")
        || has("collect")
        || has("redeem")
        || has("verify")
        || has("confirm")
        || has("click here")
        || (has("expires") || has("expiring"));

    prize_word && claim_action
}

/// Detect fake download / fake-update overlay lures (E21).
///
/// Covers the "install X to continue" malware-delivery pattern distinct from
/// ClickFix (which targets the clipboard/Win+R path). Two AND-pair patterns:
/// - **install_demand**: a download/install/update verb + a required/needed cue.
/// - **fake_plugin_gate**: a plugin/extension/codec/player noun + an install cue,
///   with an optional "to continue viewing / to access / to play" framing.
///
/// The `alert_shaped` guard in `classify()` prevents legitimate browser
/// extension install prompts (user-initiated, closable) from firing.
#[must_use]
pub fn has_download_trap_lure(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // install_demand: download/install/update + required/needed/necessary
    let action_verb = has("download") || has("install") || has("update");
    let required_cue = has("required")
        || has("needed")
        || has("necessary")
        || has("to continue")
        || has("to access")
        || has("to view")
        || has("to play");
    let install_demand = action_verb && required_cue;

    // fake_plugin_gate: plugin/extension/codec/player noun + (install verb OR required cue)
    // Catches both "install codec to view" and "browser extension required for this page".
    let plugin_noun = has("plugin")
        || has("extension")
        || has("codec")
        || has("flash")
        || has("player")
        || has("software")
        || has("component")
        || has("add-on")
        || has("addon");
    let fake_plugin_gate = plugin_noun && (action_verb || required_cue);

    install_demand || fake_plugin_gate
}

/// E22 — QR code / "quishing" lure.
///
/// Scam overlays instruct the user to scan a QR code to "verify identity",
/// "continue", or "access" a resource — QR phishing ("quishing") is a major
/// 2025-2026 growth vector (APWG Q4 2024, FBI IC3 2025). The overlay pairs
/// a displayed QR image with urgency language; the title carries the cue.
///
/// alert_shaped guard is applied at the call site in `classify()`.  The AND-pair
/// prevents FPs on legitimate QR displays (ticket kiosks, payment flows).
#[must_use]
pub fn has_qr_code_lure(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // qr_noun: explicit "qr code" or "qr" paired with "scan"
    let qr_noun = has("qr code") || has("qr-code") || (has("qr") && has("scan"));

    // verify_action: cues that follow in a lure overlay title
    let verify_action = has("verify")
        || has("confirm")
        || has("authenticate")
        || has("access")
        || has("scan to")
        || has("scan now")
        || has("continue")
        || has("proceed")
        || has("validate");

    qr_noun && verify_action
}

/// E23 — IP / network alarm lure.
///
/// Scam overlays display "Your IP address has been hacked / flagged /
/// reported to authorities" to panic victims into calling a fake support
/// number. This is one of the most common tech-support scam templates
/// (Microsoft Security, Malwarebytes 2025). The signal is an IP subject
/// token combined with an alarm word.
///
/// alert_shaped guard applied at the call site.  The AND-pair prevents FPs
/// on legitimate network-status pages ("Your IP address is …").
#[must_use]
pub fn has_ip_alarm_lure(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // ip_subject: explicit "ip address" or "your ip" (network-identity framing)
    let ip_subject = has("ip address") || has("your ip");

    // alarm_word: attack/compromise language paired with the IP subject
    let alarm_word = has("hack")
        || has("infect")
        || has("flag")
        || has("report")
        || has("stolen")
        || has("expos")
        || has("compromis")
        || has("block")
        || has("detect")
        || has("trac")
        || has("suspend")
        || has("breach");

    ip_subject && alarm_word
}

/// E24 — Package / parcel customs-fee lure.
///
/// "Your package is on hold / your shipment requires a customs fee" overlays
/// impersonate DHL, FedEx, USPS, or customs authorities to extract a small
/// advance fee from the victim.  Imposter-scam delivery variants ranked #2 in
/// FTC 2024 consumer-fraud reports (1.1M complaints, $2.7B losses combined).
///
/// Two groups: package_noun (package/parcel/shipment/order/delivery) AND
/// fee_demand (fee/customs/held/pending/unable to deliver/pay).  The AND-pair
/// prevents single-word FPs ("your order shipped!", "delivery confirmed").
/// alert_shaped guard at the call site filters out legitimate e-commerce
/// order-tracking notifications, which are user-initiated and closable.
#[must_use]
pub fn has_package_fee_lure(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // package_noun: delivery-related subject tokens
    let package_noun = has("your package")
        || has("your parcel")
        || has("your shipment")
        || has("your order")
        || has("your delivery")
        || has("package is")
        || has("parcel is")
        || has("shipment is");

    // fee_demand: coercion / hold language that signals the fee-scam pattern
    let fee_demand = has("customs fee")
        || has("customs duty")
        || has("customs charge")
        || has("on hold")
        || (has("fee") && (has("pay") || has("required") || has("pending")))
        || has("unable to deliver")
        || has("failed delivery")
        || has("delivery fee")
        || has("release fee");

    package_noun && fee_demand
}

/// E25 — Sextortion / webcam recording extortion lure.
///
/// Scam overlays (and browser pop-unders) claim to have recorded the victim
/// via their webcam visiting an adult site, then demand cryptocurrency payment
/// to prevent the footage being sent to their contacts. FBI IC3 2024 sextortion
/// complaints grew 42% YoY; browser-based sextortion overlays are a growing
/// sub-vector.
///
/// Two groups: camera_cue ("your camera" / "your webcam" / "we have recorded" /
/// "have been recording") AND extortion_word (bitcoin/btc/cryptocurrency/
/// payment/pay/contacts/expose/release).  The AND-pair prevents FPs on
/// legitimate webcam-permission dialogs (no extortion_word) and on crypto
/// news articles (no camera_cue).
/// alert_shaped guard at the call site.
#[must_use]
pub fn has_sextortion_lure(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // camera_cue: webcam/recording evidence claim
    let camera_cue = has("your camera")
        || has("your webcam")
        || has("we have recorded")
        || has("have been recording")
        || has("we have footage")
        || has("recorded you")
        || has("hacked your camera")
        || has("accessed your camera");

    // extortion_word: payment demand or threat-to-expose language
    let extortion_word = has("bitcoin")
        || has("btc")
        || has("cryptocurrency")
        || has("crypto")
        || has("payment")
        || has("pay")
        || has("your contacts")
        || has("expose")
        || has("send this")
        || has("release this");

    camera_cue && extortion_word
}

/// E26 — Gift-card payment demand.
///
/// Tech-support and authority-impersonation scams routinely instruct victims
/// to purchase gift cards and read out (or type in) the redemption codes as
/// "payment" to unlock their device, pay a "fine", or settle a fabricated
/// debt.  The FTC reports gift cards as the #1 payment method in tech-support
/// fraud losses.  No legitimate software ever asks users to purchase or send
/// gift-card codes through an overlay.
///
/// Two groups (AND-pair):
/// - gift_card_noun: names a specific gift-card product or "gift card" /
///   "prepaid card" in general.
/// - payment_instruction: language that directs the victim to purchase, send,
///   or read out the codes (buy, purchase, send codes, scratch, etc.).
///
/// The AND-pair ensures plain gift-card redemption UIs (which have neither
/// a buy instruction nor a payment send instruction) do not fire.
/// alert_shaped guard at the call site prevents FPs on legitimate gift-card
/// store fronts (user-initiated, closable windows).
#[must_use]
pub fn has_gift_card_demand(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // gift_card_noun: specific card product names or generic "gift card"
    let gift_card_noun = has("gift card")
        || has("itunes card")
        || has("google play card")
        || has("steam gift card")
        || has("amazon gift card")
        || has("apple gift card")
        || has("ebay gift card")
        || has("vanilla card")
        || has("prepaid card")
        || has("gift cards");

    // payment_instruction: buy-or-send-codes language unique to the scam
    let payment_instruction = has("send codes")
        || has("send the codes")
        || has("read me the codes")
        || has("read the codes")
        || has("scratch the card")
        || has("pay using gift card")
        || has("pay with gift card")
        || has("pay in gift card")
        || has("gift card codes")
        || has("card codes")
        || has("purchase gift card")
        || has("buy gift card")
        || has("go buy")
        || has("go to the store")
        || has("nearest store");

    gift_card_noun && payment_instruction
}

/// E27 — Refund / overpayment scam lure.
///
/// "Refund scams" (also called overpayment scams) are among the top financial
/// fraud vectors per FTC 2024 and IC3 2025, particularly targeting elderly
/// users.  The scammer — posing as a support agent, bank, or government agency
/// — claims the victim is owed a refund or that funds were accidentally
/// deposited into their account and must be returned.  The overlay instructs
/// the user to call a number or click a button to "process the refund", at
/// which point the victim is coerced into handing over banking credentials or
/// gift-card codes.
///
/// Two groups (AND-pair):
/// - `refund_noun`: "refund", "overpayment", "reimbursement", "rebate",
///   "cashback", "excess charge", 返金, 払い戻し, 過払い, 補償金.
/// - `refund_action`: language that directs the victim to act to "collect" —
///   "owed to you", "claim your refund", "pending refund", "refund is ready",
///   "process your refund", 返金手続き, お手続きください, 返金が完了, 払い戻し手続き.
///
/// The AND-pair keeps plain store return-policy text ("refund within 30 days")
/// from firing: it has a refund noun but no claim-oriented action verb.
/// alert_shaped guard at the call site prevents FPs on legitimate bank portals
/// (user-initiated, closable windows).
#[must_use]
pub fn has_refund_scam_cue(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // refund_noun: named refund/overpayment concepts
    let refund_noun = has("refund")
        || has("overpayment")
        || has("reimbursement")
        || has("rebate")
        || has("cashback")
        || has("excess charge")
        || has("overcharged")
        || has("返金")
        || has("払い戻し")
        || has("過払い")
        || has("補償金");

    // refund_action: claim/collect/process language unique to the scam
    // (plain return-policy pages never say "owed to you" or "claim your refund")
    let refund_action = has("owed to you")
        || has("you are owed")
        || has("claim your refund")
        || has("collect your refund")
        || has("pending refund")
        || has("refund is ready")
        || has("refund has been")
        || has("process your refund")
        || has("transfer your refund")
        || has("your refund of")
        || has("refund amount")
        || has("receive your refund")
        || has("get your refund")
        || has("返金手続き")
        || has("払い戻し手続き")
        || has("返金が完了")
        || has("お手続きください")
        || has("ご返金")
        || has("返金いたします")
        || has("返金を受け取");

    refund_noun && refund_action
}

/// E28 — National ID / benefit-number alarm scam.
///
/// The US Social Security Administration (SSA) impersonation scam is the
/// single most common government-impersonation variant per FTC 2024.
/// Scammers call or display overlays claiming the victim's Social Security
/// Number (SSN) has been "suspended" or "used in criminal activity" — then
/// demand the victim call a number to "reactivate" it.  Analogous scams in
/// other jurisdictions target the UK National Insurance Number (NIN) and
/// Japan's My Number (マイナンバー) card and pension number.  No legitimate
/// government service ever suspends a national ID number via a browser
/// overlay or pop-up.
///
/// Two groups (AND-pair):
/// - `id_noun`: names a national ID number or benefit program: "social
///   security", "ssn", "national insurance number", "medicare", "medicaid",
///   マイナンバー, 個人番号, 基礎年金番号, 年金番号.
/// - `id_alarm`: suspension or criminal-use language unique to the scam:
///   "has been suspended", "used in criminal", "criminal activity",
///   "criminal charges", "fraudulent activity", "under federal investigation",
///   "identity theft detected", "has been compromised", 凍結, 不正使用/不正利用,
///   犯罪に使用, 捜査中, 停止されました.
///
/// The AND-pair prevents informational articles about "social security criminal
/// activity statistics" from firing.  The alert_shaped guard at the call site
/// prevents legitimate government-portal pages (user-initiated, closable) from
/// triggering.
#[must_use]
pub fn has_national_id_alarm(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // id_noun: national ID numbers and benefit programs
    let id_noun = has("social security number")
        || has("social security")
        || has("ssn")
        || has("national insurance number") // UK NIN
        || has("medicare")
        || has("medicaid")
        || has("マイナンバー")   // Japan My Number
        || has("個人番号")       // Individual number (JP)
        || has("基礎年金番号")   // Basic pension number (JP)
        || has("年金番号"); // Pension number (JP)

    // id_alarm: suspension/criminal-use language specific to the scam.
    // Plain news or policy pages have the noun but not these alarm phrases.
    let id_alarm = has("has been suspended")
        || has("is suspended")
        || has("was suspended")
        || has("has been blocked")
        || has("used in criminal")
        || has("criminal activity")
        || has("criminal charges")
        || has("criminal case")
        || has("fraudulent activity")
        || has("associated with fraud")
        || has("under federal investigation")
        || has("identity theft")
        || has("has been compromised")
        || has("凍結")        // frozen (account/number)
        || has("不正使用")    // fraudulent use
        || has("不正利用")    // unauthorized use
        || has("犯罪に使用")  // used in crime
        || has("捜査中")      // under investigation
        || has("停止されました"); // has been suspended (JP formal)

    id_noun && id_alarm
}

/// E29 — Fake bank-fraud alert overlay.
///
/// Scammers impersonating banks or payment processors display an alert-shaped
/// overlay claiming a victim's bank account or card has been frozen or has
/// experienced fraudulent/unauthorized transactions.  The overlay prompts the
/// victim to call a number (often also on-screen, caught by `phone_number`) or
/// click a button to "unfreeze" the account, leading to credential theft or
/// gift-card payment demands.
///
/// This is distinct from `credential_harvest_cue` (which requires a credential-
/// entry instruction) and `national_id_alarm` (which targets national ID
/// numbers): `has_bank_account_alarm` fires when banking-specific account/card
/// language appears with a freeze/fraud alarm, even when no credential entry
/// instruction is present — the attacker only wants the victim to call.
///
/// Two groups (AND-pair):
/// - `bank_noun`: banking-specific terms — "bank account", "checking account",
///   "savings account", "debit card", "credit card", "your account at",
///   銀行口座, キャッシュカード, 通帳, クレジットカード, デビットカード.
/// - `bank_alarm`: fraud/freeze language — "unauthorized transaction",
///   "fraudulent transaction", "suspicious transaction", "fraudulent charge",
///   "has been frozen", "fraudulent access", "unauthorized access detected",
///   不正な取引, 不審な取引, 口座が停止, 口座が凍結, 不正アクセスを検知.
///
/// The AND-pair ensures a screen that merely says "check your credit card
/// statement" (no alarm) or "suspicious activity reported" (no bank noun)
/// does not fire.  The alert_shaped guard at the call site prevents legitimate
/// bank-app notifications (user-initiated, closable) from triggering.
#[must_use]
pub fn has_bank_account_alarm(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // bank_noun: banking-specific account/card terms
    let bank_noun = has("bank account")
        || has("checking account")
        || has("savings account")
        || has("debit card")
        || has("credit card")
        || has("your account at")
        || has("銀行口座")     // bank account (JP)
        || has("キャッシュカード") // cash card (JP)
        || has("通帳")          // bankbook / passbook (JP)
        || has("クレジットカード") // credit card (JP)
        || has("デビットカード"); // debit card (JP)

    // bank_alarm: fraud/freeze language unique to this scam pattern
    let bank_alarm = has("unauthorized transaction")
        || has("fraudulent transaction")
        || has("suspicious transaction")
        || has("fraudulent charge")
        || has("has been frozen")
        || has("account has been frozen")
        || has("access has been restricted")
        || has("fraudulent access")
        || has("unauthorized access detected")
        || has("不正な取引")     // unauthorized transaction (JP)
        || has("不審な取引")     // suspicious transaction (JP)
        || has("口座が停止")     // account suspended (JP)
        || has("口座が凍結")     // account frozen (JP)
        || has("不正アクセスを検知"); // unauthorized access detected (JP)

    bank_noun && bank_alarm
}

/// E30 — ワンクリック詐欺 / false-registration billing scam.
///
/// Detects overlays that falsely claim the user has **registered** for a paid
/// service and demand immediate payment or face legal action — the classic
/// JP "one-click fraud" (ワンクリック詐欺) template.  Distinct from
/// `has_subscription_lure` (which targets *expired* subscriptions) in that
/// E30 targets *false creation* of a new obligation.
///
/// AND-pair design:
/// - `reg_claim`: language asserting registration happened —
///   "you have been registered", "your registration", "membership confirmed",
///   "you signed up", "registration complete", "your subscription has been
///   activated", 登録が完了, 会員登録が完了, ご入会, ご登録.
/// - `payment_ultimatum`: urgency / coercion language demanding payment —
///   "pay within", "outstanding fee", "registration fee", "legal action",
///   "failure to pay", "penalty fee", "collection agency",
///   法的措置, お支払い期限, 期限内, 未払い, 延滞, ご入金.
///
/// The AND-pair prevents legitimate "thanks for registering!" confirmation
/// pages (no payment ultimatum) from firing.  The alert_shaped guard at the
/// call site prevents user-initiated, closable confirmations from triggering.
#[must_use]
pub fn has_false_registration_billing(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // reg_claim: language asserting a new registration/membership was created
    let reg_claim = has("you have been registered")
        || has("your registration")
        || has("membership confirmed")
        || has("you signed up")
        || has("registration complete")
        || has("your subscription has been activated")
        || has("registration is complete")
        || has("your account has been created")
        || has("successfully registered")
        || has("enrollment confirmed")
        || has("enrollment is complete")
        || has("登録が完了")      // registration is complete (JP)
        || has("会員登録が完了") // member registration complete (JP)
        || has("ご入会")          // membership enrollment (JP)
        || has("ご登録")          // your registration (JP)
        || has("登録されました")  // you have been registered (JP)
        || has("会員登録されました"); // member registration done (JP)

    // payment_ultimatum: urgency / legal coercion demanding payment
    let payment_ultimatum = has("pay within")
        || has("outstanding fee")
        || has("registration fee")
        || has("legal action")
        || has("failure to pay")
        || has("penalty fee")
        || has("collection agency")
        || has("sent to collections")
        || has("debt collection")
        || has("overdue balance")
        || has("amount due")
        || has("settle your balance")
        || has("法的措置")  // legal action (JP)
        || has("お支払い期限") // payment deadline (JP)
        || has("期限内にお支払い") // pay within deadline (JP)
        || has("未払い")    // unpaid / outstanding (JP)
        || has("延滞")      // overdue / delinquency (JP)
        || has("ご入金")    // please remit payment (JP)
        || has("ご請求金額") // billed amount (JP)
        || has("請求書")    // invoice / bill (JP)
        || has("督促"); // payment reminder / dunning notice (JP)

    reg_claim && payment_ultimatum
}

/// E31 — fake BSOD / "Windows has been blocked" tech-support scam overlay.
///
/// Detects the well-documented tech-support scam pattern where an overlay
/// mimics a Windows Blue Screen of Death (BSOD) or macOS kernel panic,
/// displaying Windows error codes (e.g., "Stop Code: MEMORY_MANAGEMENT") and
/// urging the victim to call a fake Microsoft/Apple support number immediately.
/// Distinct from `has_fake_scanner_cue` (which targets rogue-AV scanning
/// progress) — E31 targets the OS-impersonation / kiosk-lock variant where the
/// attacker mimics a system crash page.
///
/// AND-pair design:
/// - `bsod_marker`: language specific to OS crash / blocked-screen impersonation —
///   "windows has been blocked", "windows is blocked", "your pc is blocked",
///   "stop code", "memory_management", "kmode exception", "kernel security check",
///   "irql not less", "dpc watchdog", "blue screen", "kernel panic",
///   Windowsがブロック, PCがブロック, カーネルパニック.
/// - `call_barrier`: scam-specific call-to-action around the fake error —
///   "do not restart", "do not turn off", "do not close this",
///   "call microsoft", "contact microsoft", "microsoft support",
///   "microsoft certified", "windows helpline",
///   再起動しないでください, マイクロソフトサポート, テクニカルサポート.
///
/// The AND-pair ensures low FP risk: legitimate Windows BSODs never instruct
/// users to "call Microsoft" by phone, and windows that merely mention
/// "blue screen" without a call barrier (e.g., IT blog articles) do not fire.
/// The alert_shaped guard at the call site handles the geometry dimension.
#[must_use]
pub fn has_fake_bsod_lure(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // bsod_marker: OS crash impersonation / blocked-screen language
    let bsod_marker = has("windows has been blocked")
        || has("windows is blocked")
        || has("your pc is blocked")
        || has("your computer is blocked")
        || has("this pc is blocked")
        || has("stop code")       // Windows BSOD stop-code field
        || has("memory_management") // Windows BSOD error name
        || has("kmode exception") // "KMODE_EXCEPTION_NOT_HANDLED"
        || has("kernel security check") // "KERNEL_SECURITY_CHECK_FAILURE"
        || has("irql not less")   // "IRQL_NOT_LESS_OR_EQUAL"
        || has("dpc watchdog")    // "DPC_WATCHDOG_VIOLATION"
        || has("blue screen")     // describing the BSOD screen
        || has("kernel panic")    // macOS crash equivalent
        || has("critical process died") // Windows BSOD message
        || has("system thread exception") // Windows BSOD
        || has("ブルースクリーン")  // blue screen (JP)
        || has("windowsがブロック") // Windows is blocked (JP, case-folded)
        || has("pcがブロック")      // PC is blocked (JP, case-folded)
        || has("カーネルパニック"); // kernel panic (JP)

    // call_barrier: scam-specific instruction attached to the fake crash
    let call_barrier = has("do not restart")
        || has("do not turn off")
        || has("do not close this")
        || has("do not shut down")
        || has("call microsoft")
        || has("contact microsoft")
        || has("microsoft support")
        || has("microsoft certified")
        || has("microsoft technician")
        || has("windows helpline")
        || has("windows support line")
        || has("microsoft help desk")
        || has("apple support")       // macOS kernel-panic equivalent
        || has("apple certified")
        || has("再起動しないでください") // do not restart (JP)
        || has("シャットダウンしないで") // do not shut down (JP)
        || has("マイクロソフトサポート") // Microsoft support (JP)
        || has("マイクロソフト認定")    // Microsoft certified (JP)
        || has("テクニカルサポートに電話"); // call technical support (JP)

    bsod_marker && call_barrier
}

/// E32 — advance-fee fraud / "419" / inheritance / unclaimed-funds scam.
///
/// Detects overlays that falsely claim the victim has inherited a large sum,
/// won a lottery, or has unclaimed funds, then require payment of an "advance
/// fee" (processing, transfer, customs, notary) to release those funds.
/// Distinct from `has_prize_lure` (which targets click-to-claim prize lures)
/// because E32 specifically requires the *fee extraction* component alongside
/// the windfall claim — a hallmark of the advance-fee fraud taxonomy
/// (FTC BCP 2024 "Money you didn't expect" category, FBI IC3 2025).
///
/// AND-pair design:
/// - `fund_claim`: windfall framing — "inheritance", "inherited", "beneficiary",
///   "estate of", "deceased", "unclaimed funds", "unclaimed inheritance",
///   "lottery winning", "won the lottery", "trust fund", "prize fund",
///   遺産, 受益者, 未請求の資産, 宝くじ当選.
/// - `release_fee`: fee-extraction demand — "processing fee", "transfer fee",
///   "customs fee", "release fee", "administration fee", "advance fee",
///   "notary fee", "legal fee required", "to release the funds",
///   "to receive your funds", "to claim your inheritance",
///   手数料, 振込手数料, 関税, リリース手数料.
///
/// The AND-pair prevents legitimate estate-attorney sites (fund_claim, no fee)
/// and legitimate customs pages (release_fee, no windfall claim) from firing.
/// The alert_shaped guard at the call site ensures user-initiated legitimate
/// notifications never trigger.
#[must_use]
pub fn has_advance_fee_lure(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // fund_claim: windfall assertion — inheritance, lottery, unclaimed funds
    let fund_claim = has("inheritance")
        || has("inherited")
        || has("beneficiary")
        || has("estate of")
        || has("deceased")
        || has("unclaimed funds")
        || has("unclaimed inheritance")
        || has("unclaimed assets")
        || has("lottery winning")
        || has("won the lottery")
        || has("trust fund")
        || has("prize fund")
        || has("next of kin")
        || has("遺産")          // inheritance (JP)
        || has("受益者")        // beneficiary (JP)
        || has("未請求の資産") // unclaimed assets (JP)
        || has("宝くじ当選")   // lottery win (JP)
        || has("相続財産"); // inherited estate (JP)

    // release_fee: advance-fee extraction demand
    let release_fee = has("processing fee")
        || has("transfer fee")
        || has("customs fee")
        || has("release fee")
        || has("administration fee")
        || has("advance fee")
        || has("notary fee")
        || has("legal fee")
        || has("handling fee")
        || has("to release the funds")
        || has("to receive your funds")
        || has("to claim your inheritance")
        || has("to claim your prize")
        || has("to unlock your funds")
        || has("手数料")        // fee / handling charge (JP)
        || has("振込手数料")   // wire transfer fee (JP)
        || has("関税")          // customs fee (JP)
        || has("リリース手数料") // release fee (JP)
        || has("受け取るには手数料"); // fee to receive (JP)

    fund_claim && release_fee
}

/// E33 — fake tech-support invoice / "you were charged" cancel-scam.
///
/// Detects the increasingly prevalent attack pattern where an overlay claims
/// a large charge (e.g., $399 McAfee renewal, $499 Microsoft support plan,
/// $549 Amazon Prime) was processed on the victim's account and urges them to
/// "call to cancel" — connecting them to a fake support number.  Distinct from:
/// - `subscription_lure` (targets *expired* subscriptions — no charge claimed)
/// - `false_registration_billing` (targets *false registration* + pay-or-face-consequences)
/// - `refund_scam_cue` (targets claiming a refund is owed to the victim)
///
/// AND-pair design:
/// - `charge_claim`: language asserting a charge was already processed —
///   "you have been charged", "a charge of", "an invoice for", "your account
///   has been charged", "payment of $", "auto-charged", "billing confirmation",
///   "subscription has been renewed", "renewal charge", "order #",
///   ご請求が完了, 課金されました, お引き落とし, 自動更新料金.
/// - `cancel_cta`: call-to-cancel / dispute instruction —
///   "call to cancel", "to cancel call", "if you did not authorize",
///   "unauthorized charge", "dispute this charge", "contact billing",
///   "cancel this subscription", "to report fraud call", "to reverse this",
///   キャンセルするには電話, 不正な請求, お問い合わせください, 解約電話.
///
/// The AND-pair ensures legitimate invoice emails reflected as window titles
/// (charge_claim, no cancel_cta) and legitimate help-desk pages ("call us to
/// cancel", no charge claim) do not fire.  alert_shaped guard prevents
/// user-initiated invoice viewing sessions from triggering.
#[must_use]
pub fn has_tech_support_invoice_scam(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // charge_claim: asserts a charge was already processed
    let charge_claim = has("you have been charged")
        || has("a charge of")
        || has("an invoice for")
        || has("your account has been charged")
        || has("payment of $")
        || has("auto-charged")
        || has("billing confirmation")
        || has("subscription has been renewed")
        || has("renewal charge")
        || has("auto renewal of")
        || has("order confirmation")
        || has("has been debited")
        || has("was charged to your account")
        || has("ご請求が完了")   // billing is complete (JP)
        || has("課金されました") // you have been charged (JP)
        || has("お引き落とし")   // account deduction / direct debit (JP)
        || has("自動更新料金")   // auto-renewal charge (JP)
        || has("ご請求金額が確定"); // billing amount confirmed (JP)

    // cancel_cta: call-to-cancel / dispute urgency
    let cancel_cta = has("call to cancel")
        || has("to cancel call")
        || has("if you did not authorize")
        || has("if you did not make this")
        || has("unauthorized charge")
        || has("dispute this charge")
        || has("contact billing")
        || has("cancel this subscription")
        || has("to report fraud call")
        || has("to reverse this charge")
        || has("to cancel this order")
        || has("did not approve this")
        || has("キャンセルするには電話")  // to cancel, call (JP)
        || has("不正な請求")              // unauthorized charge (JP)
        || has("ご解約はお電話")          // to cancel by phone (JP)
        || has("解約の手続き")            // cancellation procedure (JP)
        || has("請求に心当たりのない"); // unrecognized charge (JP)

    charge_claim && cancel_cta
}

/// E34 — fake utility disconnection threat scam.
///
/// Detects overlays that impersonate a utility company (electric, gas, water)
/// and threaten immediate service disconnection unless payment is made right
/// away.  FTC 2024 lists utility impersonation as the #3 impostor-scam type
/// by report volume; IC3 2025 notes these scams often deploy full-screen
/// overlays mimicking official utility notices.
///
/// AND-pair design:
/// - `utility_service`: names the utility/public service being threatened —
///   "electric service", "electricity", "gas service", "water service",
///   "power company", "utility account", "electric company", "your power",
///   電気, ガス, 水道, 電力, 公共料金, 電気代.
/// - `cutoff_threat`: termination / disconnection language —
///   "will be disconnected", "will be shut off", "disconnection notice",
///   "service termination", "final notice", "pay to avoid disconnection",
///   "service will be terminated", "disconnected within", "your service has
///   been suspended", "pay immediately to restore",
///   停止予告, 供給停止, 料金未払い, 即時お支払い, 強制停止.
///
/// The AND-pair prevents legitimate utility account pages (utility_service, no
/// threat) and generic "final notice" debt-collection pages (cutoff_threat, no
/// utility noun) from firing.  The alert_shaped guard at the call site handles
/// the geometry dimension.
#[must_use]
pub fn has_utility_cutoff_threat(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // utility_service: names the targeted public service
    let utility_service = has("electric service")
        || has("electricity")
        || has("gas service")
        || has("water service")
        || has("power company")
        || has("utility account")
        || has("electric company")
        || has("your power")
        || has("your electricity")
        || has("your gas")
        || has("natural gas service")
        || has("電気")      // electricity (JP)
        || has("ガス")      // gas (JP)
        || has("水道")      // water/plumbing (JP)
        || has("電力")      // electric power (JP)
        || has("公共料金") // public utility bill (JP)
        || has("電気代"); // electricity bill (JP)

    // cutoff_threat: disconnection / termination urgency language
    let cutoff_threat = has("will be disconnected")
        || has("will be shut off")
        || has("disconnection notice")
        || has("service termination")
        || has("final notice")
        || has("pay to avoid disconnection")
        || has("service will be terminated")
        || has("disconnected within")
        || has("your service has been suspended")
        || has("pay immediately to restore")
        || has("immediate payment required")
        || has("avoid disconnection")
        || has("停止予告")  // disconnection notice (JP)
        || has("供給停止") // supply terminated (JP)
        || has("料金未払い") // unpaid utility bill (JP)
        || has("即時お支払い") // immediate payment (JP)
        || has("強制停止"); // forced termination (JP)

    utility_service && cutoff_threat
}

/// E35 — healthcare / Medicare benefit scam.
///
/// Detects overlays that impersonate Medicare, Medicaid, or insurance
/// providers and lure victims (typically elderly) into calling a fake
/// number by claiming a benefit is expiring, a "free" medical device is
/// available, or that they have been "approved" for a benefit.  Medicare
/// fraud is the #1 IC3 2025 elder-fraud category; FTC 2024 reports it as
/// the leading impostor-scam type by dollar loss for victims over 60.
///
/// AND-pair design:
/// - `health_benefit`: names the healthcare/insurance program being targeted —
///   "medicare", "medicaid", "health insurance", "medical coverage",
///   "prescription benefit", "health plan", "your benefits", "medical device",
///   "insurance plan", 健康保険, 医療保険, 介護保険, 保険証, 国民健康保険.
/// - `benefit_urgency`: expiry, approval, or "free" urgency language —
///   "will expire", "expiring soon", "is about to expire", "claim your free",
///   "you have been approved", "qualify for free", "enrollment period ends",
///   "your benefits have been approved", "limited time offer", "call to claim",
///   "at no cost", "free of charge", "受給期限", "期限切れ", "無料で受け取る",
///   "申請期限", "給付が承認".
///
/// The AND-pair prevents legitimate insurance company sites (health_benefit,
/// no urgency) and generic "limited time offer" popups (no health term) from
/// firing.  The alert_shaped guard at the call site ensures user-initiated
/// Medicare portal sessions never trigger.
#[must_use]
pub fn has_healthcare_scam(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // health_benefit: names the healthcare/insurance program targeted
    let health_benefit = has("medicare")
        || has("medicaid")
        || has("health insurance")
        || has("medical coverage")
        || has("prescription benefit")
        || has("health plan")
        || has("your benefits")
        || has("medical device")
        || has("insurance plan")
        || has("dental coverage")
        || has("vision coverage")
        || has("healthcare plan")
        || has("health coverage")
        || has("健康保険")   // health insurance (JP)
        || has("医療保険")   // medical insurance (JP)
        || has("介護保険")   // nursing-care insurance (JP)
        || has("保険証")     // insurance card (JP)
        || has("国民健康保険"); // national health insurance (JP)

    // benefit_urgency: expiry, approval, or "free" claim urgency
    let benefit_urgency = has("will expire")
        || has("expiring soon")
        || has("is about to expire")
        || has("claim your free")
        || has("you have been approved")
        || has("qualify for free")
        || has("enrollment period ends")
        || has("your benefits have been approved")
        || has("limited time offer")
        || has("call to claim")
        || has("at no cost to you")
        || has("free of charge")
        || has("no cost to you")
        || has("receive at no cost")
        || has("受給期限")   // benefit-claim deadline (JP)
        || has("期限切れ")   // expired / about to expire (JP)
        || has("無料で受け取る") // receive for free (JP)
        || has("申請期限")   // application deadline (JP)
        || has("給付が承認"); // benefit has been approved (JP)

    health_benefit && benefit_urgency
}

/// E36 — fake job / work-from-home scam (employment fraud with advance fee).
///
/// Detects overlays that advertise a remote job or work-from-home opportunity
/// but require the victim to pay an upfront fee — a "registration fee",
/// "equipment deposit", "starter kit purchase", or "background check fee" —
/// before starting work.  Employment fraud is a top-5 IC3 2025 non-elder-fraud
/// loss category and the FTC 2024 #1 business-opportunity fraud type.
///
/// AND-pair design:
/// - `job_offer`: language advertising the remote/flexible work opportunity —
///   "work from home", "remote work opportunity", "earn from home",
///   "make money from home", "part time job", "data entry job",
///   "flexible work", "easy money", "job offer", "hiring now",
///   在宅ワーク, 副業, テレワーク求人, 在宅アルバイト.
/// - `fee_gate`: advance-fee extraction attached to the job offer —
///   "registration fee", "equipment deposit", "background check fee",
///   "starter kit", "training fee", "materials fee", "buy kit to start",
///   "purchase equipment", "pay to start", "upfront fee", "refundable deposit",
///   登録料, 機材費, 保証金, 入会金, 初期費用.
///
/// The AND-pair ensures legitimate job-board pages (job_offer, no fee) and
/// legitimate equipment-purchase pages (fee, no job offer) do not fire.
/// The alert_shaped guard at the call site prevents user-initiated job
/// application pages from triggering.
#[must_use]
pub fn has_job_scam(s: &str) -> bool {
    let has = |a: &str| s.contains(a);

    // job_offer: advertisement of remote / flexible work
    let job_offer = has("work from home")
        || has("remote work opportunity")
        || has("earn from home")
        || has("make money from home")
        || has("part time job")
        || has("data entry job")
        || has("flexible work")
        || has("easy money opportunity")
        || has("job offer")
        || has("hiring now")
        || has("position available")
        || has("work at home")
        || has("online job")
        || has("在宅ワーク")  // work-from-home (JP)
        || has("副業")        // side job / secondary income (JP)
        || has("テレワーク")  // telework / remote work (JP)
        || has("在宅アルバイト") // work-from-home part-time (JP)
        || has("内職"); // piecework / home-based work (JP)

    // fee_gate: advance-fee extraction attached to the job offer
    let fee_gate = has("registration fee")
        || has("equipment deposit")
        || has("background check fee")
        || has("starter kit")
        || has("training fee")
        || has("materials fee")
        || has("buy kit to start")
        || has("purchase equipment")
        || has("pay to start")
        || has("upfront fee")
        || has("refundable deposit")
        || has("security deposit")
        || has("kit fee")
        || has("登録料")  // registration fee (JP)
        || has("機材費") // equipment cost (JP)
        || has("保証金") // security deposit (JP)
        || has("入会金") // membership/entrance fee (JP)
        || has("初期費用"); // initial cost / setup fee (JP)

    job_offer && fee_gate
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

    // ── strip_symbols_and_emoji ───────────────────────────────────────────

    #[test]
    fn strips_warning_emoji_from_title() {
        // ⚠️ (U+26A0 + variation selector) stripped; word is reunited.
        assert_eq!(
            strip_symbols_and_emoji("inf\u{26A0}\u{FE0F}ected"),
            "infected"
        );
        assert_eq!(
            strip_symbols_and_emoji("⚠️ your computer is infected ⚠️"),
            " your computer is infected "
        );
    }

    #[test]
    fn strips_dingbat_mid_word() {
        // ✗ (U+2717, Dingbats) inserted mid-word.
        assert_eq!(strip_symbols_and_emoji("inf\u{2717}ected"), "infected");
    }

    #[test]
    fn strips_emoji_pictographs() {
        // 🔴 (U+1F534) and 🚨 (U+1F6A8) stripped.
        assert_eq!(
            strip_symbols_and_emoji("🚨 warning: your system is at risk 🔴"),
            " warning: your system is at risk "
        );
    }

    #[test]
    fn strips_symbols_leaves_japanese_intact() {
        // Japanese kana and CJK pass through unaltered.
        let jp = "ウイルスに感染しました";
        assert_eq!(strip_symbols_and_emoji(jp), jp);
        // Mixed: emoji stripped, Japanese intact.
        assert_eq!(
            strip_symbols_and_emoji("⚠️ ウイルスに感染 ⚠️"),
            " ウイルスに感染 "
        );
    }

    #[test]
    fn strip_symbols_leaves_plain_ascii() {
        let s = "your computer is infected call 1-800-555-0100";
        assert_eq!(strip_symbols_and_emoji(s), s);
    }

    #[test]
    fn normalize_for_match_collapses_mid_word_emoji() {
        // ⚠️ inserted between letters: pipeline produces "infected"
        assert_eq!(normalize_for_match("inf\u{26A0}\u{FE0F}ected"), "infected");
        // Combination: warning emoji + zero-width + Cyrillic homoglyph + leet
        assert_eq!(
            normalize_for_match("⚠️ Y\u{200B}our C\u{043E}mputer is 1nfected ⚠️"),
            " your computer is infected "
        );
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

    // ── digit_system / has_mixed_number_systems ──────────────────

    #[test]
    fn digit_system_classifies_known_blocks() {
        assert_eq!(digit_system('5'), Some(0)); // ASCII
        assert_eq!(digit_system('\u{FF15}'), Some(0)); // full-width ５ == ASCII system
        assert_eq!(digit_system('\u{0665}'), Some(1)); // Arabic-Indic ٥
        assert_eq!(digit_system('\u{06F5}'), Some(2)); // Ext Arabic-Indic ۵
        assert_eq!(digit_system('a'), None); // letter, not a digit
        assert_eq!(digit_system('-'), None);
    }

    #[test]
    fn mixed_number_systems_fires_on_cross_script_digits() {
        // ASCII 1 + Arabic-Indic ٥ in one token → mixed.
        assert!(has_mixed_number_systems("call1\u{0665}00"));
        // ASCII + Extended Arabic-Indic.
        assert!(has_mixed_number_systems("9\u{06F9}"));
    }

    #[test]
    fn mixed_number_systems_does_not_fire_on_single_system() {
        // Pure ASCII phone number.
        assert!(!has_mixed_number_systems("call 1-800-555-0100"));
        // Pure Arabic-Indic digits.
        assert!(!has_mixed_number_systems("\u{0661}\u{0662}\u{0663}"));
        // JP FP guard: full-width digits + ASCII = same system → no fire.
        assert!(!has_mixed_number_systems("\u{FF11}\u{FF12} 34"));
        // Two systems in *separate* tokens do not fire (per-token check).
        assert!(!has_mixed_number_systems("5 \u{0665}"));
    }

    // ── is_combining_mark / has_excessive_combining_marks ─────────

    #[test]
    fn combining_mark_classification() {
        assert!(is_combining_mark('\u{0301}')); // combining acute accent
        assert!(is_combining_mark('\u{20DD}')); // combining enclosing circle
        assert!(!is_combining_mark('a'));
        assert!(!is_combining_mark('5'));
    }

    #[test]
    fn excessive_combining_marks_fires_on_zalgo() {
        // 'e' + 4 stacked combining marks → Zalgo.
        assert!(has_excessive_combining_marks(
            "e\u{0301}\u{0302}\u{0303}\u{0304}"
        ));
        // Exactly 3 in a row → fires (threshold).
        assert!(has_excessive_combining_marks("a\u{0300}\u{0301}\u{0302}"));
    }

    #[test]
    fn excessive_combining_marks_does_not_fire_on_normal_diacritics() {
        // Plain ASCII — no combining marks at all.
        assert!(!has_excessive_combining_marks("your computer is infected"));
        // A single combining mark (legitimate decomposed accent).
        assert!(!has_excessive_combining_marks("e\u{0301}"));
        // Two combining marks (Vietnamese-style stacking) — still under threshold.
        assert!(!has_excessive_combining_marks("a\u{0302}\u{0301}"));
        // Precomposed accented text never fires (no combining chars).
        assert!(!has_excessive_combining_marks("café résumé naïve"));
    }

    // ── has_clickfix_instruction ───────────────────────────────────

    #[test]
    fn clickfix_fires_on_keyboard_shortcut() {
        // Core ClickFix lure: press Win+R to open Run.
        assert!(has_clickfix_instruction("press win+r to continue"));
        assert!(has_clickfix_instruction("press windows + r then paste"));
        assert!(has_clickfix_instruction("click verify then press ctrl+v"));
    }

    #[test]
    fn clickfix_fires_on_captcha_framing() {
        // Fake-CAPTCHA framing patterns.
        assert!(has_clickfix_instruction("verify you are human"));
        assert!(has_clickfix_instruction("confirm you are human"));
        assert!(has_clickfix_instruction("i am not a robot"));
        assert!(has_clickfix_instruction("complete captcha to continue"));
    }

    #[test]
    fn clickfix_fires_on_run_cmd_phrases() {
        // Run-dialog / command-execution instructions.
        assert!(has_clickfix_instruction("open run dialog and type"));
        assert!(has_clickfix_instruction("paste the command into terminal"));
        assert!(has_clickfix_instruction("type the command shown below"));
    }

    #[test]
    fn clickfix_does_not_fire_on_plain_text() {
        // Ordinary window titles — no instruction patterns.
        assert!(!has_clickfix_instruction("your computer is infected"));
        assert!(!has_clickfix_instruction("virus alert from microsoft"));
        assert!(!has_clickfix_instruction("your subscription has expired"));
        // "human" or "verify" alone is not enough.
        assert!(!has_clickfix_instruction("human resources portal"));
        assert!(!has_clickfix_instruction("verify email address"));
    }

    #[test]
    fn clickfix_defeats_leet_evasion_via_normalize() {
        // Leet-folded through normalize_for_match before calling.
        let leet = normalize_for_match("v3r1fy you are hum4n");
        assert_eq!(leet, "verify you are human");
        assert!(has_clickfix_instruction(&leet));
    }

    #[test]
    fn glitchfix_patterns_fire() {
        // GlitchFix / CrashFix browser-error variants (Huntress Jan 2026).
        assert!(has_clickfix_instruction("browser stopped abnormally"));
        assert!(has_clickfix_instruction("your browser stopped working"));
        assert!(has_clickfix_instruction("system font required to continue"));
        assert!(has_clickfix_instruction("font missing please install"));
        assert!(has_clickfix_instruction("update your browser to continue"));
        assert!(has_clickfix_instruction("system font needs updating"));
    }

    #[test]
    fn glitchfix_does_not_fire_on_benign_browser_text() {
        // "browser" or "font" alone without the lure pairing does not fire.
        assert!(!has_clickfix_instruction("open browser settings"));
        assert!(!has_clickfix_instruction("change font size"));
        assert!(!has_clickfix_instruction("check for browser update"));
    }

    // ── has_urgency_countdown ─────────────────────────────────────

    #[test]
    fn urgency_countdown_fires_on_scam_patterns() {
        // "expires in M:SS" — single-digit minutes + urgency keyword.
        assert!(has_urgency_countdown("your session expires in 5:00"));
        // "critical" urgency with MM:SS.
        assert!(has_urgency_countdown("system critical error 02:59"));
        // "infected" + countdown.
        assert!(has_urgency_countdown(
            "your computer infected 1:30 call now"
        ));
        // "support" as urgency keyword.
        assert!(has_urgency_countdown("call support immediately 0:30"));
        // "threat" keyword + countdown.
        assert!(has_urgency_countdown("threat detected 59:59"));
        // "warn" prefix inside a word.
        assert!(has_urgency_countdown("warning system locked 3:00"));
    }

    #[test]
    fn urgency_countdown_does_not_fire_without_urgency_keyword() {
        // Countdown present but no scam urgency word.
        assert!(!has_urgency_countdown("next update in 5:00"));
        assert!(!has_urgency_countdown("meeting at 12:30 today"));
        assert!(!has_urgency_countdown("video 1:45 remaining"));
    }

    #[test]
    fn urgency_countdown_does_not_fire_without_countdown_pattern() {
        // Urgency keyword present but no countdown.
        assert!(!has_urgency_countdown("your computer is infected"));
        assert!(!has_urgency_countdown("critical system error"));
        assert!(!has_urgency_countdown("call support now"));
    }

    #[test]
    fn urgency_countdown_does_not_fire_on_port_numbers() {
        // Port-style "host:8080" has 4 digits right of colon → rejected.
        assert!(!has_urgency_countdown("alert server infected:8080"));
        // 3 digits right → also rejected.
        assert!(!has_urgency_countdown("warn system error:123"));
    }

    #[test]
    fn urgency_countdown_defeats_leet_via_normalize() {
        // "3xp1r3s" → "expires" after normalize_for_match.
        let norm = normalize_for_match("3xp1r3s in 4:59 call 1-800");
        assert!(has_urgency_countdown(&norm));
    }

    // ── has_forced_retention ──────────────────────────────────────────

    #[test]
    fn forced_retention_fires_on_scam_instructions() {
        assert!(has_forced_retention("do not close this window"));
        assert!(has_forced_retention(
            "warning do not turn off your computer"
        ));
        assert!(has_forced_retention(
            "dont close this window support is checking"
        ));
        assert!(has_forced_retention("do not exit this page"));
        assert!(has_forced_retention("do not shut down your pc"));
        assert!(has_forced_retention(
            "keep this window open while we help you"
        ));
        assert!(has_forced_retention(
            "stay on this page microsoft is helping"
        ));
        assert!(has_forced_retention("this window must remain open"));
    }

    #[test]
    fn forced_retention_does_not_fire_on_benign_text() {
        // Normal window titles must not fire.
        assert!(!has_forced_retention("install complete"));
        assert!(!has_forced_retention("update available"));
        assert!(!has_forced_retention("download in progress please wait"));
        assert!(!has_forced_retention("close after reading"));
        // "close" alone is not a retention cue.
        assert!(!has_forced_retention("close this ticket"));
    }

    #[test]
    fn forced_retention_handles_homoglyphs_via_normalize() {
        // Cyrillic 'с' (U+0441) in "close" → fold to 'c' → "close".
        let norm = normalize_for_match("do not сlose this window");
        assert!(has_forced_retention(&norm));
    }

    #[test]
    fn forced_retention_fires_on_japanese_scam_instructions() {
        // The iconic JP サポート詐欺 retention phrase.
        assert!(has_forced_retention(
            "この画面を閉じないでください サポートにお電話ください"
        ));
        assert!(has_forced_retention("ウィンドウを閉じないでください"));
        assert!(has_forced_retention(
            "電源を切らないでください システムを修復しています"
        ));
        assert!(has_forced_retention("コンピュータを再起動しないでください"));
        assert!(has_forced_retention("このページから離れないでください"));
        // Plain (non-polite) inflection still matches via substring.
        assert!(has_forced_retention("画面を閉じないで今すぐ電話"));
    }

    #[test]
    fn forced_retention_does_not_fire_on_benign_japanese() {
        // Legitimate "close" instruction is not a retention coercion.
        assert!(!has_forced_retention("読み終わったら閉じてください"));
        // Benign restart notice (no negation).
        assert!(!has_forced_retention(
            "更新を完了するには再起動してください"
        ));
        // Generic window label.
        assert!(!has_forced_retention("ダウンロードが完了しました"));
    }

    // ── has_credential_harvest_cue ────────────────────────────────────

    #[test]
    fn credential_harvest_fires_on_account_alarms() {
        assert!(has_credential_harvest_cue(
            "your account has been suspended"
        ));
        assert!(has_credential_harvest_cue("account locked please verify"));
        assert!(has_credential_harvest_cue(
            "unusual sign-in activity detected"
        ));
        assert!(has_credential_harvest_cue(
            "suspicious login from new device"
        ));
        assert!(has_credential_harvest_cue(
            "account compromised contact support"
        ));
        assert!(has_credential_harvest_cue(
            "suspicious activity on your account"
        ));
    }

    #[test]
    fn credential_harvest_fires_on_cred_instructions() {
        assert!(has_credential_harvest_cue(
            "verify your account to continue"
        ));
        assert!(has_credential_harvest_cue(
            "confirm your password to unlock"
        ));
        assert!(has_credential_harvest_cue(
            "confirm your identity before proceeding"
        ));
        assert!(has_credential_harvest_cue("please re-enter your password"));
        assert!(has_credential_harvest_cue(
            "enter credentials to restore access"
        ));
        assert!(has_credential_harvest_cue(
            "update your payment information"
        ));
    }

    #[test]
    fn credential_harvest_does_not_fire_on_benign_text() {
        // A security blog article title about phishing should not fire.
        assert!(!has_credential_harvest_cue("how phishing attacks work"));
        // A legitimate login error (no account alarm, no instruction).
        assert!(!has_credential_harvest_cue(
            "incorrect password please try again"
        ));
        // "verify" alone without "account" or "identity" does not fire.
        assert!(!has_credential_harvest_cue("verify your email address"));
        // "account" alone without an alarm pairing does not fire.
        assert!(!has_credential_harvest_cue("account settings"));
    }

    #[test]
    fn credential_harvest_fires_on_japanese_phishing() {
        // Account alarms.
        assert!(has_credential_harvest_cue(
            "あなたのアカウントが停止されました 今すぐ確認してください"
        ));
        assert!(has_credential_harvest_cue("アカウントが凍結されました"));
        assert!(has_credential_harvest_cue("不審なログインを検知しました"));
        // Credential instructions.
        assert!(has_credential_harvest_cue("パスワードを確認してください"));
        assert!(has_credential_harvest_cue(
            "本人確認のため情報を入力してください"
        ));
        assert!(has_credential_harvest_cue(
            "アカウントを確認して再開してください"
        ));
    }

    #[test]
    fn credential_harvest_does_not_fire_on_benign_japanese() {
        // Legitimate account-settings label, no alarm/instruction pairing.
        assert!(!has_credential_harvest_cue("アカウント設定を開く"));
        // Generic login page header.
        assert!(!has_credential_harvest_cue("ログインページへようこそ"));
        // Password-change help article (no alarm, no confirm/re-enter pairing).
        assert!(!has_credential_harvest_cue("パスワードの変更方法について"));
    }

    // ── has_fake_scanner_cue ─────────────────────────────────────────────

    #[test]
    fn fake_scanner_fires_on_scareware_titles() {
        // Fake scanning progress.
        assert!(has_fake_scanner_cue("scanning for viruses please wait"));
        assert!(has_fake_scanner_cue("scanning for threats on your system"));
        assert!(has_fake_scanner_cue("scanning for malware"));
        assert!(has_fake_scanner_cue("scanning for spyware"));
        // Threat-count language.
        assert!(has_fake_scanner_cue("4 threats detected on your pc"));
        assert!(has_fake_scanner_cue("3 viruses found remove now"));
        assert!(has_fake_scanner_cue("12 infections identified"));
        // Removal language.
        assert!(has_fake_scanner_cue("removing malware from your computer"));
        assert!(has_fake_scanner_cue("virus removed successfully"));
        assert!(has_fake_scanner_cue("removing spyware do not close"));
        // Repair language.
        assert!(has_fake_scanner_cue("repairing your system please wait"));
        assert!(has_fake_scanner_cue("system repair in progress"));
        assert!(has_fake_scanner_cue("repair your pc now"));
        // System-error language.
        assert!(has_fake_scanner_cue("critical system error detected"));
        assert!(has_fake_scanner_cue("system error found contact support"));
    }

    #[test]
    fn fake_scanner_does_not_fire_on_benign_titles() {
        // Legitimate IDE / build output titles.
        assert!(!has_fake_scanner_cue("build in progress"));
        assert!(!has_fake_scanner_cue("installing update please wait"));
        assert!(!has_fake_scanner_cue("download complete"));
        // A real security product whose user-opened window shows summary.
        // "removed" alone without a threat word must not fire.
        assert!(!has_fake_scanner_cue("item removed from cart"));
        // "error" alone without system+detected does not fire.
        assert!(!has_fake_scanner_cue("error loading page"));
        // "repair" alone (e.g. Word repair dialog header).
        assert!(!has_fake_scanner_cue("repair complete"));
    }

    #[test]
    fn fake_scanner_defeats_leet_via_normalize() {
        // "v1rus" → "virus", "thr34t" → "threat" after normalize_for_match.
        let norm = normalize_for_match("sc4nning for v1rus3s");
        assert!(has_fake_scanner_cue(&norm));
    }

    #[test]
    fn fake_scanner_fires_on_japanese_scareware() {
        // Scanning progress.
        assert!(has_fake_scanner_cue("スキャン中 ウイルスを検索しています"));
        // Threat-count / detection framing.
        assert!(has_fake_scanner_cue("脅威が見つかりました 今すぐ対処"));
        assert!(has_fake_scanner_cue("3個のウイルスを検出しました"));
        assert!(has_fake_scanner_cue("マルウェアが検出されました"));
        // Removal progress.
        assert!(has_fake_scanner_cue(
            "マルウェアを削除しています お待ちください"
        ));
        assert!(has_fake_scanner_cue("ウイルスを駆除しています"));
        // Repair progress.
        assert!(has_fake_scanner_cue(
            "システムを修復しています 電源を切らないで"
        ));
    }

    #[test]
    fn fake_scanner_does_not_fire_on_benign_japanese() {
        // Generic progress with no threat noun.
        assert!(!has_fake_scanner_cue("更新をインストールしています"));
        // Legitimate security-software summary (no scan/detect/repair verb).
        assert!(!has_fake_scanner_cue("ウイルス対策ソフトの設定"));
        // Download progress.
        assert!(!has_fake_scanner_cue("ダウンロード中です"));
    }

    // ── has_subscription_lure ────────────────────────────────────────────

    #[test]
    fn subscription_lure_fires_on_scareware_titles() {
        assert!(has_subscription_lure(
            "your norton subscription has expired renew now"
        ));
        assert!(has_subscription_lure(
            "mcafee protection expired call to activate"
        ));
        assert!(has_subscription_lure(
            "windows defender subscription expiring click to purchase"
        ));
        assert!(has_subscription_lure(
            "your license has expired please renew today"
        ));
        assert!(has_subscription_lure(
            "membership expired buy now to restore protection"
        ));
    }

    #[test]
    fn subscription_lure_does_not_fire_on_benign_text() {
        // Only two of the three groups — no action word → no fire.
        assert!(!has_subscription_lure("your subscription has expired"));
        // Only subject + action — no expiry → no fire.
        assert!(!has_subscription_lure("subscription manager renew"));
        // Neither expired nor action word — plain product name.
        assert!(!has_subscription_lure(
            "norton security subscription active"
        ));
        // Unrelated expired context.
        assert!(!has_subscription_lure("coupon expired"));
    }

    #[test]
    fn subscription_lure_handles_homoglyphs_via_normalize() {
        // Cyrillic 'е' in "expired" → 'e' after normalize_for_match.
        let norm = normalize_for_match("subscription has еxpired renew now");
        assert!(has_subscription_lure(&norm));
    }

    // ── has_authority_lure ───────────────────────────────────────────────

    #[test]
    fn authority_lure_fires_on_lea_impersonation() {
        // Classic Reveton/Winlock titles.
        assert!(has_authority_lure(
            "fbi warning your computer has been locked"
        ));
        assert!(has_authority_lure(
            "fbi cyber notice illegal activity detected"
        ));
        assert!(has_authority_lure(
            "interpol warning your device is blocked"
        ));
        assert!(has_authority_lure(
            "cybercrime division notice you are violating the law"
        ));
        assert!(has_authority_lure("homeland security warning"));
        assert!(has_authority_lure(
            "department of justice illegal content notice"
        ));
        assert!(has_authority_lure(
            "law enforcement violation fine required"
        ));
        assert!(has_authority_lure(
            "cyber police your computer is locked call now"
        ));
        assert!(has_authority_lure(
            "national security agency warning illegal"
        ));
        assert!(has_authority_lure(
            "cia notice you are arrested pay penalty"
        ));
    }

    #[test]
    fn authority_lure_does_not_fire_on_benign_titles() {
        // "warning" alone without an agency token.
        assert!(!has_authority_lure("warning low battery"));
        // Agency name in a legitimate context without a coercion word.
        assert!(!has_authority_lure("fbi crime statistics report 2024"));
        // Security blog article title — no coercion pairing expected.
        assert!(!has_authority_lure(
            "how to report cybercrime to authorities"
        ));
        // Only coercion words, no agency.
        assert!(!has_authority_lure(
            "your account has been locked please call"
        ));
    }

    #[test]
    fn authority_lure_defeats_homoglyphs_via_normalize() {
        // Cyrillic 'і' in "warning" → 'i' after normalize_for_match.
        let norm = normalize_for_match("fbі warnіng your computer is locked");
        assert!(has_authority_lure(&norm));
    }

    #[test]
    fn authority_lure_fires_on_japanese_police_impersonation() {
        // 警察庁 (National Police Agency) + 警告 (warning) — IPA サポート詐欺
        assert!(has_authority_lure(
            "警察庁からの警告 あなたのコンピュータはロックされました"
        ));
        // 警視庁 (Tokyo Metropolitan Police) + 違反 (violation)
        assert!(has_authority_lure(
            "警視庁 違法コンテンツの違反が検出されました"
        ));
        // 国税庁 (National Tax Agency) + 罰金 (fine)
        assert!(has_authority_lure(
            "国税庁 未払い税金の罰金を支払ってください"
        ));
        // サイバー警察 + 不正アクセス
        assert!(has_authority_lure(
            "サイバー警察 不正アクセスを検出 アカウントを凍結しました"
        ));
        // 消費者庁 + ブロック
        assert!(has_authority_lure("消費者庁 違反によりブロックされました"));
    }

    #[test]
    fn authority_lure_does_not_fire_on_benign_japanese() {
        // Agency name in a legitimate news/info context, no coercion word.
        assert!(!has_authority_lure("警察庁 交通安全週間のお知らせ"));
        // Coercion word alone, no agency.
        assert!(!has_authority_lure("バッテリー残量の警告"));
        // 国税庁 legitimate tax-filing reminder, no fine/penalty coercion.
        assert!(!has_authority_lure("国税庁 確定申告の受付を開始しました"));
    }

    #[test]
    fn authority_lure_fires_on_additional_western_agencies() {
        // UK HMRC + fine
        assert!(has_authority_lure("hmrc notice unpaid tax penalty fine"));
        // Europol + locked
        assert!(has_authority_lure("europol warning your device is locked"));
        // Australian Federal Police + violation
        assert!(has_authority_lure(
            "australian federal police violation notice"
        ));
    }

    #[test]
    fn authority_lure_fires_on_irs_and_us_agencies() {
        // IRS impersonation — FTC #2 government impersonator
        assert!(has_authority_lure(
            "internal revenue service warning: unpaid taxes penalty"
        ));
        assert!(has_authority_lure(
            "internal revenue service notice your account is suspended"
        ));
        // FTC impersonation
        assert!(has_authority_lure(
            "federal trade commission warning illegal activity detected"
        ));
        // US Customs
        assert!(has_authority_lure(
            "customs and border protection violation notice penalty"
        ));
        // DEA
        assert!(has_authority_lure(
            "drug enforcement warning your device is blocked"
        ));
    }

    #[test]
    fn authority_lure_fires_on_warrant_and_legal_coercion() {
        // Warrant + existing agency
        assert!(has_authority_lure("fbi arrest warrant issued against you"));
        // Subpoena framing
        assert!(has_authority_lure("department of justice subpoena notice"));
        // JP warrant
        assert!(has_authority_lure("警察庁 令状 逮捕"));
        // JP prosecutors + prosecution coercion
        assert!(has_authority_lure("検察庁 起訴状 不正アクセス"));
        // JP Ministry of Justice + freeze
        assert!(has_authority_lure("法務省 凍結通知 違法"));
    }

    #[test]
    fn authority_lure_does_not_fire_on_irs_benign() {
        // Plain IRS info — no coercion
        assert!(!has_authority_lure(
            "internal revenue service tax filing deadline"
        ));
        // Plain customs info — no coercion
        assert!(!has_authority_lure(
            "customs and border protection: declare items over $800"
        ));
        // JP Ministry of Justice info
        assert!(!has_authority_lure("法務省 出入国在留管理局 在留資格"));
    }

    // ── has_screen_share_lure ─────────────────────────────────────────────

    #[test]
    fn screen_share_lure_fires_on_scam_instructions() {
        // "Share your screen" variants.
        assert!(has_screen_share_lure(
            "share your screen with our support team"
        ));
        assert!(has_screen_share_lure(
            "screen sharing required to fix your computer"
        ));
        assert!(has_screen_share_lure(
            "share your desktop with a microsoft technician"
        ));
        assert!(has_screen_share_lure(
            "please share your display with support"
        ));
        // "Allow/enable remote" variants.
        assert!(has_screen_share_lure(
            "allow remote viewing to diagnose your pc"
        ));
        assert!(has_screen_share_lure(
            "enable remote access to fix the issue"
        ));
        assert!(has_screen_share_lure(
            "allow remote control of your computer"
        ));
        // "Grant access" variants.
        assert!(has_screen_share_lure(
            "grant access to our support agent to continue"
        ));
        assert!(has_screen_share_lure(
            "grant access to technician to repair your pc"
        ));
    }

    #[test]
    fn screen_share_lure_does_not_fire_on_benign_titles() {
        // "Share" without "screen/desktop/display".
        assert!(!has_screen_share_lure("share this document with your team"));
        // "Screen" without "share/sharing".
        assert!(!has_screen_share_lure("screen brightness settings"));
        // Legitimate screenshare UI label (would be user-initiated and closable anyway).
        assert!(!has_screen_share_lure("zoom meeting in progress"));
        // "Remote" without "allow/enable" + the target words.
        assert!(!has_screen_share_lure("remote desktop connection"));
        // "Grant" without "access".
        assert!(!has_screen_share_lure("grant permission requested"));
    }

    // ── has_crypto_drain_lure ─────────────────────────────────────────────

    #[test]
    fn crypto_drain_lure_fires_on_wallet_alarm() {
        // wallet word + alarm action
        assert!(has_crypto_drain_lure(
            "your wallet has been compromised click here"
        ));
        assert!(has_crypto_drain_lure(
            "suspicious activity detected on your wallet"
        ));
        assert!(has_crypto_drain_lure(
            "your metamask wallet has been hacked"
        ));
        assert!(has_crypto_drain_lure(
            "your coinbase account has been flagged"
        ));
        assert!(has_crypto_drain_lure(
            "unauthorized access to your web3 wallet detected"
        ));
    }

    #[test]
    fn crypto_drain_lure_fires_on_wallet_coercion() {
        assert!(has_crypto_drain_lure("connect your wallet to continue"));
        assert!(has_crypto_drain_lure("validate your wallet now"));
        assert!(has_crypto_drain_lure(
            "verify your metamask wallet to restore access"
        ));
        assert!(has_crypto_drain_lure(
            "link your coinbase wallet to claim funds"
        ));
    }

    #[test]
    fn crypto_drain_lure_fires_on_seed_harvest() {
        assert!(has_crypto_drain_lure("seed phrase verification required"));
        assert!(has_crypto_drain_lure(
            "enter your recovery phrase to restore access"
        ));
        assert!(has_crypto_drain_lure("confirm your secret recovery phrase"));
        assert!(has_crypto_drain_lure(
            "provide your private key to verify ownership"
        ));
        assert!(has_crypto_drain_lure(
            "mnemonic required to unlock your wallet"
        ));
    }

    #[test]
    fn crypto_drain_lure_does_not_fire_on_benign() {
        // News / educational text about crypto
        assert!(!has_crypto_drain_lure("bitcoin price reaches new high"));
        assert!(!has_crypto_drain_lure("ethereum network upgrade completed"));
        // Password managers / security apps using "key" without seed context
        assert!(!has_crypto_drain_lure(
            "your encryption key has been rotated"
        ));
        // Legitimate account lock without wallet/crypto context
        assert!(!has_crypto_drain_lure(
            "your account has been suspended for inactivity"
        ));
        // Remote desktop app — no crypto tokens
        assert!(!has_crypto_drain_lure(
            "share your screen with our support agent"
        ));
    }

    // ── has_prize_lure ────────────────────────────────────────────────────

    #[test]
    fn prize_lure_fires_on_lottery_overlays() {
        // prize_word + claim/collect action
        assert!(has_prize_lure(
            "congratulations you have won a prize click to claim"
        ));
        assert!(has_prize_lure(
            "you are today's lucky winner collect your reward now"
        ));
        assert!(has_prize_lure(
            "you won a 500 gift card claim it before it expires"
        ));
        assert!(has_prize_lure(
            "you have been selected as today's winner verify now"
        ));
    }

    #[test]
    fn prize_lure_fires_on_gift_card_scam() {
        // gift card variants with claim action — the AND-pair catches them
        assert!(has_prize_lure(
            "congratulations you have won a 100 amazon gift card click here to claim"
        ));
        assert!(has_prize_lure(
            "you are eligible for a free gift card claim today"
        ));
    }

    #[test]
    fn prize_lure_fires_on_lottery_coercion() {
        // urgency / expiry lure on a winning claim
        assert!(has_prize_lure(
            "your prize will expire in 24 hours claim now"
        ));
        assert!(has_prize_lure(
            "you have been selected to receive a reward click here to collect"
        ));
    }

    #[test]
    fn prize_lure_does_not_fire_on_benign() {
        // No action verb paired with prize
        assert!(!has_prize_lure("congratulations on your new job"));
        // Prize word without claim/collect/winner framing
        assert!(!has_prize_lure("best picture award ceremony 2024"));
        // Legitimate game result — no claim urgency
        assert!(!has_prize_lure("you scored a personal record today"));
        // Generic e-commerce loyalty point notification (no alarm)
        assert!(!has_prize_lure("you have earned 500 reward points"));
    }

    // ── has_download_trap_lure ────────────────────────────────────────────

    #[test]
    fn download_trap_lure_fires_on_install_demand() {
        // install/update + required/to continue
        assert!(has_download_trap_lure(
            "download required to continue viewing"
        ));
        assert!(has_download_trap_lure(
            "update required to access this page"
        ));
        assert!(has_download_trap_lure(
            "install required to view this content"
        ));
        assert!(has_download_trap_lure("software update needed to continue"));
        assert!(has_download_trap_lure(
            "update necessary to play this video"
        ));
    }

    #[test]
    fn download_trap_lure_fires_on_fake_plugin_gate() {
        // plugin/extension/codec + install/download
        assert!(has_download_trap_lure("install plugin to continue"));
        assert!(has_download_trap_lure("flash player update required"));
        assert!(has_download_trap_lure("download codec to play this video"));
        assert!(has_download_trap_lure(
            "browser extension required for this page"
        ));
        assert!(has_download_trap_lure("add-on installation required"));
    }

    #[test]
    fn download_trap_lure_does_not_fire_on_benign() {
        // Download link without required framing
        assert!(!has_download_trap_lure("download the free ebook now"));
        // Legitimate app update notification — no required/to-continue
        assert!(!has_download_trap_lure(
            "a new version of the app is available"
        ));
        // Generic OS update (no plugin noun, no required cue in same string)
        assert!(!has_download_trap_lure(
            "windows update completed successfully"
        ));
        // ClickFix-style keyboard shortcut — no download/install verb
        assert!(!has_download_trap_lure("press windows and r to verify"));
    }

    // ── has_qr_code_lure ──────────────────────────────────────────────────

    #[test]
    fn qr_code_lure_fires_on_quishing_overlays() {
        assert!(has_qr_code_lure("scan qr code to verify your identity"));
        assert!(has_qr_code_lure("scan the qr code to continue"));
        assert!(has_qr_code_lure("scan qr to confirm your account"));
        assert!(has_qr_code_lure("qr code scan now to access your account"));
        assert!(has_qr_code_lure("qr-code scan to authenticate"));
    }

    #[test]
    fn qr_code_lure_fires_on_verify_proceed_variants() {
        assert!(has_qr_code_lure("scan qr code to proceed"));
        assert!(has_qr_code_lure("scan qr to validate your identity"));
        assert!(has_qr_code_lure("use qr code to access your account"));
    }

    #[test]
    fn qr_code_lure_does_not_fire_on_benign() {
        // Legitimate QR display with no verify action
        assert!(!has_qr_code_lure("qr code for this event"));
        // Boarding pass / ticket — no verify action
        assert!(!has_qr_code_lure("show your qr code at the gate"));
        // Plain text without qr_noun
        assert!(!has_qr_code_lure("verify your identity to continue"));
        // Scan without QR reference
        assert!(!has_qr_code_lure("scan your fingerprint to log in"));
    }

    // ── has_ip_alarm_lure ─────────────────────────────────────────────────

    #[test]
    fn ip_alarm_lure_fires_on_tech_support_scam_text() {
        assert!(has_ip_alarm_lure("your ip address has been hacked"));
        assert!(has_ip_alarm_lure(
            "ip address detected infected with malware"
        ));
        assert!(has_ip_alarm_lure(
            "your ip address has been flagged by our security"
        ));
        assert!(has_ip_alarm_lure(
            "your ip has been reported to the authorities"
        ));
        assert!(has_ip_alarm_lure("your ip address has been compromised"));
    }

    #[test]
    fn ip_alarm_lure_fires_on_breach_and_block_variants() {
        assert!(has_ip_alarm_lure(
            "your ip address is blocked due to suspicious activity"
        ));
        assert!(has_ip_alarm_lure("your ip has been suspended"));
        assert!(has_ip_alarm_lure("ip address breach detected"));
    }

    #[test]
    fn ip_alarm_lure_does_not_fire_on_benign() {
        // Network status page — shows IP without alarm
        assert!(!has_ip_alarm_lure("your ip address is 192.168.1.1"));
        // Firewall log entry — no "your ip" or "ip address" subject
        assert!(!has_ip_alarm_lure("connection blocked by firewall"));
        // Generic security headline without ip subject
        assert!(!has_ip_alarm_lure("network security tips for 2025"));
        // Legitimate CAPTCHA page
        assert!(!has_ip_alarm_lure("verify you are not a robot"));
    }

    // ── has_package_fee_lure ──────────────────────────────────────────────

    #[test]
    fn package_fee_lure_fires_on_delivery_scam() {
        assert!(has_package_fee_lure(
            "your package is on hold pay customs fee to release"
        ));
        assert!(has_package_fee_lure(
            "your shipment is on hold due to unpaid customs duty"
        ));
        assert!(has_package_fee_lure(
            "your parcel is on hold pending customs clearance fee"
        ));
        assert!(has_package_fee_lure(
            "your delivery has failed delivery please pay fee required"
        ));
    }

    #[test]
    fn package_fee_lure_fires_on_unable_to_deliver_variants() {
        assert!(has_package_fee_lure(
            "your package is unable to deliver customs fee required"
        ));
        assert!(has_package_fee_lure(
            "your order is on hold release fee required"
        ));
    }

    #[test]
    fn package_fee_lure_does_not_fire_on_benign() {
        // Legitimate order confirmation — no fee demand
        assert!(!has_package_fee_lure(
            "your package has been shipped and is on its way"
        ));
        // Package tracking without hold/fee language
        assert!(!has_package_fee_lure("your order has been delivered"));
        // Customs FAQ article — "customs fee" but no package_noun
        assert!(!has_package_fee_lure(
            "how to calculate customs fees for imports"
        ));
        // E-commerce loyalty point — "your order" but no fee/hold
        assert!(!has_package_fee_lure(
            "your order has earned 500 reward points"
        ));
    }

    // ── has_sextortion_lure ───────────────────────────────────────────────

    #[test]
    fn sextortion_lure_fires_on_webcam_extortion() {
        assert!(has_sextortion_lure(
            "we have recorded you using your webcam pay bitcoin now"
        ));
        assert!(has_sextortion_lure(
            "your camera has been hacked we have footage pay in btc"
        ));
        assert!(has_sextortion_lure(
            "we have been recording you send payment to avoid exposure"
        ));
        assert!(has_sextortion_lure(
            "your webcam was accessed we will send this to your contacts unless you pay"
        ));
    }

    #[test]
    fn sextortion_lure_fires_on_crypto_payment_demand() {
        assert!(has_sextortion_lure(
            "recorded you visiting adult sites send cryptocurrency to stop release"
        ));
        assert!(has_sextortion_lure(
            "hacked your camera send btc or we will expose this"
        ));
    }

    #[test]
    fn sextortion_lure_does_not_fire_on_benign() {
        // Webcam setup dialog — no extortion_word
        assert!(!has_sextortion_lure(
            "allow your camera to be used for this video call"
        ));
        // Crypto news — no camera_cue
        assert!(!has_sextortion_lure("bitcoin payment processing completed"));
        // Security advisory with "camera" but no payment demand
        assert!(!has_sextortion_lure(
            "your camera permission was requested by this website"
        ));
        // Generic privacy notice
        assert!(!has_sextortion_lure(
            "we do not record or store your video calls"
        ));
    }

    // ── has_gift_card_demand ──────────────────────────────────────────────

    #[test]
    fn gift_card_demand_fires_on_tech_support_payment() {
        // Classic "buy iTunes gift cards to pay us" tech-support-scam pattern
        assert!(has_gift_card_demand(
            "please buy gift cards from the store and send codes to fix your computer"
        ));
        assert!(has_gift_card_demand(
            "purchase gift cards now to unlock your device"
        ));
        assert!(has_gift_card_demand(
            "go to the store and buy amazon gift card then read me the codes"
        ));
        assert!(has_gift_card_demand(
            "pay using gift cards to remove the virus"
        ));
    }

    #[test]
    fn gift_card_demand_fires_on_send_codes_pattern() {
        // "send codes" / "card codes" patterns with a specific card product
        assert!(has_gift_card_demand(
            "scratch the itunes card and send codes to our agent"
        ));
        assert!(has_gift_card_demand(
            "please send the gift card codes to this number"
        ));
        assert!(has_gift_card_demand(
            "gift card codes required to proceed with your case"
        ));
        assert!(has_gift_card_demand("itunes card send the codes to verify"));
    }

    #[test]
    fn gift_card_demand_fires_on_store_direction() {
        // Authority-impersonation variants directing victim to a physical store
        assert!(has_gift_card_demand(
            "go to the nearest store and purchase gift cards for the fine"
        ));
        assert!(has_gift_card_demand(
            "go buy google play card and call us back with the numbers"
        ));
    }

    #[test]
    fn gift_card_demand_does_not_fire_on_benign() {
        // Gift-card redemption UI — no payment_instruction
        assert!(!has_gift_card_demand(
            "enter your gift card code below to add balance"
        ));
        // Gift-card marketing — no buy/send-codes coercion
        assert!(!has_gift_card_demand(
            "send a gift card to a friend for their birthday"
        ));
        // Gift card balance check — no instruction to send codes
        assert!(!has_gift_card_demand("check your amazon gift card balance"));
        // Crypto news with "card" — no gift_card_noun
        assert!(!has_gift_card_demand(
            "buy bitcoin with debit card on our exchange"
        ));
        // Generic purchase page — no gift card product
        assert!(!has_gift_card_demand(
            "purchase now to unlock premium features"
        ));
    }

    // ── has_refund_scam_cue ───────────────────────────────────────────────
    #[test]
    fn refund_scam_fires_on_owed_to_you() {
        assert!(has_refund_scam_cue(
            "a refund of $499 is owed to you — call to collect"
        ));
        assert!(has_refund_scam_cue(
            "overpayment detected: $199 owed to you — click to claim"
        ));
        assert!(has_refund_scam_cue(
            "your reimbursement of $299 owed to you — call support now"
        ));
    }

    #[test]
    fn refund_scam_fires_on_pending_refund() {
        assert!(has_refund_scam_cue(
            "pending refund: $349. call 1-800-555-0100 to process"
        ));
        assert!(has_refund_scam_cue(
            "your refund of $299 has been approved — click here to receive"
        ));
        assert!(has_refund_scam_cue(
            "cashback of $450 is ready — process your refund now"
        ));
    }

    #[test]
    fn refund_scam_fires_jp() {
        assert!(has_refund_scam_cue(
            "返金が完了しました。お手続きください。"
        ));
        assert!(has_refund_scam_cue(
            "払い戻し手続きが必要です。ご連絡ください。"
        ));
        assert!(has_refund_scam_cue(
            "ご返金いたします。返金手続きをお願いします。"
        ));
    }

    #[test]
    fn refund_scam_does_not_fire_on_benign() {
        // Plain return policy — has refund noun but no claim action
        assert!(!has_refund_scam_cue(
            "refund policy: returns accepted within 30 days"
        ));
        assert!(!has_refund_scam_cue(
            "we offer a full refund within 14 days of purchase"
        ));
        // Only action, no noun
        assert!(!has_refund_scam_cue(
            "claim your prize now by clicking here"
        ));
        // Rebate ad without claim action
        assert!(!has_refund_scam_cue(
            "mail-in rebate: save $20 on your next purchase"
        ));
        // Legitimate bank portal phrase — has noun but says "30 days" not "owed to you"
        assert!(!has_refund_scam_cue(
            "your overpayment will be processed within 5-7 business days"
        ));
    }

    #[test]
    fn refund_scam_does_not_fire_jp_benign() {
        // Legitimate e-commerce return policy
        assert!(!has_refund_scam_cue("返金は30日以内にお申し込みください"));
        // Legitimate cancellation confirmation
        assert!(!has_refund_scam_cue("キャンセルを承りました"));
    }

    // ── has_national_id_alarm ─────────────────────────────────────────────
    #[test]
    fn national_id_alarm_fires_on_ssn_suspended() {
        assert!(has_national_id_alarm(
            "your social security number has been suspended — call 1-800-555-0100"
        ));
        assert!(has_national_id_alarm(
            "ssn used in criminal activity — immediate action required"
        ));
        assert!(has_national_id_alarm(
            "your social security was used in criminal charges — call doj"
        ));
    }

    #[test]
    fn national_id_alarm_fires_on_medicare_fraud() {
        assert!(has_national_id_alarm(
            "medicare account has been compromised — verify your identity now"
        ));
        assert!(has_national_id_alarm(
            "medicaid has been suspended due to fraudulent activity"
        ));
    }

    #[test]
    fn national_id_alarm_fires_jp() {
        assert!(has_national_id_alarm(
            "マイナンバーが不正使用されました。捜査中です。"
        ));
        assert!(has_national_id_alarm(
            "年金番号が凍結されました。至急サポートにご連絡ください。"
        ));
        assert!(has_national_id_alarm(
            "個人番号が犯罪に使用されています。警察に連絡済みです。"
        ));
    }

    #[test]
    fn national_id_alarm_does_not_fire_on_benign() {
        // Policy article — has noun but no alarm
        assert!(!has_national_id_alarm(
            "social security benefits increased by 3.2% in 2025"
        ));
        // Medicare explanation page
        assert!(!has_national_id_alarm(
            "medicare covers hospital visits, doctor visits, and prescriptions"
        ));
        // Only alarm, no noun
        assert!(!has_national_id_alarm(
            "your account has been suspended — please verify"
        ));
        // Legitimate UK NIN page (no alarm)
        assert!(!has_national_id_alarm(
            "your national insurance number is on your payslip"
        ));
    }

    #[test]
    fn national_id_alarm_does_not_fire_jp_benign() {
        // Legitimate JP pension info
        assert!(!has_national_id_alarm("基礎年金番号の確認方法について"));
        // Legitimate マイナンバー application guide
        assert!(!has_national_id_alarm("マイナンバーカードの申請方法"));
    }

    // ── has_bank_account_alarm ────────────────────────────────────────────
    #[test]
    fn bank_alarm_fires_on_frozen_account() {
        assert!(has_bank_account_alarm(
            "your bank account has been frozen due to suspicious activity — call now"
        ));
        assert!(has_bank_account_alarm(
            "checking account access has been restricted — unauthorized transaction detected"
        ));
        assert!(has_bank_account_alarm(
            "your debit card has been frozen — fraudulent transaction detected"
        ));
    }

    #[test]
    fn bank_alarm_fires_on_fraudulent_charge() {
        assert!(has_bank_account_alarm(
            "credit card fraudulent charge detected — call 1-800-555-0100"
        ));
        assert!(has_bank_account_alarm(
            "savings account: unauthorized transaction — verify your identity"
        ));
    }

    #[test]
    fn bank_alarm_fires_jp() {
        assert!(has_bank_account_alarm(
            "銀行口座に不正な取引が検出されました。サポートにご連絡ください。"
        ));
        assert!(has_bank_account_alarm(
            "キャッシュカードが不正利用されました。口座が凍結されました。"
        ));
        assert!(has_bank_account_alarm(
            "銀行口座が停止されました。不審な取引が検出されました。"
        ));
    }

    #[test]
    fn bank_alarm_does_not_fire_on_benign() {
        // No alarm — just balance info
        assert!(!has_bank_account_alarm(
            "your bank account balance is $1,234.56"
        ));
        // No bank noun — just a generic alarm
        assert!(!has_bank_account_alarm(
            "suspicious activity detected — verify your identity"
        ));
        // Legitimate fraud alert email body — but no bank_noun
        assert!(!has_bank_account_alarm(
            "unauthorized transaction: a $99 charge was processed"
        ));
        // Generic "account frozen" without bank noun
        assert!(!has_bank_account_alarm(
            "your account has been frozen — contact support"
        ));
    }

    #[test]
    fn bank_alarm_does_not_fire_jp_benign() {
        // Legitimate balance check
        assert!(!has_bank_account_alarm(
            "銀行口座の残高確認はアプリでどうぞ"
        ));
        // Generic suspended without fraud alarm
        assert!(!has_bank_account_alarm(
            "クレジットカードの請求書が届きました"
        ));
    }

    // ── has_false_registration_billing ───────────────────────────────────────

    #[test]
    fn false_reg_billing_fires_on_pay_within() {
        assert!(has_false_registration_billing(
            "your registration is complete — pay within 72 hours to avoid legal action"
        ));
        assert!(has_false_registration_billing(
            "you have been registered for our premium service. outstanding fee: $149. pay within 24 hours."
        ));
    }

    #[test]
    fn false_reg_billing_fires_on_legal_action() {
        assert!(has_false_registration_billing(
            "membership confirmed. failure to pay will result in legal action and penalty fee."
        ));
        assert!(has_false_registration_billing(
            "you signed up for our adult content service. amount due: $299. legal action will follow."
        ));
    }

    #[test]
    fn false_reg_billing_fires_jp() {
        assert!(has_false_registration_billing(
            "ご登録が完了しました。未払いの場合は法的措置を取ります。"
        ));
        assert!(has_false_registration_billing(
            "会員登録が完了しました。ご請求金額：¥29800。お支払い期限内にご入金ください。"
        ));
        assert!(has_false_registration_billing(
            "登録が完了しました。督促状を発送する前にご入金ください。"
        ));
    }

    #[test]
    fn false_reg_billing_does_not_fire_on_benign() {
        // Legitimate "thanks for registering" with no payment demand
        assert!(!has_false_registration_billing(
            "registration complete — welcome to our community!"
        ));
        // Payment page without registration claim
        assert!(!has_false_registration_billing(
            "outstanding fee: $29.99 — please pay within 30 days"
        ));
        // Subscription lure without false registration
        assert!(!has_false_registration_billing(
            "your subscription has expired. renew to restore access."
        ));
        // Legal notice without registration claim
        assert!(!has_false_registration_billing(
            "failure to pay may result in legal action"
        ));
    }

    #[test]
    fn false_reg_billing_does_not_fire_jp_benign() {
        // Legitimate e-commerce order confirmation
        assert!(!has_false_registration_billing(
            "ご注文が完了しました。ご利用ありがとうございます。"
        ));
        // Invoice without registration claim
        assert!(!has_false_registration_billing(
            "請求書を送付いたします。お支払い期限をご確認ください。"
        ));
    }

    // ── has_fake_bsod_lure ───────────────────────────────────────────────────

    #[test]
    fn fake_bsod_fires_on_stop_code_and_call_microsoft() {
        assert!(has_fake_bsod_lure(
            "stop code: memory_management — call microsoft support immediately"
        ));
        assert!(has_fake_bsod_lure(
            "stop code: kmode exception — do not restart your computer call microsoft"
        ));
    }

    #[test]
    fn fake_bsod_fires_on_windows_blocked() {
        assert!(has_fake_bsod_lure(
            "windows has been blocked call microsoft certified technician 1-800-555-0100"
        ));
        assert!(has_fake_bsod_lure(
            "your pc is blocked — do not turn off this computer — contact microsoft"
        ));
    }

    #[test]
    fn fake_bsod_fires_on_blue_screen_do_not_restart() {
        assert!(has_fake_bsod_lure(
            "blue screen error — do not restart — call windows helpline now"
        ));
        assert!(has_fake_bsod_lure(
            "kernel panic — do not shut down — call apple support immediately"
        ));
    }

    #[test]
    fn fake_bsod_fires_jp() {
        assert!(has_fake_bsod_lure(
            "ブルースクリーンが発生しました。再起動しないでください。マイクロソフトサポートに電話してください。"
        ));
        assert!(has_fake_bsod_lure(
            "windowsがブロックされました。テクニカルサポートに電話してください。"
        ));
    }

    #[test]
    fn fake_bsod_does_not_fire_on_benign() {
        // BSOD marker only — no call barrier
        assert!(!has_fake_bsod_lure("blue screen troubleshooting guide"));
        // Call barrier only — no BSOD marker
        assert!(!has_fake_bsod_lure(
            "do not restart your computer while updates are installing"
        ));
        // IT article mentioning stop codes
        assert!(!has_fake_bsod_lure(
            "how to read windows stop codes for debugging"
        ));
        // Legitimate kernel panic report without call instruction
        assert!(!has_fake_bsod_lure("kernel panic log: cpu 0 caller"));
    }

    #[test]
    fn fake_bsod_does_not_fire_jp_benign() {
        // Legitimate update progress — no BSOD marker
        assert!(!has_fake_bsod_lure(
            "更新プログラムのインストール中は再起動しないでください。"
        ));
        // BSOD article without call instruction
        assert!(!has_fake_bsod_lure("ブルースクリーンエラーの原因と対処法"));
    }

    // ── has_advance_fee_lure ─────────────────────────────────────────────────

    #[test]
    fn advance_fee_fires_on_inheritance_plus_processing_fee() {
        assert!(has_advance_fee_lure(
            "you are a beneficiary of the estate of a deceased customer — processing fee required to release the funds"
        ));
        assert!(has_advance_fee_lure(
            "unclaimed funds of $4.5 million — advance fee of $250 to unlock your funds"
        ));
    }

    #[test]
    fn advance_fee_fires_on_lottery_plus_transfer_fee() {
        assert!(has_advance_fee_lure(
            "congratulations! you won the lottery — pay customs fee to claim your prize"
        ));
        assert!(has_advance_fee_lure(
            "you have inherited a trust fund — legal fee required to release the funds to you"
        ));
    }

    #[test]
    fn advance_fee_fires_jp() {
        assert!(has_advance_fee_lure(
            "遺産の受益者として選ばれました。手数料をお支払いください。"
        ));
        assert!(has_advance_fee_lure(
            "宝くじ当選のお知らせ。振込手数料をお支払いいただくと受け取り可能です。"
        ));
    }

    #[test]
    fn advance_fee_does_not_fire_on_benign() {
        // Windfall claim without fee — legitimate estate notification
        assert!(!has_advance_fee_lure(
            "you are listed as a beneficiary in the estate of john smith"
        ));
        // Fee without windfall claim
        assert!(!has_advance_fee_lure(
            "processing fee: $5 for account opening"
        ));
        // Prize lure without advance fee
        assert!(!has_advance_fee_lure(
            "you won the lottery — click here to claim"
        ));
        // Customs fee for legitimate package
        assert!(!has_advance_fee_lure(
            "customs fee required for your international parcel delivery"
        ));
    }

    #[test]
    fn advance_fee_does_not_fire_jp_benign() {
        // Legitimate estate law office page
        assert!(!has_advance_fee_lure("遺産相続の手続きについてのご案内"));
        // Customs fee for real package
        assert!(!has_advance_fee_lure(
            "関税のお支払いは配達時にお願いします。"
        ));
    }

    // ── has_tech_support_invoice_scam ────────────────────────────────────────

    #[test]
    fn invoice_scam_fires_on_charge_plus_cancel_cta() {
        assert!(has_tech_support_invoice_scam(
            "you have been charged $499.00 for microsoft support plan — call to cancel"
        ));
        assert!(has_tech_support_invoice_scam(
            "a charge of $399 mcafee subscription renewal — if you did not authorize call now"
        ));
    }

    #[test]
    fn invoice_scam_fires_on_auto_renewal_dispute() {
        assert!(has_tech_support_invoice_scam(
            "billing confirmation — auto renewal of $349 — to cancel call 1-800-555-0100"
        ));
        assert!(has_tech_support_invoice_scam(
            "subscription has been renewed — $549 — to report fraud call support"
        ));
    }

    #[test]
    fn invoice_scam_fires_jp() {
        assert!(has_tech_support_invoice_scam(
            "ご請求が完了しました。請求に心当たりのない場合はご解約はお電話でご連絡ください。"
        ));
        assert!(has_tech_support_invoice_scam(
            "自動更新料金¥49800が課金されました。キャンセルするには電話してください。"
        ));
    }

    #[test]
    fn invoice_scam_does_not_fire_on_benign() {
        // Charge claim without cancel instruction
        assert!(!has_tech_support_invoice_scam(
            "billing confirmation — your order has been charged — thank you!"
        ));
        // Cancel instruction without charge claim
        assert!(!has_tech_support_invoice_scam(
            "to cancel your subscription please call our support line"
        ));
        // Expired subscription without charge claim
        assert!(!has_tech_support_invoice_scam(
            "your subscription has expired — renew to restore access"
        ));
    }

    #[test]
    fn invoice_scam_does_not_fire_jp_benign() {
        // Legitimate renewal confirmation without cancel cta
        assert!(!has_tech_support_invoice_scam(
            "ご請求が完了しました。ご利用ありがとうございます。"
        ));
        // Legitimate cancellation guidance without charge claim
        assert!(!has_tech_support_invoice_scam(
            "解約の手続きはマイページからお手続きください。"
        ));
    }

    // ── has_utility_cutoff_threat ────────────────────────────────────────────

    #[test]
    fn utility_cutoff_fires_on_electric_disconnection() {
        assert!(has_utility_cutoff_threat(
            "your electricity service will be disconnected in 2 hours pay immediately"
        ));
        assert!(has_utility_cutoff_threat(
            "final notice — electric service disconnection notice — avoid disconnection now"
        ));
    }

    #[test]
    fn utility_cutoff_fires_on_gas_termination() {
        assert!(has_utility_cutoff_threat(
            "gas service will be shut off today — pay to avoid disconnection"
        ));
        assert!(has_utility_cutoff_threat(
            "your natural gas service will be terminated — immediate payment required"
        ));
    }

    #[test]
    fn utility_cutoff_fires_jp() {
        assert!(has_utility_cutoff_threat(
            "電気の停止予告です。料金未払いのため供給停止となります。即時お支払いください。"
        ));
        assert!(has_utility_cutoff_threat(
            "ガスの供給停止予告。強制停止を避けるため即時お支払いください。"
        ));
    }

    #[test]
    fn utility_cutoff_does_not_fire_on_benign() {
        // Utility service mention without threat
        assert!(!has_utility_cutoff_threat(
            "electricity usage report for this month — thank you"
        ));
        // Cutoff language without utility noun
        assert!(!has_utility_cutoff_threat(
            "your account will be disconnected — final notice"
        ));
        // Scheduled maintenance notice (not a threat)
        assert!(!has_utility_cutoff_threat(
            "electric service maintenance scheduled for saturday"
        ));
    }

    #[test]
    fn utility_cutoff_does_not_fire_jp_benign() {
        // Legitimate bill notification
        assert!(!has_utility_cutoff_threat(
            "電気代のご請求書が届きました。ご確認ください。"
        ));
        // Maintenance notice
        assert!(!has_utility_cutoff_threat("ガスの点検のお知らせ"));
    }

    // ── has_healthcare_scam ──────────────────────────────────────────────────

    #[test]
    fn healthcare_scam_fires_on_medicare_expiring() {
        assert!(has_healthcare_scam(
            "your medicare benefits will expire — call to claim your free medical device"
        ));
        assert!(has_healthcare_scam(
            "medicare enrollment period ends soon — you have been approved at no cost to you"
        ));
    }

    #[test]
    fn healthcare_scam_fires_on_health_insurance_free_offer() {
        assert!(has_healthcare_scam(
            "your health insurance plan expiring soon — claim your free benefits today"
        ));
        assert!(has_healthcare_scam(
            "health coverage limited time offer — qualify for free at no cost to you"
        ));
    }

    #[test]
    fn healthcare_scam_fires_jp() {
        assert!(has_healthcare_scam(
            "健康保険の受給期限が近づいています。無料で受け取るにはお電話ください。"
        ));
        assert!(has_healthcare_scam(
            "介護保険の給付が承認されました。申請期限内にお手続きください。"
        ));
    }

    #[test]
    fn healthcare_scam_does_not_fire_on_benign() {
        // Health plan mention without urgency
        assert!(!has_healthcare_scam(
            "your medicare account summary — view your benefits"
        ));
        // Urgency without health term
        assert!(!has_healthcare_scam(
            "limited time offer — claim your free gift today"
        ));
        // Legitimate annual benefits renewal (no scam framing)
        assert!(!has_healthcare_scam(
            "dental coverage is available for review — contact hr"
        ));
    }

    #[test]
    fn healthcare_scam_does_not_fire_jp_benign() {
        // Legitimate insurance card renewal
        assert!(!has_healthcare_scam(
            "保険証の更新についてのお知らせです。手続き方法をご確認ください。"
        ));
        // Health plan information page
        assert!(!has_healthcare_scam("国民健康保険の加入手続きのご案内"));
    }

    // ── has_job_scam ─────────────────────────────────────────────────────────

    #[test]
    fn job_scam_fires_on_work_from_home_plus_registration_fee() {
        assert!(has_job_scam(
            "work from home — easy money opportunity — registration fee required to start"
        ));
        assert!(has_job_scam(
            "data entry job — part time job available — pay to start — starter kit fee $49"
        ));
    }

    #[test]
    fn job_scam_fires_on_hiring_plus_deposit() {
        assert!(has_job_scam(
            "hiring now — work at home — refundable deposit required — equipment deposit $199"
        ));
        assert!(has_job_scam(
            "remote work opportunity — flexible work — background check fee upfront fee required"
        ));
    }

    #[test]
    fn job_scam_fires_jp() {
        assert!(has_job_scam(
            "在宅ワークで月収50万円。副業募集中。登録料3000円が必要です。"
        ));
        assert!(has_job_scam(
            "内職・テレワーク求人。保証金をお預けいただきます。初期費用が必要。"
        ));
    }

    #[test]
    fn job_scam_does_not_fire_on_benign() {
        // Legitimate job listing — no fee
        assert!(!has_job_scam(
            "work from home position available — apply now — no experience required"
        ));
        // Fee without job offer
        assert!(!has_job_scam("equipment deposit required for this rental"));
        // Legitimate training program — no job offer keyword
        assert!(!has_job_scam(
            "training fee: $99 for the certification course"
        ));
    }

    #[test]
    fn job_scam_does_not_fire_jp_benign() {
        // Legitimate job post without fee
        assert!(!has_job_scam(
            "在宅ワーク・テレワークの求人情報サイト。無料登録で転職。"
        ));
        // Legitimate membership fee without job offer
        assert!(!has_job_scam("入会金は初回のみ5000円です。月会費は無料。"));
    }
}
