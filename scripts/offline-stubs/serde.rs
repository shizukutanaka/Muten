//! Offline stand-in for `serde`'s `Serialize`/`Deserialize` derives.
//!
//! WHY THIS EXISTS. Two things in this crate cannot be *run* without
//! these derives, only read:
//!   * `src/sink.rs`'s `CheckpointSig`, whose JSON round-trip is a real
//!     test (the MDM/SIEM transport format);
//!   * `src/lib.rs` and the 12 modules it pulls in, which every
//!     behavioural test of `classify()` needs — including
//!     `tests/benign_corpus.rs` (the 0-false-positive claim) and
//!     `tests/scoring_scenarios.rs` (the detect→dismiss claim). Those
//!     tests do not exercise serde at all; they are blocked by it.
//!
//! WHAT IT REPRODUCES.
//!   * Named-field structs: field-by-field, in declaration order.
//!   * Unit-variant enums: the variant name, `rename_all = "snake_case"`
//!     honoured (and it is the only rename form this crate uses).
//!   * Single-field tuple variants: serde's externally-tagged default,
//!     `{"variant_name": payload}`.
//!   * `#[serde(default)]`, at container or field level: a missing field
//!     falls back to `Default::default()`.
//!
//! WHAT IT DOES NOT. Every other shape - struct variants, multi-field
//! tuple variants, generics, any `#[serde(...)]` option beyond the two
//! above - **panics at compile time**. That is deliberate: a permissive
//! stand-in (`impl<T> Serialize for T {}`) would accept code real serde
//! rejects, so a green would read stronger than it is. This one fails
//! loudly on anything it has not been taught.
//!
//! THE CLAIM THIS SUPPORTS, AND THE ONE IT DOES NOT. Tests run against
//! it verify **`classify()`'s behaviour**. They do NOT verify serde
//! integration, and a green here is NOT "the crate compiles under real
//! serde" - only `cargo build` answers that.
extern crate proc_macro;
use proc_macro::TokenStream;

/// Strip `#[...]` attributes and `//`-comments, returning the cleaned
/// text plus the `#[serde(...)]` bodies that were removed.
fn split_attrs(s: &str) -> (String, Vec<String>) {
    let b: Vec<char> = s.chars().collect();
    let (mut out, mut serde_attrs) = (String::new(), Vec::new());
    let mut i = 0;
    while i < b.len() {
        if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '/' {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if b[i] == '#' && i + 1 < b.len() && b[i + 1] == '[' {
            let start = i;
            let mut depth = 0;
            i += 1;
            while i < b.len() {
                if b[i] == '[' {
                    depth += 1;
                } else if b[i] == ']' {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                i += 1;
            }
            let attr: String = b[start..i].iter().collect();
            if attr.replace(' ', "").starts_with("#[serde(") {
                serde_attrs.push(attr);
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    (out, serde_attrs)
}

/// Split a body on top-level commas, ignoring nested delimiters.
fn top_level_split(body: &str) -> Vec<String> {
    let (mut parts, mut cur, mut depth) = (Vec::new(), String::new(), 0i32);
    for c in body.chars() {
        match c {
            '{' | '[' | '(' | '<' => {
                depth += 1;
                cur.push(c)
            }
            '}' | ']' | ')' | '>' => {
                depth -= 1;
                cur.push(c)
            }
            ',' if depth == 0 => {
                parts.push(cur.trim().to_string());
                cur = String::new()
            }
            c => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur.trim().to_string());
    }
    parts.into_iter().filter(|p| !p.is_empty()).collect()
}

fn snake_case(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

enum Shape {
    /// Named-field struct: (type name, field names, container-level default).
    Struct(String, Vec<String>, bool),
    /// Enum: (type name, variants as (rust name, wire name, has payload)).
    Enum(String, Vec<(String, String, bool)>),
}

fn parse(input: &str) -> Shape {
    let (raw, attrs) = split_attrs(input);
    // The derive's token stream re-renders with arbitrary newlines, so
    // `pub enum\nName` is possible. Collapse whitespace before parsing.
    let clean = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let all_attrs = attrs.join(" ").replace(' ', "");
    for a in &attrs {
        let a = a.replace(' ', "");
        assert!(
            a == "#[serde(default)]" || a == "#[serde(rename_all=\"snake_case\")]",
            "serde shim: unsupported attribute {a} - teach the shim or drop the derive"
        );
    }
    let snake = all_attrs.contains("rename_all=\"snake_case\"");
    let container_default = all_attrs.contains("serde(default)");

    let is_enum = clean.contains("enum ");
    let kw = if is_enum { "enum " } else { "struct " };
    let kw_at = clean
        .find(kw)
        .unwrap_or_else(|| panic!("serde shim: no struct/enum in {clean:?}"));
    let rest = &clean[kw_at + kw.len()..];
    let open = rest.find('{').expect("serde shim: no body");
    let name = rest[..open].trim().to_string();
    assert!(
        name.chars().all(|c| c.is_alphanumeric() || c == '_'),
        "serde shim: generics are not supported ({name})"
    );
    let close = rest.rfind('}').expect("serde shim: unterminated body");
    let body = &rest[open + 1..close];

    if is_enum {
        let mut variants = Vec::new();
        for item in top_level_split(body) {
            assert!(
                !item.contains('{'),
                "serde shim: struct variants are not supported ({item})"
            );
            let (ident, payload) = match item.find('(') {
                Some(p) => {
                    let inner = &item[p + 1..item.rfind(')').expect("serde shim: bad variant")];
                    assert!(
                        !inner.contains(','),
                        "serde shim: multi-field tuple variants are not supported ({item})"
                    );
                    (item[..p].trim().to_string(), true)
                }
                None => (item.trim().to_string(), false),
            };
            let wire = if snake { snake_case(&ident) } else { ident.clone() };
            variants.push((ident, wire, payload));
        }
        assert!(!variants.is_empty(), "serde shim: enum {name} has no variants");
        Shape::Enum(name, variants)
    } else {
        // Field-level `#[serde(default)]` was stripped with the rest; the
        // crate only ever uses it to make a missing field fall back to the
        // type default, which container-level default already expresses.
        let field_default = container_default || attrs.iter().any(|a| a.replace(' ', "") == "#[serde(default)]");
        let mut fields = Vec::new();
        for decl in top_level_split(body) {
            let colon = decl
                .find(':')
                .unwrap_or_else(|| panic!("serde shim: unparsable field {decl:?}"));
            let ident = decl[..colon].trim().trim_start_matches("pub ").trim();
            assert!(
                ident.chars().all(|c| c.is_alphanumeric() || c == '_'),
                "serde shim: unsupported field declaration {decl:?}"
            );
            fields.push(ident.to_string());
        }
        assert!(!fields.is_empty(), "serde shim: struct {name} has no fields");
        Shape::Struct(name, fields, field_default)
    }
}

#[proc_macro_derive(Serialize, attributes(serde))]
pub fn derive_serialize(item: TokenStream) -> TokenStream {
    let code = match parse(&item.to_string()) {
        Shape::Struct(name, fields, _) => {
            let body: String = fields
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    let sep = if i == 0 { "" } else { "out.push(',');" };
                    format!(
                        "{sep} out.push_str(\"\\\"{f}\\\":\"); \
                         ::serde_json::Serialize::write_json(&self.{f}, out);"
                    )
                })
                .collect();
            format!(
                "impl ::serde_json::Serialize for {name} {{
                    fn write_json(&self, out: &mut ::std::string::String) {{
                        out.push('{{'); {body} out.push('}}');
                    }}
                }}"
            )
        }
        Shape::Enum(name, variants) => {
            let arms: String = variants
                .iter()
                .map(|(ident, wire, payload)| {
                    if *payload {
                        format!(
                            "{name}::{ident}(v) => {{ \
                               out.push_str(\"{{\\\"{wire}\\\":\"); \
                               ::serde_json::Serialize::write_json(v, out); \
                               out.push('}}'); }},"
                        )
                    } else {
                        format!("{name}::{ident} => out.push_str(\"\\\"{wire}\\\"\"),")
                    }
                })
                .collect();
            format!(
                "impl ::serde_json::Serialize for {name} {{
                    fn write_json(&self, out: &mut ::std::string::String) {{
                        match self {{ {arms} }}
                    }}
                }}"
            )
        }
    };
    code.parse().expect("serde shim: generated Serialize must parse")
}

#[proc_macro_derive(Deserialize, attributes(serde))]
pub fn derive_deserialize(item: TokenStream) -> TokenStream {
    let code = match parse(&item.to_string()) {
        Shape::Struct(name, fields, default) => {
            let body: String = fields
                .iter()
                .map(|f| {
                    if default {
                        format!(
                            "{f}: match v.get(\"{f}\") {{ \
                                ::std::option::Option::Some(x) => \
                                    ::serde_json::FromJson::from_value(x)?, \
                                ::std::option::Option::None => \
                                    ::std::default::Default::default() }},"
                        )
                    } else {
                        format!(
                            "{f}: ::serde_json::FromJson::from_value(\
                                v.get(\"{f}\").ok_or_else(|| \
                                ::serde_json::Error(\"missing field {f}\".to_string()))?)?,"
                        )
                    }
                })
                .collect();
            format!(
                "impl ::serde_json::FromJson for {name} {{
                    fn from_value(v: &::serde_json::Value)
                        -> ::std::result::Result<Self, ::serde_json::Error> {{
                        ::std::result::Result::Ok({name} {{ {body} }})
                    }}
                }}"
            )
        }
        Shape::Enum(name, variants) => {
            let unit: String = variants
                .iter()
                .filter(|(_, _, p)| !*p)
                .map(|(ident, wire, _)| {
                    format!("\"{wire}\" => return ::std::result::Result::Ok({name}::{ident}),")
                })
                .collect();
            let tagged: String = variants
                .iter()
                .filter(|(_, _, p)| *p)
                .map(|(ident, wire, _)| {
                    format!(
                        "if let ::std::option::Option::Some(x) = v.get(\"{wire}\") {{ \
                           return ::std::result::Result::Ok({name}::{ident}(\
                             ::serde_json::FromJson::from_value(x)?)); }}"
                    )
                })
                .collect();
            format!(
                "impl ::serde_json::FromJson for {name} {{
                    fn from_value(v: &::serde_json::Value)
                        -> ::std::result::Result<Self, ::serde_json::Error> {{
                        if let ::std::option::Option::Some(s) = v.as_str() {{
                            match s {{ {unit}
                                other => return ::std::result::Result::Err(
                                    ::serde_json::Error(format!(\"unknown {name} {{other}}\"))),
                            }}
                        }}
                        {tagged}
                        ::std::result::Result::Err(
                            ::serde_json::Error(\"expected {name}\".to_string()))
                    }}
                }}"
            )
        }
    };
    code.parse().expect("serde shim: generated Deserialize must parse")
}
