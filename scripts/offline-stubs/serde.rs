//! Offline stand-in for `serde`'s `Serialize`/`Deserialize` derives.
//!
//! WHY THIS EXISTS. `src/sink.rs`'s `CheckpointSig` - the signed
//! head-and-count blob an MDM ships to a SIEM - derives both. Without
//! them sink.rs does not compile, and none of its tests could run.
//!
//! SCOPE. Plain structs with named fields only: it emits impls of
//! `serde_json`'s `Serialize`/`FromJson` traits, field by field, in
//! declaration order. No enums, no generics, no `#[serde(...)]`
//! attributes, no borrowed deserialization. This is exactly the shape
//! `CheckpointSig` has; anything else will fail loudly at compile time
//! rather than silently testing something different.
extern crate proc_macro;
use proc_macro::TokenStream;

/// Strip `#[...]` attributes and `///` doc comments so the field list can
/// be read directly. Doc comments survive into the derive's token stream
/// on some rustc versions as literal `///` lines, so both forms go.
fn strip_attrs(s: &str) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '/' {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if b[i] == '#' && i + 1 < b.len() && b[i + 1] == '[' {
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
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// `(type name, field names)` for a named-field struct.
fn parse_struct(input: &str) -> (String, Vec<String>) {
    let s = strip_attrs(input);
    let kw = s
        .find("struct ")
        .unwrap_or_else(|| panic!("serde shim: only named-field structs are supported"));
    let rest = &s[kw + 7..];
    let open = rest
        .find('{')
        .unwrap_or_else(|| panic!("serde shim: only named-field structs are supported"));
    let name = rest[..open].trim().to_string();
    let close = rest
        .rfind('}')
        .unwrap_or_else(|| panic!("serde shim: unterminated struct body"));
    let body = &rest[open + 1..close];
    let mut fields = Vec::new();
    for decl in body.split(',') {
        let decl = decl.trim();
        if decl.is_empty() {
            continue;
        }
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
    (name, fields)
}

#[proc_macro_derive(Serialize)]
pub fn derive_serialize(item: TokenStream) -> TokenStream {
    let (name, fields) = parse_struct(&item.to_string());
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
    .parse()
    .expect("serde shim: generated Serialize must parse")
}

#[proc_macro_derive(Deserialize)]
pub fn derive_deserialize(item: TokenStream) -> TokenStream {
    let (name, fields) = parse_struct(&item.to_string());
    let body: String = fields
        .iter()
        .map(|f| {
            format!(
                "{f}: ::serde_json::FromJson::from_value(\
                    v.get(\"{f}\").ok_or_else(|| \
                    ::serde_json::Error(\"missing field {f}\".to_string()))?)?,"
            )
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
    .parse()
    .expect("serde shim: generated Deserialize must parse")
}
