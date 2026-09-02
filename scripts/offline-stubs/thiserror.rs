//! Offline stand-in for `thiserror`'s `#[derive(Error)]`.
//!
//! WHY THIS EXISTS. `src/sink.rs`'s `ChainError` - the type every
//! audit-chain verification failure comes back as - derives
//! `thiserror::Error`. Without the derive the module does not compile, so
//! none of its tamper-detection tests could ever run offline.
//!
//! WHAT IT REPRODUCES AND WHAT IT DOES NOT. It accepts the `#[error(..)]`
//! helper attributes and emits `Display` (delegating to `Debug`) plus
//! `std::error::Error`. It does NOT reproduce the human-readable message
//! text, so THE EXACT WORDING OF ERROR MESSAGES IS NOT UNDER TEST HERE.
//! That is acceptable only because no sink.rs test asserts on the message
//! text - they match on the variant (`ChainError::Broken { line: 1, .. }`),
//! which this shim leaves completely untouched. If a test ever asserts on
//! wording, this shim must grow or the test must be excluded and said so.
extern crate proc_macro;
use proc_macro::TokenStream;

/// Name of the `enum`/`struct` a derive was applied to, taken from the
/// token stream (no `syn` available offline).
fn type_name(input: &str) -> String {
    let mut it = input.split_whitespace().peekable();
    while let Some(tok) = it.next() {
        if tok == "enum" || tok == "struct" {
            if let Some(name) = it.next() {
                return name
                    .trim_end_matches(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .to_string();
            }
        }
    }
    panic!("thiserror shim: no enum/struct name found");
}

#[proc_macro_derive(Error, attributes(error, source, from, backtrace))]
pub fn derive_error(item: TokenStream) -> TokenStream {
    let name = type_name(&item.to_string());
    format!(
        "impl ::std::fmt::Display for {name} {{
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {{
                ::std::fmt::Debug::fmt(self, f)
            }}
        }}
        impl ::std::error::Error for {name} {{}}"
    )
    .parse()
    .expect("thiserror shim: generated code must parse")
}
