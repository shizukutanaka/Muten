//! Minimal but CORRECT JSON standing in for `serde_json`.
//!
//! WHY THIS EXISTS. Several product modules (`src/sink.rs`, the helper
//! reference tests) parse and emit JSON, and this environment cannot
//! download crates. Without a stand-in, those tests can only be read,
//! never run. Only the surface those callers use is provided.
//!
//! WHAT IS FAITHFUL AND WHAT IS NOT. Variant names, map ordering
//! (`BTreeMap`, as upstream's default), integer-vs-float preservation,
//! and JSON string escaping follow `serde_json` so that parse → emit →
//! parse round-trips byte-for-byte. `scripts/check-sink.sh` proves the
//! round-trip before trusting any result built on it. What is NOT
//! provided: upstream's `Serialize`/`Deserialize` model (visitors,
//! borrowed data, `#[serde(...)]` options), error kinds, and
//! arbitrary-precision numbers. Byte-identical output with upstream on
//! every input is NOT claimed — only self-consistency, which is what the
//! hash-chain tests actually depend on.
use std::collections::BTreeMap;
use std::fmt;
use std::ops::Index;

/// A JSON number. Integers stay integers so `1` never re-emits as `1.0`
/// (which would break the canonical-form round-trip the chain hashes).
#[derive(Debug, Clone, PartialEq)]
pub enum Number {
    PosInt(u64),
    NegInt(i64),
    Float(f64),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

// Upstream implements `Eq` for both, so structs holding a `Value` can
// derive `Eq` (src/monitor.rs's AuditEvent does).
impl Eq for Number {}
impl Eq for Value {}

#[derive(Debug)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Value {
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        if let Value::Array(a) = self {
            Some(a)
        } else {
            None
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        if let Value::String(s) = self {
            Some(s.as_str())
        } else {
            None
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(Number::PosInt(n)) => Some(*n),
            Value::Number(Number::NegInt(n)) if *n >= 0 => Some(*n as u64),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        if let Value::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
    pub fn get<I: ValueIndex>(&self, index: I) -> Option<&Value> {
        index.index_into(self)
    }
}

/// Mirrors upstream's `serde_json::value::Index` for the two forms the
/// callers use: object key and array position.
pub trait ValueIndex {
    fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value>;
}
impl ValueIndex for &str {
    fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value> {
        match v {
            Value::Object(m) => m.get(*self),
            _ => None,
        }
    }
}
impl ValueIndex for usize {
    fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value> {
        match v {
            Value::Array(a) => a.get(*self),
            _ => None,
        }
    }
}

// `w["id"]` / `modal["window"]["blocks_input"]`
static NULL: Value = Value::Null;
impl Index<&str> for Value {
    type Output = Value;
    fn index(&self, k: &str) -> &Value {
        match self {
            Value::Object(m) => m.get(k).unwrap_or(&NULL),
            _ => &NULL,
        }
    }
}
// `w["id"] == "0x01"` and `x["blocks_input"] == true`
impl PartialEq<&str> for Value {
    fn eq(&self, o: &&str) -> bool {
        matches!(self, Value::String(s) if s == *o)
    }
}
impl PartialEq<bool> for Value {
    fn eq(&self, o: &bool) -> bool {
        matches!(self, Value::Bool(b) if b == o)
    }
}

// ── Building values (the `json!` macro's expression leaves) ──────────

/// How a Rust value becomes a `Value` inside `json!`.
pub trait ToValue {
    fn to_value(&self) -> Value;
}
macro_rules! to_value_uint {
    ($($t:ty),*) => { $( impl ToValue for $t {
        fn to_value(&self) -> Value { Value::Number(Number::PosInt(*self as u64)) }
    } )* };
}
macro_rules! to_value_int {
    ($($t:ty),*) => { $( impl ToValue for $t {
        fn to_value(&self) -> Value {
            if *self >= 0 { Value::Number(Number::PosInt(*self as u64)) }
            else { Value::Number(Number::NegInt(*self as i64)) }
        }
    } )* };
}
to_value_uint!(u8, u16, u32, u64, usize);
to_value_int!(i8, i16, i32, i64, isize);
impl ToValue for f64 {
    fn to_value(&self) -> Value {
        Value::Number(Number::Float(*self))
    }
}
impl ToValue for bool {
    fn to_value(&self) -> Value {
        Value::Bool(*self)
    }
}
impl ToValue for str {
    fn to_value(&self) -> Value {
        Value::String(self.to_string())
    }
}
impl ToValue for String {
    fn to_value(&self) -> Value {
        Value::String(self.clone())
    }
}
impl ToValue for Value {
    fn to_value(&self) -> Value {
        self.clone()
    }
}
impl<T: ToValue + ?Sized> ToValue for &T {
    fn to_value(&self) -> Value {
        (**self).to_value()
    }
}
impl<T: ToValue> ToValue for Vec<T> {
    fn to_value(&self) -> Value {
        Value::Array(self.iter().map(ToValue::to_value).collect())
    }
}
impl<T: ToValue> ToValue for [T] {
    fn to_value(&self) -> Value {
        Value::Array(self.iter().map(ToValue::to_value).collect())
    }
}
impl<T: ToValue, const N: usize> ToValue for [T; N] {
    fn to_value(&self) -> Value {
        Value::Array(self.iter().map(ToValue::to_value).collect())
    }
}

/// Object-body muncher for [`json!`]. Nested `{}`/`[]` are recognised as
/// token groups first, so they recurse into `json!` rather than being
/// mis-parsed as Rust blocks; everything else is a plain expression.
#[macro_export]
#[doc(hidden)]
macro_rules! json_obj {
    ($m:ident) => {};
    ($m:ident ,) => {};
    ($m:ident $k:tt : { $($inner:tt)* } , $($rest:tt)*) => {
        $m.insert(::std::string::String::from($k), $crate::json!({ $($inner)* }));
        $crate::json_obj!($m $($rest)*);
    };
    ($m:ident $k:tt : { $($inner:tt)* }) => {
        $m.insert(::std::string::String::from($k), $crate::json!({ $($inner)* }));
    };
    ($m:ident $k:tt : [ $($inner:tt)* ] , $($rest:tt)*) => {
        $m.insert(::std::string::String::from($k), $crate::json!([ $($inner)* ]));
        $crate::json_obj!($m $($rest)*);
    };
    ($m:ident $k:tt : [ $($inner:tt)* ]) => {
        $m.insert(::std::string::String::from($k), $crate::json!([ $($inner)* ]));
    };
    ($m:ident $k:tt : $v:expr , $($rest:tt)*) => {
        $m.insert(::std::string::String::from($k), $crate::ToValue::to_value(&$v));
        $crate::json_obj!($m $($rest)*);
    };
    ($m:ident $k:tt : $v:expr) => {
        $m.insert(::std::string::String::from($k), $crate::ToValue::to_value(&$v));
    };
}

/// Array-body muncher for [`json!`].
#[macro_export]
#[doc(hidden)]
macro_rules! json_arr {
    ($a:ident) => {};
    ($a:ident ,) => {};
    ($a:ident { $($inner:tt)* } , $($rest:tt)*) => {
        $a.push($crate::json!({ $($inner)* }));
        $crate::json_arr!($a $($rest)*);
    };
    ($a:ident { $($inner:tt)* }) => {
        $a.push($crate::json!({ $($inner)* }));
    };
    ($a:ident [ $($inner:tt)* ] , $($rest:tt)*) => {
        $a.push($crate::json!([ $($inner)* ]));
        $crate::json_arr!($a $($rest)*);
    };
    ($a:ident [ $($inner:tt)* ]) => {
        $a.push($crate::json!([ $($inner)* ]));
    };
    ($a:ident $v:expr , $($rest:tt)*) => {
        $a.push($crate::ToValue::to_value(&$v));
        $crate::json_arr!($a $($rest)*);
    };
    ($a:ident $v:expr) => {
        $a.push($crate::ToValue::to_value(&$v));
    };
}

/// `serde_json::json!` for the shapes the product uses.
#[macro_export]
macro_rules! json {
    (null) => { $crate::Value::Null };
    ({ $($tt:tt)* }) => {{
        #[allow(unused_mut)]
        let mut m = ::std::collections::BTreeMap::new();
        $crate::json_obj!(m $($tt)*);
        $crate::Value::Object(m)
    }};
    ([ $($tt:tt)* ]) => {{
        #[allow(unused_mut)]
        let mut a = ::std::vec::Vec::new();
        $crate::json_arr!(a $($tt)*);
        $crate::Value::Array(a)
    }};
    ($v:expr) => { $crate::ToValue::to_value(&$v) };
}

// ── Emitting ────────────────────────────────────────────────────────

/// RFC 8259 string escaping, matching `serde_json`: the two mandatory
/// escapes, the five short forms, `\u00XX` for the remaining control
/// characters, and non-ASCII passed through as UTF-8.
fn escape_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Anything `to_string` can serialize. Only the callers' shapes.
pub trait Serialize {
    fn write_json(&self, out: &mut String);
}
impl Serialize for Value {
    fn write_json(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(Number::PosInt(n)) => out.push_str(&n.to_string()),
            Value::Number(Number::NegInt(n)) => out.push_str(&n.to_string()),
            Value::Number(Number::Float(n)) => out.push_str(&n.to_string()),
            Value::String(s) => escape_into(out, s),
            Value::Array(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write_json(out);
                }
                out.push(']');
            }
            Value::Object(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    escape_into(out, k);
                    out.push(':');
                    v.write_json(out);
                }
                out.push('}');
            }
        }
    }
}
impl Serialize for str {
    fn write_json(&self, out: &mut String) {
        escape_into(out, self);
    }
}
impl Serialize for String {
    fn write_json(&self, out: &mut String) {
        escape_into(out, self);
    }
}
macro_rules! serialize_scalar {
    ($($t:ty),*) => { $( impl Serialize for $t {
        fn write_json(&self, out: &mut String) { out.push_str(&self.to_string()); }
    } )* };
}
serialize_scalar!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize, f64);
impl Serialize for bool {
    fn write_json(&self, out: &mut String) {
        out.push_str(if *self { "true" } else { "false" });
    }
}
impl<T: Serialize + ?Sized> Serialize for &T {
    fn write_json(&self, out: &mut String) {
        (**self).write_json(out);
    }
}

pub fn to_string<T: Serialize + ?Sized>(v: &T) -> Result<String, Error> {
    let mut s = String::new();
    v.write_json(&mut s);
    Ok(s)
}

// serde_json::Value implements Display as compact JSON.
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        self.write_json(&mut s);
        f.write_str(&s)
    }
}

// ── Parsing ─────────────────────────────────────────────────────────

/// The deserialization half, matching what `from_str::<T>` needs. The
/// `serde` derive shim emits impls of this for plain structs; upstream's
/// full `Deserialize` model (visitors, borrowed data, lifetimes) is not
/// reproduced.
pub trait FromJson: Sized {
    fn from_value(v: &Value) -> Result<Self, Error>;
}
impl FromJson for Value {
    fn from_value(v: &Value) -> Result<Self, Error> {
        Ok(v.clone())
    }
}
impl FromJson for String {
    fn from_value(v: &Value) -> Result<Self, Error> {
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| Error("expected string".into()))
    }
}
impl FromJson for bool {
    fn from_value(v: &Value) -> Result<Self, Error> {
        v.as_bool().ok_or_else(|| Error("expected bool".into()))
    }
}
macro_rules! from_json_uint {
    ($($t:ty),*) => { $( impl FromJson for $t {
        fn from_value(v: &Value) -> Result<Self, Error> {
            v.as_u64().and_then(|n| <$t>::try_from(n).ok())
                .ok_or_else(|| Error("expected integer".into()))
        }
    } )* };
}
from_json_uint!(u8, u16, u32, u64, usize);

pub fn from_str<T: FromJson>(s: &str) -> Result<T, Error> {
    T::from_value(&parse_value(s)?)
}

fn parse_value(s: &str) -> Result<Value, Error> {
    let b: Vec<char> = s.chars().collect();
    let mut i = 0usize;
    let v = parse(&b, &mut i)?;
    skip_ws(&b, &mut i);
    if i != b.len() {
        return Err(Error(format!("trailing input at {i}")));
    }
    Ok(v)
}

fn skip_ws(b: &[char], i: &mut usize) {
    while *i < b.len() && b[*i].is_whitespace() {
        *i += 1
    }
}

fn parse(b: &[char], i: &mut usize) -> Result<Value, Error> {
    skip_ws(b, i);
    if *i >= b.len() {
        return Err(Error("unexpected end".into()));
    }
    match b[*i] {
        '{' => {
            *i += 1;
            let mut m = BTreeMap::new();
            skip_ws(b, i);
            if *i < b.len() && b[*i] == '}' {
                *i += 1;
                return Ok(Value::Object(m));
            }
            loop {
                skip_ws(b, i);
                let k = match parse(b, i)? {
                    Value::String(s) => s,
                    _ => return Err(Error("key".into())),
                };
                skip_ws(b, i);
                if *i >= b.len() || b[*i] != ':' {
                    return Err(Error("expected :".into()));
                }
                *i += 1;
                m.insert(k, parse(b, i)?);
                skip_ws(b, i);
                match b.get(*i) {
                    Some(',') => *i += 1,
                    Some('}') => {
                        *i += 1;
                        break;
                    }
                    _ => return Err(Error("expected , or }".into())),
                }
            }
            Ok(Value::Object(m))
        }
        '[' => {
            *i += 1;
            let mut a = Vec::new();
            skip_ws(b, i);
            if *i < b.len() && b[*i] == ']' {
                *i += 1;
                return Ok(Value::Array(a));
            }
            loop {
                a.push(parse(b, i)?);
                skip_ws(b, i);
                match b.get(*i) {
                    Some(',') => *i += 1,
                    Some(']') => {
                        *i += 1;
                        break;
                    }
                    _ => return Err(Error("expected , or ]".into())),
                }
            }
            Ok(Value::Array(a))
        }
        '"' => {
            *i += 1;
            let mut s = String::new();
            loop {
                let c = *b.get(*i).ok_or_else(|| Error("unterminated string".into()))?;
                *i += 1;
                match c {
                    '"' => break,
                    '\\' => {
                        let e = *b.get(*i).ok_or_else(|| Error("bad escape".into()))?;
                        *i += 1;
                        s.push(match e {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            'b' => '\u{8}',
                            'f' => '\u{c}',
                            'u' => {
                                if *i + 4 > b.len() {
                                    return Err(Error("truncated \\u".into()));
                                }
                                let h: String = b[*i..*i + 4].iter().collect();
                                *i += 4;
                                char::from_u32(
                                    u32::from_str_radix(&h, 16)
                                        .map_err(|_| Error("bad \\u".into()))?,
                                )
                                .unwrap_or('\u{fffd}')
                            }
                            o => o,
                        })
                    }
                    // RFC 8259: raw control characters are illegal inside strings.
                    c if (c as u32) < 0x20 => {
                        return Err(Error(format!("raw control char {:#x}", c as u32)))
                    }
                    c => s.push(c),
                }
            }
            Ok(Value::String(s))
        }
        't' => {
            expect(b, i, "true")?;
            Ok(Value::Bool(true))
        }
        'f' => {
            expect(b, i, "false")?;
            Ok(Value::Bool(false))
        }
        'n' => {
            expect(b, i, "null")?;
            Ok(Value::Null)
        }
        _ => {
            let st = *i;
            if b[*i] == '-' {
                *i += 1
            }
            let mut floaty = false;
            while *i < b.len()
                && (b[*i].is_ascii_digit() || matches!(b[*i], '.' | 'e' | 'E' | '+' | '-'))
            {
                if matches!(b[*i], '.' | 'e' | 'E') {
                    floaty = true;
                }
                *i += 1;
            }
            let s: String = b[st..*i].iter().collect();
            if !floaty {
                if let Ok(n) = s.parse::<u64>() {
                    return Ok(Value::Number(Number::PosInt(n)));
                }
                if let Ok(n) = s.parse::<i64>() {
                    return Ok(Value::Number(Number::NegInt(n)));
                }
            }
            s.parse::<f64>()
                .map(|f| Value::Number(Number::Float(f)))
                .map_err(|_| Error(format!("bad number {s:?}")))
        }
    }
}

fn expect(b: &[char], i: &mut usize, w: &str) -> Result<(), Error> {
    for c in w.chars() {
        if b.get(*i) != Some(&c) {
            return Err(Error(format!("expected {w}")));
        }
        *i += 1;
    }
    Ok(())
}
