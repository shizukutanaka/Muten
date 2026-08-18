//! Minimal but CORRECT JSON parser standing in for `serde_json`.
//! Only the surface the helper_reference tests use is provided.
use std::collections::BTreeMap;
use std::fmt;
use std::ops::Index;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null, Bool(bool), Num(f64), Str(String),
    Arr(Vec<Value>), Obj(BTreeMap<String, Value>),
}

#[derive(Debug)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl Value {
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        if let Value::Arr(a) = self { Some(a) } else { None }
    }
}

// `w["id"]` / `modal["window"]["blocks_input"]`
static NULL: Value = Value::Null;
impl Index<&str> for Value {
    type Output = Value;
    fn index(&self, k: &str) -> &Value {
        match self { Value::Obj(m) => m.get(k).unwrap_or(&NULL), _ => &NULL }
    }
}
// `w["id"] == "0x01"` and `x["blocks_input"] == true`
impl PartialEq<&str> for Value {
    fn eq(&self, o: &&str) -> bool { matches!(self, Value::Str(s) if s == *o) }
}
impl PartialEq<bool> for Value {
    fn eq(&self, o: &bool) -> bool { matches!(self, Value::Bool(b) if b == o) }
}

pub fn from_str(s: &str) -> Result<Value, Error> {
    let b: Vec<char> = s.chars().collect();
    let mut i = 0usize;
    let v = parse(&b, &mut i)?;
    skip_ws(&b, &mut i);
    if i != b.len() { return Err(Error(format!("trailing input at {i}"))); }
    Ok(v)
}

fn skip_ws(b: &[char], i: &mut usize) { while *i < b.len() && b[*i].is_whitespace() { *i += 1 } }

fn parse(b: &[char], i: &mut usize) -> Result<Value, Error> {
    skip_ws(b, i);
    if *i >= b.len() { return Err(Error("unexpected end".into())); }
    match b[*i] {
        '{' => { *i += 1; let mut m = BTreeMap::new();
            skip_ws(b, i);
            if *i < b.len() && b[*i] == '}' { *i += 1; return Ok(Value::Obj(m)); }
            loop {
                skip_ws(b, i);
                let k = match parse(b, i)? { Value::Str(s) => s, _ => return Err(Error("key".into())) };
                skip_ws(b, i);
                if *i >= b.len() || b[*i] != ':' { return Err(Error("expected :".into())); }
                *i += 1;
                m.insert(k, parse(b, i)?);
                skip_ws(b, i);
                match b.get(*i) {
                    Some(',') => { *i += 1 }
                    Some('}') => { *i += 1; break }
                    _ => return Err(Error("expected , or }".into())),
                }
            }
            Ok(Value::Obj(m)) }
        '[' => { *i += 1; let mut a = Vec::new();
            skip_ws(b, i);
            if *i < b.len() && b[*i] == ']' { *i += 1; return Ok(Value::Arr(a)); }
            loop {
                a.push(parse(b, i)?);
                skip_ws(b, i);
                match b.get(*i) {
                    Some(',') => { *i += 1 }
                    Some(']') => { *i += 1; break }
                    _ => return Err(Error("expected , or ]".into())),
                }
            }
            Ok(Value::Arr(a)) }
        '"' => { *i += 1; let mut s = String::new();
            loop {
                let c = *b.get(*i).ok_or_else(|| Error("unterminated string".into()))?;
                *i += 1;
                match c {
                    '"' => break,
                    '\\' => { let e = *b.get(*i).ok_or_else(|| Error("bad escape".into()))?; *i += 1;
                        s.push(match e {
                            'n' => '\n', 't' => '\t', 'r' => '\r', 'b' => '\u{8}', 'f' => '\u{c}',
                            'u' => { let h: String = b[*i..*i+4].iter().collect(); *i += 4;
                                     char::from_u32(u32::from_str_radix(&h, 16)
                                        .map_err(|_| Error("bad \\u".into()))?).unwrap_or('\u{fffd}') }
                            o => o,
                        }) }
                    // RFC 8259: raw control characters are illegal inside strings.
                    c if (c as u32) < 0x20 => return Err(Error(format!("raw control char {:#x}", c as u32))),
                    c => s.push(c),
                }
            }
            Ok(Value::Str(s)) }
        't' => { expect(b, i, "true")?; Ok(Value::Bool(true)) }
        'f' => { expect(b, i, "false")?; Ok(Value::Bool(false)) }
        'n' => { expect(b, i, "null")?; Ok(Value::Null) }
        _ => { let st = *i;
            if b[*i] == '-' { *i += 1 }
            while *i < b.len() && (b[*i].is_ascii_digit() || matches!(b[*i], '.'|'e'|'E'|'+'|'-')) { *i += 1 }
            let s: String = b[st..*i].iter().collect();
            s.parse::<f64>().map(Value::Num).map_err(|_| Error(format!("bad number {s:?}"))) }
    }
}

fn expect(b: &[char], i: &mut usize, w: &str) -> Result<(), Error> {
    for c in w.chars() {
        if b.get(*i) != Some(&c) { return Err(Error(format!("expected {w}"))); }
        *i += 1;
    }
    Ok(())
}

// serde_json::Value implements Display as compact JSON; the tests use it in
// assert! messages.
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => write!(f, "null"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Num(n) => write!(f, "{n}"),
            Value::Str(s) => write!(f, "{:?}", s),
            Value::Arr(a) => {
                write!(f, "[")?;
                for (i, v) in a.iter().enumerate() {
                    if i > 0 { write!(f, ",")? }
                    write!(f, "{v}")?;
                }
                write!(f, "]")
            }
            Value::Obj(m) => {
                write!(f, "{{")?;
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 { write!(f, ",")? }
                    write!(f, "{:?}:{}", k, v)?;
                }
                write!(f, "}}")
            }
        }
    }
}
