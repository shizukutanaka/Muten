#[path = "__CONFUSABLES__"]
mod confusables;
include!("__SLICED__");

fn url_host(u: &str) -> &str { host_str(u) }

fn main() {
    // Legitimate URLs an enterprise fleet actually sees. Each is chosen to
    // exercise a specific signal's stated false-positive reasoning.
    let cases: &[(&str, &str)] = &[
        ("brand_impersonation (literal brand)", "https://www.microsoft.com/"),
        ("brand_impersonation (subdomain)",     "https://mail.google.com/"),
        ("brand_impersonation (JP brand)",      "https://www.mufg.jp/"),
        ("brand_impersonation (apple)",         "https://support.apple.com/en-us"),
        ("combosquat (legit concatenation)",    "https://windowsupdate.com/"),
        ("combosquat (hyphen, no brand)",       "https://corp-intranet.example/"),
        ("typosquat (real short domain)",       "https://amazon.com/"),
        ("typosquat (paypal real)",             "https://www.paypal.com/signin"),
        ("cloud storage (legit asset)",         "https://storage.googleapis.com/corp/report.pdf"),
        ("url path (security advisory)",        "https://github.com/org/repo/security/advisories"),
        ("intranet raw IP",                     "http://10.0.0.5/dashboard"),
    ];
    let mut fired = 0;
    for (label, url) in cases {
        let h = url_host(url);
        let mut hits: Vec<String> = vec![];
        if let Some(b) = brand_impersonation(h) { hits.push(format!("brand_impersonation({b})")); }
        if let Some((b, l)) = combosquat(h)     { hits.push(format!("combosquat({b}+{l})")); }
        if let Some(b) = typosquat_brand(h)     { hits.push(format!("typosquat({b})")); }
        if hits.is_empty() { println!("  clean  {label:<38} {h}"); }
        else { fired += 1; println!("  FIRES  {label:<38} {h} -> {hits:?}"); }
    }
    // Positive controls: these SHOULD fire, proving the probe has teeth.
    println!("\n  -- positive controls (must fire) --");
    let mut ctrl_ok = 0;
    for (label, url) in [("combosquat", "https://apple-support.example/"),
                         ("typosquat",  "https://amzon.com/")] {
        let h = url_host(url);
        let f = combosquat(h).is_some() || typosquat_brand(h).is_some() || brand_impersonation(h).is_some();
        println!("  {}  {label:<12} {h}", if f {"fires "} else {"MISS  "});
        if f { ctrl_ok += 1; }
    }
    println!("\n  legitimate URLs firing: {fired}/{}   positive controls firing: {ctrl_ok}/2", cases.len());
    std::process::exit(if fired == 0 && ctrl_ok == 2 { 0 } else { 1 });
}
