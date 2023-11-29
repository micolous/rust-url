// Copyright 2016 The rust-url developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This Rust crate implements IDNA
//! [per the WHATWG URL Standard](https://url.spec.whatwg.org/#idna).
//!
//! It also exposes the underlying algorithms from [*Unicode IDNA Compatibility Processing*
//! (Unicode Technical Standard #46)](http://www.unicode.org/reports/tr46/)
//! and [Punycode (RFC 3492)](https://tools.ietf.org/html/rfc3492).
//!
//! Quoting from [UTS #46’s introduction](http://www.unicode.org/reports/tr46/#Introduction):
//!
//! > Initially, domain names were restricted to ASCII characters.
//! > A system was introduced in 2003 for internationalized domain names (IDN).
//! > This system is called Internationalizing Domain Names for Applications,
//! > or IDNA2003 for short.
//! > This mechanism supports IDNs by means of a client software transformation
//! > into a format known as Punycode.
//! > A revision of IDNA was approved in 2010 (IDNA2008).
//! > This revision has a number of incompatibilities with IDNA2003.
//! >
//! > The incompatibilities force implementers of client software,
//! > such as browsers and emailers,
//! > to face difficult choices during the transition period
//! > as registries shift from IDNA2003 to IDNA2008.
//! > This document specifies a mechanism
//! > that minimizes the impact of this transition for client software,
//! > allowing client software to access domains that are valid under either system.
#![no_std]

// For forwards compatibility
#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

#[cfg(not(feature = "alloc"))]
compile_error!("the `alloc` feature must be enabled");

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

use alloc::string::String;
use core::fmt;

pub mod punycode;
#[cfg_attr(windows, path = "windows.rs")]
mod uts46;

pub use crate::uts46::Idna;

/// The [domain to ASCII](https://url.spec.whatwg.org/#concept-domain-to-ascii) algorithm.
///
/// Return the ASCII representation a domain name,
/// normalizing characters (upper-case to lower-case and other kinds of equivalence)
/// and using Punycode as necessary.
///
/// This process may fail.
pub fn domain_to_ascii(domain: &str) -> Result<String, Errors> {
    Config::default().to_ascii(domain)
}

/// The [domain to ASCII](https://url.spec.whatwg.org/#concept-domain-to-ascii) algorithm,
/// with the `beStrict` flag set.
pub fn domain_to_ascii_strict(domain: &str) -> Result<String, Errors> {
    Config::default()
        .use_std3_ascii_rules(true)
        .verify_dns_length(true)
        .to_ascii(domain)
}

/// The [domain to Unicode](https://url.spec.whatwg.org/#concept-domain-to-unicode) algorithm.
///
/// Return the Unicode representation of a domain name,
/// normalizing characters (upper-case to lower-case and other kinds of equivalence)
/// and decoding Punycode as necessary.
///
/// This may indicate [syntax violations](https://url.spec.whatwg.org/#syntax-violation)
/// but always returns a string for the mapped domain.
pub fn domain_to_unicode(domain: &str) -> (String, Result<(), Errors>) {
    Config::default().to_unicode(domain)
}

#[derive(Clone, Copy)]
#[must_use]
pub struct Config {
    use_std3_ascii_rules: bool,
    transitional_processing: bool,
    verify_dns_length: bool,
    check_hyphens: bool,
    use_idna_2008_rules: bool,
}

/// The defaults are that of https://url.spec.whatwg.org/#idna
impl Default for Config {
    fn default() -> Self {
        Config {
            use_std3_ascii_rules: false,
            transitional_processing: false,
            check_hyphens: false,
            // check_bidi: true,
            // check_joiners: true,

            // Only use for to_ascii, not to_unicode
            verify_dns_length: false,
            use_idna_2008_rules: false,
        }
    }
}

impl Config {
    #[inline]
    pub fn use_std3_ascii_rules(mut self, value: bool) -> Self {
        self.use_std3_ascii_rules = value;
        self
    }

    #[inline]
    pub fn transitional_processing(mut self, value: bool) -> Self {
        self.transitional_processing = value;
        self
    }

    #[inline]
    pub fn verify_dns_length(mut self, value: bool) -> Self {
        self.verify_dns_length = value;
        self
    }

    #[inline]
    pub fn check_hyphens(mut self, value: bool) -> Self {
        self.check_hyphens = value;
        self
    }

    #[inline]
    pub fn use_idna_2008_rules(mut self, value: bool) -> Self {
        self.use_idna_2008_rules = value;
        self
    }

    /// http://www.unicode.org/reports/tr46/#ToASCII
    pub fn to_ascii(self, domain: &str) -> Result<String, Errors> {
        let mut result = String::with_capacity(domain.len());
        let mut codec = Idna::new(self);
        codec.to_ascii(domain, &mut result).map(|()| result)
    }

    /// http://www.unicode.org/reports/tr46/#ToUnicode
    pub fn to_unicode(self, domain: &str) -> (String, Result<(), Errors>) {
        let mut codec = Idna::new(self);
        let mut out = String::with_capacity(domain.len());
        let result = codec.to_unicode(domain, &mut out);
        (out, result)
    }
}

/// Errors recorded during UTS #46 processing.
///
/// This is opaque for now, indicating what types of errors have been encountered at least once.
/// More details may be exposed in the future.
#[derive(Default)]
pub struct Errors {
    punycode: bool,
    check_hyphens: bool,
    check_bidi: bool,
    start_combining_mark: bool,
    invalid_mapping: bool,
    nfc: bool,
    disallowed_by_std3_ascii_rules: bool,
    disallowed_mapped_in_std3: bool,
    disallowed_character: bool,
    too_long_for_dns: bool,
    too_short_for_dns: bool,
    disallowed_in_idna_2008: bool,
    #[cfg(windows)]
    windows: Option<windows::core::Error>,
}

impl Errors {
    fn is_err(&self) -> bool {
        #[cfg(windows)]
        if self.windows.is_some() {
            return true;
        }

        self.punycode
            || self.check_hyphens
            || self.check_bidi
            || self.start_combining_mark
            || self.invalid_mapping
            || self.nfc
            || self.disallowed_by_std3_ascii_rules
            || self.disallowed_mapped_in_std3
            || self.disallowed_character
            || self.too_long_for_dns
            || self.too_short_for_dns
            || self.disallowed_in_idna_2008
    }
}

impl fmt::Debug for Errors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fields = [
            ("punycode", self.punycode),
            ("check_hyphens", self.check_hyphens),
            ("check_bidi", self.check_bidi),
            ("start_combining_mark", self.start_combining_mark),
            ("invalid_mapping", self.invalid_mapping),
            ("nfc", self.nfc),
            (
                "disallowed_by_std3_ascii_rules",
                self.disallowed_by_std3_ascii_rules,
            ),
            ("disallowed_mapped_in_std3", self.disallowed_mapped_in_std3),
            ("disallowed_character", self.disallowed_character),
            ("too_long_for_dns", self.too_long_for_dns),
            ("too_short_for_dns", self.too_short_for_dns),
            ("disallowed_in_idna_2008", self.disallowed_in_idna_2008),
        ];

        let mut empty = true;
        f.write_str("Errors { ")?;
        for (name, val) in &fields {
            if *val {
                if !empty {
                    f.write_str(", ")?;
                }
                f.write_str(name)?;
                empty = false;
            }
        }

        #[cfg(windows)]
        if let Some(windows) = &self.windows {
            if !empty {
                f.write_str(", ")?;
            }
            f.write_fmt(format_args!("windows: {:?}", windows))?;
            empty = false;
        }

        if !empty {
            f.write_str(" }")
        } else {
            f.write_str("}")
        }
    }
}

impl From<Errors> for Result<(), Errors> {
    fn from(e: Errors) -> Result<(), Errors> {
        if !e.is_err() {
            Ok(())
        } else {
            Err(e)
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Errors {}

impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// Detect simple cases: all lowercase ASCII characters and digits where none
// of the labels start with PUNYCODE_PREFIX and labels don't start or end with hyphen.
pub(crate) fn is_simple(domain: &str) -> bool {
    if domain.is_empty() {
        return false;
    }
    let (mut prev, mut puny_prefix) = ('?', 0);
    for c in domain.chars() {
        if c == '.' {
            if prev == '-' {
                return false;
            }
            puny_prefix = 0;
            continue;
        } else if puny_prefix == 0 && c == '-' {
            return false;
        } else if puny_prefix < 5 {
            if c == ['x', 'n', '-', '-'][puny_prefix] {
                puny_prefix += 1;
                if puny_prefix == 4 {
                    return false;
                }
            } else {
                puny_prefix = 5;
            }
        }
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() {
            return false;
        }
        prev = c;
    }

    true
}
