use crate::{is_simple, Config, Errors};
use alloc::{string::String, vec, vec::Vec};
use windows::{
    core::{HSTRING, PCWSTR, PWSTR},
    Win32::{
        Foundation::GetLastError,
        Globalization::{IdnToAscii, IdnToUnicode, IDN_ALLOW_UNASSIGNED, IDN_USE_STD3_ASCII_RULES},
    },
};

#[derive(Default)]
pub struct Idna {
    config: Config,
    normalized: String,
    output: String,
}

impl Idna {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            normalized: String::new(),
            output: String::new(),
        }
    }

    /// http://www.unicode.org/reports/tr46/#ToASCII
    #[allow(clippy::wrong_self_convention)]
    pub fn to_ascii(&mut self, domain: &str, out: &mut String) -> Result<(), Errors> {
        let domain_wide = HSTRING::from(domain);
        let mut dwflags = 0;
        if self.config.use_std3_ascii_rules {
            dwflags |= IDN_USE_STD3_ASCII_RULES;
        }

        // Get the required buffer size
        let len = unsafe { IdnToAscii(dwflags, domain_wide.as_wide(), None) };

        if len <= 0 || len > u16::MAX.into() {
            let mut e = Errors::default();
            e.windows = unsafe { GetLastError() }.err();
            return Err(e);
        }

        let buffer_size = len as u16;
        let mut asciicharstr = Vec::new();
        asciicharstr.resize(buffer_size.into(), 0);

        let len = unsafe { IdnToAscii(dwflags, domain_wide.as_wide(), Some(&mut asciicharstr)) };

        if len <= 0 || len > (asciicharstr.len() as i32) {
            let mut e = Errors::default();
            e.windows = unsafe { GetLastError() }.err();
            return Err(e);
        }

        asciicharstr.truncate(len as usize);
        let s = String::from_utf16_lossy(&asciicharstr);
        out.push_str(&s);

        Ok(())
    }

    /// http://www.unicode.org/reports/tr46/#ToUnicode
    #[allow(clippy::wrong_self_convention)]
    pub fn to_unicode(&mut self, domain: &str, out: &mut String) -> Result<(), Errors> {
        if is_simple(domain) {
            out.push_str(domain);
            return Errors::default().into();
        }
        let domain_wide = HSTRING::from(domain);
        let mut dwflags = 0;
        if self.config.use_std3_ascii_rules {
            dwflags |= IDN_USE_STD3_ASCII_RULES;
        }

        // Get the required buffer size
        let len = unsafe { IdnToUnicode(dwflags, domain_wide.as_wide(), None) };

        if len <= 0 || len > u16::MAX.into() {
            let mut e = Errors::default();
            e.windows = unsafe { GetLastError() }.err();
            return Err(e);
        }

        let buffer_size = len as u16;
        let mut unicodecharstr = Vec::new();
        unicodecharstr.resize(buffer_size.into(), 0);

        let len =
            unsafe { IdnToUnicode(dwflags, domain_wide.as_wide(), Some(&mut unicodecharstr)) };

        if len <= 0 || len > (unicodecharstr.len() as i32) {
            let mut e = Errors::default();
            e.windows = unsafe { GetLastError() }.err();
            return Err(e);
        }

        unicodecharstr.truncate(len as usize);
        let s = String::from_utf16_lossy(&unicodecharstr);
        out.push_str(&s);

        Ok(())
    }
}
