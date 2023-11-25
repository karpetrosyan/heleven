use regex::bytes::Regex;

static FIELD_VALUE_WITH_OWS: &str = concat!(
    r"^[ \t]*",
    r"(",
    r"[\x21-\x7e\x80-\xff]",                              // field-vchar
    r"([ \t[\x21-\x7e\x80-\xff]]+[\x21-\x7e\x80-\xff])?", // [ 1*( SP / HTAB / field-vchar ) field-vchar ]
    r")*",
    r"[ \t]*$",
);

trait CharABNF {
    fn is_alpha(&self) -> bool;
    fn is_bit(&self) -> bool;
    fn is_char(&self) -> bool;
    fn is_cr(&self) -> bool;
    fn is_crlf(&self) -> bool;
    fn is_ctl(&self) -> bool;
    fn is_digit(&self) -> bool;
    fn is_dquote(&self) -> bool;
    fn is_hexdig(&self) -> bool;
    fn is_htab(&self) -> bool;
    fn is_lf(&self) -> bool;
    fn is_octet(&self) -> bool;
    fn is_sp(&self) -> bool;
    fn is_vchar(&self) -> bool;
    fn is_wsp(&self) -> bool;
    fn is_tchar(&self) -> bool;
}

impl CharABNF for u8 {
    fn is_alpha(&self) -> bool {
        // A-Z / a-z
        (0x41..=0x5a).chain(0x61..=0x7a).any(|c| c == *self)
    }

    fn is_bit(&self) -> bool {
        // 0 / 1
        *self == 0x30 || *self == 0x31
    }

    fn is_char(&self) -> bool {
        // any 7-bit US-ASCII character, excluding NUL
        (0x01..=0x7f).contains(self)
    }

    fn is_cr(&self) -> bool {
        // carriage return
        *self == 0x0d
    }

    fn is_crlf(&self) -> bool {
        // Internet standard newline
        *self == 0x0d && *self == 0x0a
    }

    fn is_ctl(&self) -> bool {
        // controls
        (0x00..=0x1f).chain(0x7f..=0x7f).any(|c| c == *self)
    }

    fn is_digit(&self) -> bool {
        // 0-9
        (0x30..=0x39).contains(self)
    }

    fn is_dquote(&self) -> bool {
        // double quote
        *self == 0x22
    }

    fn is_hexdig(&self) -> bool {
        // 0-9 / A-F / a-f
        (0x30..=0x39)
            .chain(0x41..=0x46)
            .chain(0x61..=0x66)
            .any(|c| c == *self)
    }

    fn is_htab(&self) -> bool {
        // horizontal tab
        *self == 0x09
    }

    fn is_lf(&self) -> bool {
        // linefeed
        *self == 0x0a
    }

    fn is_octet(&self) -> bool {
        // 8 bits of data
        (0x00..=0xff).contains(self)
    }

    fn is_sp(&self) -> bool {
        // space
        *self == 0x20
    }

    fn is_vchar(&self) -> bool {
        // visible (printing) characters
        (0x21..=0x7e).contains(self)
    }

    fn is_wsp(&self) -> bool {
        // white space
        *self == 0x20 || *self == 0x09
    }

    fn is_tchar(&self) -> bool {
        // any VCHAR except delimiters
        self.is_alpha() || self.is_digit() || b"!#$%&'*+-.^_`|~".contains(self)
    }
}

#[derive(Debug, PartialEq)]
pub enum ParseError {
    InvalidHeaderKeyChar,
    InvalidHeaderValueChar,
    ColonNotFound,
    InvalidHeaderValue,
}

pub fn extract_header_lines(headers: &[u8]) -> Vec<&[u8]> {
    let mut header_lines: Vec<&[u8]> = Vec::new();

    for line in headers
        .split(|&c| c == b'\n')
        .filter(|&line| line.len() > 0)
    {
        if line[line.len() - 1] == b'\r' {
            header_lines.push(&line[..line.len() - 1]);
        } else {
            header_lines.push(line);
        }
    }

    header_lines
}

pub fn extract_header_name_value(header_line: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    let mut colon_index: Option<usize> = None;

    for (i, &c) in header_line.iter().enumerate() {
        if c == b':' {
            colon_index = Some(i);
            break;
        }

        if !c.is_tchar() {
            return Err(ParseError::InvalidHeaderKeyChar);
        }
    }

    let colon_index = colon_index.ok_or(ParseError::ColonNotFound)?;

    let re = Regex::new(FIELD_VALUE_WITH_OWS).expect("Invalid regex");
    let haystack = &header_line[colon_index + 1..];

    let capture = re
        .captures(haystack)
        .ok_or(ParseError::InvalidHeaderValue)?;

    let key = &header_line[..colon_index];
    let value = capture
        .get(1)
        .ok_or(ParseError::InvalidHeaderValue)?
        .as_bytes();

    Ok((key, value))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn extract_header_lines_with_carriage_return() {
        let headers = b"Content-Type: text/html\r\nContent-Length: 1234\r\n";

        let header_lines = extract_header_lines(headers);

        assert_eq!(header_lines.len(), 2);
        assert_eq!(header_lines[0], b"Content-Type: text/html");
        assert_eq!(header_lines[1], b"Content-Length: 1234");
    }

    #[test]
    fn extract_headers_without_carriage_return() {
        let headers = b"Content-Type: text/html\nContent-Length: 1234\n";

        let header_lines = extract_header_lines(headers);

        assert_eq!(header_lines.len(), 2);
        assert_eq!(header_lines[0], b"Content-Type: text/html");
        assert_eq!(header_lines[1], b"Content-Length: 1234");
    }

    #[test]
    fn extract_key_value_from_headerline_without_ows() {
        let header_line = b"Content-Type:text/html";

        let (key, value) = extract_header_name_value(header_line).unwrap();

        assert_eq!(key, b"Content-Type");
        assert_eq!(value, b"text/html");
    }

    #[test]
    fn extract_key_value_from_headerline_with_ows() {
        let header_line = b"Content-Type: text/html ";

        let (key, value) = extract_header_name_value(header_line).unwrap();

        assert_eq!(key, b"Content-Type");
        assert_eq!(value, b"text/html");
    }

    #[test]
    fn extract_key_value_from_headerline_with_multiple_ows() {
        let header_line = b"Content-Type:   text/html   ";

        let (key, value) = extract_header_name_value(header_line).unwrap();

        assert_eq!(key, b"Content-Type");
        assert_eq!(value, b"text/html");
    }

    #[test]
    fn extract_key_value_from_headerline_with_invalid_key_char() {
        let header_line = b"Content-T\nype: text/html";

        let result = extract_header_name_value(header_line);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParseError::InvalidHeaderKeyChar);
    }

    #[test]
    fn extract_key_value_from_headerline_without_colon() {
        let header_line = b"Content-Type";

        let result = extract_header_name_value(header_line);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParseError::ColonNotFound);
    }

    #[test]
    fn extract_key_value_from_headerline_with_invalid_value_char() {
        let header_line = b"Content-Type: text/ht\nml";

        let result = extract_header_name_value(header_line.as_slice());

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParseError::InvalidHeaderValue);
    }

    #[test]
    fn extract_key_value_from_user_agent_line() {
        let header_line = b"User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0";

        let (key, value) = extract_header_name_value(header_line).unwrap();

        assert_eq!(key, b"User-Agent");
        assert_eq!(
            value,
            b"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"
        );
    }
}
