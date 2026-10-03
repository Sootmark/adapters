//! RFC 4180 CSV, read record by record with the line each record starts
//! on (quoted fields may span lines), for importers of tools' CSV output.

/// One CSV record: its fields and the 1-based line it starts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvRecord {
    pub line: u64,
    pub fields: Vec<String>,
}

/// A malformed record, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvError {
    pub line: u64,
    pub message: &'static str,
}

/// Records of `text`, which may start with a UTF-8 byte order mark. Line
/// breaks are `\n` or `\r\n`; empty lines between records are skipped.
pub fn records(text: &str) -> impl Iterator<Item = Result<CsvRecord, CsvError>> + '_ {
    Reader {
        rest: text.strip_prefix('\u{feff}').unwrap_or(text),
        line: 1,
    }
}

struct Reader<'a> {
    rest: &'a str,
    line: u64,
}

impl Iterator for Reader<'_> {
    type Item = Result<CsvRecord, CsvError>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(after) = self
            .rest
            .strip_prefix("\r\n")
            .or_else(|| self.rest.strip_prefix('\n'))
        {
            self.rest = after;
            self.line += 1;
        }
        if self.rest.is_empty() {
            return None;
        }
        let start = self.line;
        let mut fields = Vec::new();
        let mut chars = self.rest.char_indices().peekable();
        let mut field = String::new();
        let mut quoted = false;
        let mut at_field_start = true;
        let mut end = self.rest.len();
        while let Some((index, c)) = chars.next() {
            if quoted {
                match c {
                    '"' if chars.peek().is_some_and(|&(_, next)| next == '"') => {
                        chars.next();
                        field.push('"');
                    }
                    '"' => quoted = false,
                    '\n' => {
                        self.line += 1;
                        field.push(c);
                    }
                    _ => field.push(c),
                }
                continue;
            }
            match c {
                '"' if at_field_start => {
                    quoted = true;
                    at_field_start = false;
                }
                ',' => {
                    fields.push(std::mem::take(&mut field));
                    at_field_start = true;
                }
                '\r' if chars.peek().is_some_and(|&(_, next)| next == '\n') => {}
                '\n' => {
                    end = index + 1;
                    self.line += 1;
                    break;
                }
                '"' => {
                    self.rest = "";
                    return Some(Err(CsvError {
                        line: start,
                        message: "quote inside an unquoted field",
                    }));
                }
                _ => {
                    field.push(c);
                    at_field_start = false;
                }
            }
        }
        if quoted {
            self.rest = "";
            return Some(Err(CsvError {
                line: start,
                message: "quoted field never closed",
            }));
        }
        fields.push(field);
        self.rest = &self.rest[end..];
        Some(Ok(CsvRecord {
            line: start,
            fields,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(text: &str) -> Vec<Result<CsvRecord, CsvError>> {
        records(text).collect()
    }

    #[test]
    fn reads_quotes_escapes_and_line_breaks() {
        let rows = all("\u{feff}a,\"b,c\",\"say \"\"hi\"\"\"\r\n\r\n\"multi\nline\",x\n1,,\n");
        let fields: Vec<Vec<String>> = rows.iter().map(|r| r.clone().unwrap().fields).collect();
        assert_eq!(fields[0], ["a", "b,c", "say \"hi\""]);
        assert_eq!(fields[1], ["multi\nline", "x"]);
        assert_eq!(fields[2], ["1", "", ""]);
        let lines: Vec<u64> = rows.iter().map(|r| r.clone().unwrap().line).collect();
        assert_eq!(lines, [1, 3, 5]);
    }

    #[test]
    fn reports_broken_quoting() {
        assert_eq!(
            all("a,\"open\n").pop(),
            Some(Err(CsvError {
                line: 1,
                message: "quoted field never closed"
            }))
        );
        assert!(all("a,b\"c\n")[0].is_err());
        assert_eq!(
            all("last,row").pop().unwrap().unwrap().fields,
            ["last", "row"]
        );
    }
}
