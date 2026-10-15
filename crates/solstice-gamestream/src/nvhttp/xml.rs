//! The XML NVHTTP returns.
//!
//! Sunshine serialises with `boost::property_tree`, so every response is
//! `<?xml version="1.0" encoding="utf-8"?><root status_code="200">...</root>`
//! with scalar children. That is the whole schema.

/// Escape text for an XML body or attribute.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Control characters are not representable in XML 1.0 at all, and
            // several of these fields echo attacker-supplied names.
            c if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' => {}
            c => out.push(c),
        }
    }
    out
}

/// A `<root status_code="...">` document under construction.
#[derive(Debug)]
pub struct Root {
    status_code: u16,
    status_message: Option<String>,
    body: String,
}

impl Root {
    /// A successful response.
    pub fn ok() -> Self {
        Self {
            status_code: 200,
            status_message: None,
            body: String::new(),
        }
    }

    /// An error response. Moonlight shows `status_message` to the user.
    pub fn error(status_code: u16, message: &str) -> Self {
        Self {
            status_code,
            status_message: Some(message.to_owned()),
            body: String::new(),
        }
    }

    /// Add `<name>value</name>`.
    pub fn child(mut self, name: &str, value: impl std::fmt::Display) -> Self {
        self.body
            .push_str(&format!("<{name}>{}</{name}>", escape(&value.to_string())));
        self
    }

    /// Add pre-rendered markup.
    pub fn raw(mut self, markup: &str) -> Self {
        self.body.push_str(markup);
        self
    }

    /// Render the document.
    pub fn render(&self) -> String {
        let status = match &self.status_message {
            Some(m) => format!(
                " status_code=\"{}\" status_message=\"{}\"",
                self.status_code,
                escape(m)
            ),
            None => format!(" status_code=\"{}\"", self.status_code),
        };
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><root{status}>{}</root>",
            self.body
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_the_documented_envelope() {
        let xml = Root::ok().child("paired", 1).render();
        assert_eq!(
            xml,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><root status_code=\"200\"><paired>1</paired></root>"
        );
    }

    #[test]
    fn errors_carry_a_message() {
        let xml = Root::error(401, "Unauthorized").render();
        assert!(xml.contains("status_code=\"401\""));
        assert!(xml.contains("status_message=\"Unauthorized\""));
    }

    /// Device names come straight off the query string.
    #[test]
    fn attacker_supplied_text_cannot_escape_the_document() {
        let xml = Root::ok()
            .child("devicename", "</root><evil a=\"1\">&")
            .render();
        assert!(!xml.contains("<evil"));
        assert!(xml.contains("&lt;/root&gt;"));
        assert!(xml.contains("&amp;"));
        assert_eq!(xml.matches("</root>").count(), 1);
    }

    #[test]
    fn control_characters_are_stripped() {
        assert_eq!(escape("a\u{0}b\u{1}c"), "abc");
        assert_eq!(escape("keep\tthese\n"), "keep\tthese\n");
    }
}
