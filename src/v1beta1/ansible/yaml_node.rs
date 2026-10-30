//! Reading the author's playbook the way Ansible will.
//!
//! The operator does not hand the playbook to Ansible as written: [`super::render_playbook`] parses
//! it, appends the completion-marker play and writes it out again. Whatever Ansible would have read
//! from the original has to survive that round trip, and two things make that harder than it looks:
//!
//! - **Tags.** `!vault` (an inline-encrypted value) and `!unsafe` (a string Jinja must not template)
//!   only mean something while they are attached to their node. A generic value such as
//!   `serde_json::Value` has nowhere to put a tag and silently drops it, which turns `!unsafe` text
//!   into a template Ansible evaluates. [`YamlNode`] keeps the tag of every node, keys included.
//! - **YAML 1.1.** Ansible reads YAML 1.1 through PyYAML, where an unquoted `0644` is octal,
//!   `yes`/`on` are booleans, `1:30` is the number 90 and `2024-01-15` is a date. [`parse_playbook`]
//!   gives every plain scalar the type PyYAML gives it, and [`to_string`] quotes every string a
//!   YAML 1.1 reader would mistake for something else.
//!
//! The types cannot come from serde-saphyr's own reading. It follows YAML 1.2 with some YAML 1.1
//! additions, which is neither what the spec says nor what PyYAML does: it reads `y` and `n` as
//! booleans, `09` as the float 9.0 and `1:30` as a string. So [`YamlNode::resolve_plain_scalars`]
//! takes each untagged plain scalar's spelling from the source and resolves it the way PyYAML's
//! resolver and `SafeConstructor` do; serde-saphyr only supplies structure, tags and spans.

use std::fmt;
use std::sync::LazyLock;

use regex::Regex;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_saphyr::options::NonFiniteFloatPolicy;
use serde_saphyr::{Location, Spanned, Tagged};

/// Parses a playbook, which has to be a sequence of plays, the way Ansible reads the same text.
pub fn parse_playbook(input: &str) -> Result<Vec<YamlNode>, serde_saphyr::Error> {
    let mut plays: Vec<YamlNode> = parse(input)?;
    for play in &mut plays {
        play.resolve_plain_scalars(input);
    }
    Ok(plays)
}

/// Parses any YAML document the way Ansible reads the same text.
pub fn parse_document(input: &str) -> Result<YamlNode, serde_saphyr::Error> {
    let mut document: YamlNode = parse(input)?;
    document.resolve_plain_scalars(input);
    Ok(document)
}

/// Not public on its own: the plain scalars of a tree parsed here carry serde-saphyr's types until
/// [`YamlNode::resolve_plain_scalars`] has run over it.
fn parse<'de, T: Deserialize<'de>>(input: &'de str) -> Result<T, serde_saphyr::Error> {
    let mut options = serde_saphyr::Options::default();
    // `.inf` and `.nan` are ordinary YAML 1.1 floats; the default rejects them for any target that
    // does not ask for a float by type, which a generic tree never does.
    options.non_finite_float_policy = NonFiniteFloatPolicy::PassThrough;
    serde_saphyr::from_str_with_options(input, options)
}

/// What PyYAML reads from a plain scalar.
enum Resolved {
    Value(Content),
    /// A value [`Content`] cannot hold: a date or date-time, or a number beyond 64 bits. It is
    /// written back as its spelling with this tag: serde-saphyr quotes such a string, and the tag
    /// makes PyYAML construct the value from it all the same.
    Tagged(&'static str),
    String,
}

// PyYAML's implicit resolvers (`yaml/resolver.py`), with the verbose-mode whitespace removed. Tried
// in PyYAML's order; the boolean one is `yaml_1_1_boolean`.
static FLOAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$",
    )
    .unwrap()
});
static INT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$",
    )
    .unwrap()
});
static NULL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:~|null|Null|NULL|)$").unwrap());
static TIMESTAMP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$",
    )
    .unwrap()
});

/// What PyYAML, and so Ansible, reads from a plain scalar spelled `spelling`.
fn resolve_plain(spelling: &str) -> Resolved {
    if let Some(value) = yaml_1_1_boolean(spelling) {
        Resolved::Value(Content::Bool(value))
    } else if FLOAT.is_match(spelling) {
        yaml_1_1_float(spelling).map_or(Resolved::Tagged("tag:yaml.org,2002:float"), |value| {
            Resolved::Value(Content::Float(value))
        })
    } else if INT.is_match(spelling) {
        yaml_1_1_int(spelling).map_or(Resolved::Tagged("tag:yaml.org,2002:int"), Resolved::Value)
    } else if NULL.is_match(spelling) {
        Resolved::Value(Content::Null)
    } else if TIMESTAMP.is_match(spelling) {
        Resolved::Tagged("tag:yaml.org,2002:timestamp")
    } else {
        Resolved::String
    }
}

fn yaml_1_1_boolean(spelling: &str) -> Option<bool> {
    match spelling {
        "yes" | "Yes" | "YES" | "true" | "True" | "TRUE" | "on" | "On" | "ON" => Some(true),
        "no" | "No" | "NO" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF" => Some(false),
        _ => None,
    }
}

/// Splits off the sign the way `SafeConstructor` does, after dropping every `_`.
fn sign_and_magnitude(spelling: &str) -> (bool, String) {
    let value = spelling.replace('_', "");
    match value.strip_prefix('-') {
        Some(magnitude) => (true, magnitude.to_owned()),
        None => (false, value.strip_prefix('+').unwrap_or(&value).to_owned()),
    }
}

/// `SafeConstructor.construct_yaml_int`, for a spelling [`INT`] matched.
fn yaml_1_1_int(spelling: &str) -> Option<Content> {
    let (negative, digits) = sign_and_magnitude(spelling);
    let magnitude = if digits == "0" {
        0
    } else if let Some(binary) = digits.strip_prefix("0b") {
        u64::from_str_radix(binary, 2).ok()?
    } else if let Some(hex) = digits.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()?
    } else if digits.starts_with('0') {
        u64::from_str_radix(&digits, 8).ok()?
    } else if digits.contains(':') {
        digits.split(':').try_fold(0u64, |value, part| {
            value.checked_mul(60)?.checked_add(part.parse().ok()?)
        })?
    } else {
        digits.parse().ok()?
    };

    Some(if negative {
        Content::Int(0i64.checked_sub_unsigned(magnitude)?)
    } else {
        i64::try_from(magnitude).map_or(Content::UInt(magnitude), Content::Int)
    })
}

/// `SafeConstructor.construct_yaml_float`, for a spelling [`FLOAT`] matched.
fn yaml_1_1_float(spelling: &str) -> Option<f64> {
    let (negative, digits) = sign_and_magnitude(&spelling.to_lowercase());
    let magnitude = match digits.as_str() {
        ".inf" => f64::INFINITY,
        ".nan" => f64::NAN,
        // Summed from the last part up, as PyYAML does, so the rounding matches too.
        _ if digits.contains(':') => {
            let mut value = 0.0;
            let mut base = 1.0;
            for part in digits.rsplit(':') {
                value += part.parse::<f64>().ok()? * base;
                base *= 60.0;
            }
            value
        }
        _ => digits.parse().ok()?,
    };
    Some(if negative { -magnitude } else { magnitude })
}

/// The text of a plain scalar as written in `source`, or `None` for a quoted or block scalar.
///
/// The span of a quoted scalar includes its quotes, and that of a block scalar its final line break,
/// so neither matches a bare spelling. The exception is a block scalar that ends the input without
/// a line break, which is why a value directly under a `|` or `>` header is ruled out explicitly.
fn plain_spelling(source: &str, at: Location) -> Option<&str> {
    let span = at.span();
    let start = usize::try_from(span.byte_offset()?).ok()?;
    let end = start + usize::try_from(span.byte_len()?).ok()?;
    let spelling = source.get(start..end)?;

    let before = source[..start].trim_end_matches([' ', '\t']);
    if let Some(previous_lines) = before.strip_suffix('\n') {
        let previous_line = previous_lines.trim_end_matches('\r');
        let previous_line = previous_line.rsplit('\n').next().unwrap_or(previous_line);
        let header = previous_line
            .split(" #")
            .next()
            .unwrap_or_default()
            .trim_end();
        let indicator = header.rsplit([' ', '\t']).next().unwrap_or(header);
        if let Some(modifiers) = indicator.strip_prefix(['|', '>'])
            && modifiers
                .chars()
                .all(|c| matches!(c, '1'..='9' | '+' | '-'))
        {
            return None;
        }
    }

    Some(spelling)
}

/// Writes `value` as YAML for Ansible to read.
///
/// A long single-line string stays on one line instead of being folded at 80 characters: folding
/// does not change its value, but these files are what someone reads when a run misbehaves, and an
/// SSH argument list wrapped mid-way is easy to misread and impossible to grep for.
pub fn to_string<T: Serialize>(value: &T) -> Result<String, serde_saphyr::SerializeError> {
    let mut options = serde_saphyr::SerializerOptions::default();
    options.folded_wrap_chars = usize::MAX;
    serde_saphyr::to_string_with_options(value, options)
}

/// One node of a YAML document, with its tag, where it was written and, for a mapping, its key order.
#[derive(Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct YamlNode(Tagged<Spanned<Content>>);

impl YamlNode {
    pub fn is_sequence(&self) -> bool {
        matches!(self.0.0.value, Content::Sequence(_))
    }

    /// Gives every untagged plain scalar the type and value PyYAML gives its spelling.
    ///
    /// `defined` rather than `referenced`, so an alias reads the spelling of its anchor, not `*name`.
    fn resolve_plain_scalars(&mut self, source: &str) {
        let Tagged(node, tag) = &mut self.0;
        let defined = node.defined;
        match &mut node.value {
            Content::Sequence(items) => {
                for item in items {
                    item.resolve_plain_scalars(source);
                }
            }
            Content::Mapping(entries) => {
                for (key, value) in entries {
                    key.resolve_plain_scalars(source);
                    value.resolve_plain_scalars(source);
                }
            }
            scalar if tag.is_none() => {
                let Some(spelling) = plain_spelling(source, defined) else {
                    return;
                };
                match resolve_plain(spelling) {
                    Resolved::Value(value) => *scalar = value,
                    Resolved::Tagged(resolved_tag) => {
                        *tag = Some(resolved_tag.to_owned());
                        *scalar = Content::String(spelling.to_owned());
                    }
                    // A plain scalar over several lines is folded into one, so only a single-line
                    // one is its own spelling.
                    Resolved::String
                        if !matches!(scalar, Content::String(_)) && !spelling.contains('\n') =>
                    {
                        *scalar = Content::String(spelling.to_owned());
                    }
                    Resolved::String => {}
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
enum Content {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    String(String),
    Sequence(Vec<YamlNode>),
    Mapping(Vec<(YamlNode, YamlNode)>),
}

// Hand-written rather than an untagged enum: serde buffers an untagged enum's input before matching
// a variant, and the tags of every nested node would be lost in that buffer.
impl<'de> Deserialize<'de> for Content {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ContentVisitor;

        impl<'de> Visitor<'de> for ContentVisitor {
            type Value = Content;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("any YAML node")
            }

            fn visit_unit<E>(self) -> Result<Content, E> {
                Ok(Content::Null)
            }

            fn visit_none<E>(self) -> Result<Content, E> {
                Ok(Content::Null)
            }

            fn visit_bool<E>(self, value: bool) -> Result<Content, E> {
                Ok(Content::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Content, E> {
                Ok(Content::Int(value))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Content, E> {
                Ok(Content::UInt(value))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Content, E> {
                Ok(Content::Float(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Content, E> {
                Ok(Content::String(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Content, E> {
                Ok(Content::String(value))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Content, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Content::Sequence(items))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Content, A::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    entries.push(entry);
                }
                Ok(Content::Mapping(entries))
            }
        }

        deserializer.deserialize_any(ContentVisitor)
    }
}

impl Serialize for Content {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Content::Null => serializer.serialize_unit(),
            Content::Bool(value) => serializer.serialize_bool(*value),
            Content::Int(value) => serializer.serialize_i64(*value),
            Content::UInt(value) => serializer.serialize_u64(*value),
            Content::Float(value) => serializer.serialize_f64(*value),
            Content::String(value) => serializer.serialize_str(value),
            Content::Sequence(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Content::Mapping(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(yaml: &str) -> String {
        to_string(&parse_document(yaml).unwrap()).unwrap()
    }

    #[test]
    fn tags_survive_on_scalars_sequences_and_keys() {
        let rendered = round_trip(
            "secret: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6231346531\n\
             raw: !unsafe '{{ not_a_template }}'\n\
             raw_list: !unsafe ['{{ a }}']\n\
             !custom key: value\n",
        );

        assert!(
            rendered.contains("secret: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6231346531\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("raw: !unsafe \"{{ not_a_template }}\"\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("raw_list: !unsafe\n  - \"{{ a }}\"\n"),
            "{rendered}"
        );
        assert!(rendered.contains("? !custom key\n: value\n"), "{rendered}");
    }

    #[test]
    fn long_strings_stay_on_one_line_and_multi_line_ones_stay_literal() {
        let long = "x ".repeat(60);
        let rendered = to_string(&serde_json::json!({ "long": long, "multi": "a\nb\n" })).unwrap();

        assert_eq!(
            rendered,
            format!("long: \"{long}\"\nmulti: |\n  a\n  b\n"),
            "{rendered}"
        );
    }

    /// Each pair is what Ansible reads from the left-hand text and the spelling that keeps that
    /// meaning once rendered.
    #[test]
    fn values_keep_the_meaning_yaml_1_1_gives_them() {
        let rendered = round_trip(
            "quoted_yes: \"yes\"\n\
             quoted_off: 'off'\n\
             plain_yes: yes\n\
             plain_off: Off\n\
             octal: 0644\n\
             quoted_octal: \"0644\"\n\
             infinite: .inf\n",
        );

        for expected in [
            "quoted_yes: \"yes\"\n",
            "quoted_off: \"off\"\n",
            "plain_yes: true\n",
            "plain_off: false\n",
            "octal: 420\n",
            "quoted_octal: \"0644\"\n",
            "infinite: .inf\n",
        ] {
            assert!(rendered.contains(expected), "{expected:?} in {rendered}");
        }
    }

    /// Each plain spelling and how it is rendered so that PyYAML reads it as it reads the original.
    /// Several are where serde-saphyr's own reading differs from PyYAML's: it takes `09` for 9.0,
    /// `1:30` and dates for strings, `1_000.5` for a string, `1e3` and `0o17` for numbers, and
    /// `nUlL` for null.
    #[test]
    fn plain_scalars_resolve_as_pyyaml_resolves_them() {
        for (spelling, rendered) in [
            (
                "2024-01-15",
                "!<tag:yaml.org,2002:timestamp> \"2024-01-15\"",
            ),
            (
                "2024-01-15 10:30:00",
                "!<tag:yaml.org,2002:timestamp> \"2024-01-15 10:30:00\"",
            ),
            ("1:30", "90"),
            ("-1:30", "-90"),
            ("1:30.5", "90.5"),
            ("09", "\"09\""),
            ("0644", "420"),
            ("0b101", "5"),
            ("0x1F", "31"),
            ("1_000", "1000"),
            ("1_000.5", "1000.5"),
            ("1e3", "\"1e3\""),
            ("1.0e3", "\"1.0e3\""),
            ("1.5e+3", "1500.0"),
            ("0o17", "\"0o17\""),
            ("-.Inf", "-.inf"),
            ("nUlL", "\"nUlL\""),
            ("Null", "null"),
            ("", "null"),
            (
                "18446744073709551616",
                "!<tag:yaml.org,2002:int> \"18446744073709551616\"",
            ),
        ] {
            assert_eq!(
                round_trip(&format!("v: {spelling}\n")),
                format!("v: {rendered}\n"),
                "{spelling:?}"
            );
        }
    }

    /// PyYAML takes 18 spellings as booleans, not every one the YAML 1.1 spec lists: `y`, `n` and
    /// odd letter cases are strings to Ansible and have to stay strings.
    #[test]
    fn only_the_booleans_pyyaml_knows_become_booleans() {
        let rendered = round_trip(
            "a: y\nb: n\nc: Y\nd: yEs\ne: tRuE\nf: YES\ng: On\nh: off\ni: True\nj: 'yes'\nk: !!str yes\n",
        );

        for expected in [
            "a: \"y\"\n",
            "b: \"n\"\n",
            "c: \"Y\"\n",
            "d: \"yEs\"\n",
            "e: \"tRuE\"\n",
            "f: true\n",
            "g: true\n",
            "h: false\n",
            "i: true\n",
            "j: \"yes\"\n",
        ] {
            assert!(rendered.contains(expected), "{expected:?} in {rendered}");
        }
        assert!(!rendered.contains("k: true"), "{rendered}");
    }

    #[test]
    fn keys_aliases_and_flow_items_are_read_like_any_other_scalar() {
        let rendered = round_trip("on: &answer yes\nalias: *answer\nflow: [y, no]\n");

        assert_eq!(
            rendered,
            "true: true\nalias: true\nflow:\n- \"y\"\n- false\n"
        );
    }

    /// A block scalar is never a boolean, even when it ends the input without a line break, which
    /// leaves its source text indistinguishable from a bare `yes`.
    #[test]
    fn a_block_scalar_stays_a_string() {
        for yaml in [
            "a: |-\n  yes",
            "a: >-\n  yes",
            "a: |- # note\n  yes",
            "a: |2-\n  yes",
        ] {
            assert_eq!(round_trip(yaml), "a: \"yes\"\n", "{yaml:?}");
        }
        assert_eq!(round_trip("a:\n  yes"), "a: true\n");
    }

    #[test]
    fn mapping_keys_keep_the_authors_order() {
        let rendered = round_trip("zebra: 1\napple: 2\nmango: 3\n");

        assert_eq!(rendered, "zebra: 1\napple: 2\nmango: 3\n");
    }

    #[test]
    fn only_a_sequence_is_a_sequence() {
        assert!(parse_document("- a\n").unwrap().is_sequence());
        assert!(!parse_document("a: 1\n").unwrap().is_sequence());
        assert!(!parse_document("a\n").unwrap().is_sequence());
    }
}
