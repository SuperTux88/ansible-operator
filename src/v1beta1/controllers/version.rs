//! Version parsing for the ordered selector operators (`Gt`, `Ge`, `Lt`, `Le`).
//!
//! Both sides of such a comparison — a Node's label value and the single value the selector term
//! lists — go through [`parse`], and only a pair that both parse is compared. Everything else is
//! not a match, which is what makes a dependency selector fail closed: a plan waits rather than
//! running somewhere it should not.
//!
//! The grammar is SemVer 2.0 with the leniency a label value needs, because the values people
//! already put on Nodes are not written for a parser:
//!
//! - an optional leading `v`, as in `v1.4.2`;
//! - one to three numeric components, with the missing ones read as `0`, so `1.4` is `1.4.0` and a
//!   bare `3` is `3.0.0` — which is what makes an integer label compare exactly as Kubernetes'
//!   integer-only `Gt`/`Lt` would compare it;
//! - build metadata after `+` **or** `_`, ignored. A Kubernetes label value cannot contain `+` at
//!   all, so Helm's own `helm.sh/chart` convention of writing it as `_` is the only form a chart
//!   version can take on a Node.
//!
//! Ordering is SemVer's, so `1.10.0` is newer than `1.9.0` and a pre-release sorts *before* its
//! release: `Ge 1.4.0` deliberately excludes `1.4.0-rc.1`.

use semver::Version;

/// Parses a label or selector value as a version, or `None` if it is not one.
pub fn parse(raw: &str) -> Option<Version> {
    let raw = raw.strip_prefix(['v', 'V']).unwrap_or(raw);
    let core_and_pre = raw.split(['+', '_']).next()?;
    let (core, pre) = match core_and_pre.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (core_and_pre, None),
    };

    let mut components = [0u64; 3];
    let mut seen = 0;
    for component in core.split('.') {
        // `u64::from_str` accepts a leading `+`, which is not a version component.
        if seen == components.len() || !component.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        components[seen] = component.parse().ok()?;
        seen += 1;
    }
    if seen == 0 {
        return None;
    }

    let [major, minor, patch] = components;
    let normalised = match pre {
        Some(pre) => format!("{major}.{minor}.{patch}-{pre}"),
        None => format!("{major}.{minor}.{patch}"),
    };

    Version::parse(&normalised).ok()
}

#[cfg(test)]
mod tests {
    use semver::Version;

    use super::parse;

    fn version(raw: &str) -> Version {
        parse(raw).unwrap_or_else(|| panic!("{raw} should parse"))
    }

    #[test]
    fn full_versions_parse() {
        assert_eq!(version("1.4.2"), Version::new(1, 4, 2));
    }

    #[test]
    fn missing_components_are_zero() {
        assert_eq!(version("1.4"), Version::new(1, 4, 0));
        assert_eq!(version("1"), Version::new(1, 0, 0));
        assert_eq!(version("0"), Version::new(0, 0, 0));
    }

    #[test]
    fn leading_v_is_optional() {
        assert_eq!(version("v1.4.2"), Version::new(1, 4, 2));
        assert_eq!(version("V1.4.2"), Version::new(1, 4, 2));
    }

    #[test]
    fn build_metadata_is_ignored() {
        // A label value cannot contain `+`, so a chart version reaches a Node with `_` instead.
        assert_eq!(version("1.4.2_a1b2c3"), Version::new(1, 4, 2));
        assert_eq!(version("1.4.2+a1b2c3"), Version::new(1, 4, 2));
        // Underscores are not valid SemVer build metadata, so the whole remainder is dropped
        // rather than handed to the parser.
        assert_eq!(version("1.4.2_a1_b2"), Version::new(1, 4, 2));
    }

    #[test]
    fn pre_releases_sort_before_their_release() {
        assert!(version("1.4.0-rc.1") < version("1.4.0"));
        assert!(version("1.4.0-rc.1") < version("1.4.0-rc.2"));
        assert!(version("1.4.0-rc.1") > version("1.3.9"));
    }

    #[test]
    fn components_are_ordered_numerically_not_as_strings() {
        // The whole reason Kubernetes' string equality cannot express "at least this version".
        assert!(version("1.10.0") > version("1.9.0"));
        assert!(version("10") > version("9"));
    }

    #[test]
    fn integers_compare_like_kubernetes_gt_and_lt() {
        assert!(version("3") > version("2"));
        assert_eq!(version("3"), version("3.0.0"));
    }

    #[test]
    fn build_metadata_does_not_affect_ordering() {
        assert_eq!(version("1.4.2_a"), version("1.4.2_b"));
    }

    #[test]
    fn unparseable_values_are_rejected() {
        for raw in [
            "",
            "v",
            "latest",
            "1.4.2.1", // four components
            "1..2",    // empty component
            "1.x",     // non-numeric component
            " 1.4.2",  // a label value cannot hold a space, but nothing here may assume it
            "+1.4.2",  // `u64::from_str` would accept the sign
            "-1.4.2",  // parsed as an empty core with a pre-release
            "1.4.2-",  // empty pre-release: not valid SemVer
            "1.4.2-rc 1",
            "99999999999999999999", // overflows u64
        ] {
            assert!(parse(raw).is_none(), "{raw} should not parse");
        }
    }
}
