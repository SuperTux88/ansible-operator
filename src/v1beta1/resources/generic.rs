use std::borrow::Cow;
use std::collections::BTreeMap;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

pub type LabelMap = BTreeMap<String, String>;

/// Marker type for `#[schemars(with = "UnsignedInt")]` on `u32` fields. A bare `u32` renders as
/// `format: uint32`, which Kubernetes does not recognise and warns about on every `kubectl apply`
/// of the CRD (it only knows `int32`/`int64`). This emits a plain non-negative integer
/// (`type: integer, minimum: 0`) instead — the same value constraint, without the unrecognised
/// format. Use `Option<UnsignedInt>` for optional `u32` fields.
pub struct UnsignedInt;

/// Marker type for `u32` fields whose zero value is meaningless, emitting the same
/// Kubernetes-compatible integer schema as [`UnsignedInt`] with a minimum of one. Rejecting `0` at
/// admission is what keeps a "how many times" field from being read as "never".
pub struct PositiveInt;

impl JsonSchema for PositiveInt {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("PositiveInt")
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        serde_json::from_value(serde_json::json!({
            "type": "integer",
            "minimum": 1
        }))
        .unwrap()
    }
}

impl JsonSchema for UnsignedInt {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("UnsignedInt")
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        serde_json::from_value(serde_json::json!({
            "type": "integer",
            "minimum": 0
        }))
        .unwrap()
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeSelectorTerm {
    pub match_labels: Option<LabelMap>,
    pub match_expressions: Option<Vec<SelectorExpression>>,
}

/// A `matchLabels` + `matchExpressions` label selector — structurally identical to
/// `NodeSelectorTerm`, aliased for readability where the target is something other than a Node
/// (e.g. a namespace selector). Kubernetes' own `metav1.LabelSelector` has the same two fields.
pub type LabelSelector = NodeSelectorTerm;

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SelectorExpression {
    pub operator: SelectorOperator,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// How a `matchExpressions` term compares a label against the values it lists.
///
/// `In`, `NotIn`, `Exists` and `DoesNotExist` behave exactly as Kubernetes' own label selectors do.
///
/// `Gt`, `Ge`, `Lt` and `Le` order the label value against the term's single value **as a version**,
/// which Kubernetes itself cannot do: its own `Gt`/`Lt` parse both sides as integers, so a dotted
/// version never matches, and plain string ordering would sort 1.10.0 before 1.9.0. An optional
/// leading `v` is accepted, missing components are read as `0` (so `1.4` is `1.4.0` and an integer
/// is a one-component version, comparing exactly as Kubernetes would compare it), a pre-release
/// sorts before its release (`Ge 1.4.0` excludes `1.4.0-rc.1`), and build metadata after `+` or `_`
/// is ignored. A comparison that cannot be answered matches nothing: no such label on the object,
/// anything other than exactly one value listed, or either side not a version.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub enum SelectorOperator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
    Gt,
    Ge,
    Lt,
    Le,
}
