#[derive(thiserror::Error, Debug)]
pub enum RenderError {
    /// Without the source snippet the parser attaches: the message lands in a status condition,
    /// where several lines of the author's own playbook only bury the line and column.
    #[error("{}", .0.without_snippet())]
    ParseError(#[from] serde_saphyr::Error),

    #[error(transparent)]
    SerializationError(#[from] serde_saphyr::SerializeError),
}
