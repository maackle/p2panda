use named_id::*;

impl Nameable for crate::OperationId {
    fn shortener(&self) -> Option<Shortener> {
        Some(Shortener {
            prefix: "OP",
            length: 4,
        })
    }
}

impl Nameable for crate::ActorId {
    fn shortener(&self) -> Option<Shortener> {
        Some(Shortener {
            prefix: "A",
            length: 4,
        })
    }
}
