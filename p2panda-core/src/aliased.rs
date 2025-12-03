use named_id::*;

impl Nameable for crate::Hash {
    fn shortener(&self) -> Option<Shortener> {
        Some(Shortener {
            prefix: "H",
            length: 4,
        })
    }
}

impl Nameable for crate::PublicKey {
    fn shortener(&self) -> Option<Shortener> {
        Some(Shortener {
            prefix: "PK",
            length: 4,
        })
    }
}
