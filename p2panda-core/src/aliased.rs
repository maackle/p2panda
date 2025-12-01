use std::borrow::Cow;

use aliased_id::{AliasedId, ShortId};

impl ShortId for crate::Hash {
    const PREFIX: &'static str = "H";

    fn to_short_string(&self) -> String {
        self.to_hex()
    }
}

impl ShortId for crate::PublicKey {
    const PREFIX: &'static str = "PK";

    fn to_short_string(&self) -> String {
        self.to_hex()
    }
}

impl AliasedId for crate::PublicKey {
    const SHOW_SHORT_ID: bool = false;

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl AliasedId for crate::Hash {
    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}
