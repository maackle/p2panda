use std::borrow::Cow;

use aliased_id::{AliasedId, ShortId};

impl ShortId for crate::OperationId {
    const PREFIX: &'static str = "OP";

    fn to_short_string(&self) -> String {
        self.to_hex()
    }
}

impl ShortId for crate::ActorId {
    const PREFIX: &'static str = "A";

    fn to_short_string(&self) -> String {
        self.to_hex()
    }
}

impl AliasedId for crate::ActorId {
    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl AliasedId for crate::OperationId {
    const SHOW_SHORT_ID: bool = true;

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}
