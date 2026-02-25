// SPDX-License-Identifier: MIT OR Apache-2.0

//! Extensions for p2panda operations required when they are the underlying messaging carrier for
//! auth groups messages.
use p2panda_core::{Extension, Extensions, Hash, Operation, PublicKey};
use serde::{Deserialize, Serialize};

use crate::group::GroupAction;
use crate::traits::{Conditions, Operation as AuthOperation};

/// Auth extensions.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthExtension<C = ()> {
    pub group_id: PublicKey,
    pub action: GroupAction<PublicKey, C>,
}

/// Blanket implementation of auth::Operation trait.
impl<E, C> AuthOperation<PublicKey, Hash, C> for Operation<E>
where
    E: Extensions + Extension<AuthExtension<C>>,
    C: Conditions,
{
    fn id(&self) -> Hash {
        self.hash
    }

    fn author(&self) -> PublicKey {
        self.header.public_key
    }

    fn dependencies(&self) -> Vec<Hash> {
        self.header.previous.clone()
    }

    fn group_id(&self) -> PublicKey {
        let extension: AuthExtension<C> =
            self.header.extension().expect("auth extension is present");
        extension.group_id
    }

    fn action(&self) -> GroupAction<PublicKey, C> {
        let extension: AuthExtension<C> =
            self.header.extension().expect("auth extension is present");
        extension.action
    }
}
