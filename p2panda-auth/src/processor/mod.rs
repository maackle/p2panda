// SPDX-License-Identifier: MIT OR Apache-2.0

//! Types and methods for ordering and processing groups control messages.
mod extensions;
mod store;

pub use extensions::AuthExtension;
use named_id::RenameAll;
pub use store::{AuthState, Store, StoreError};

use std::fmt::Debug;

use p2panda_core::{Hash, PublicKey};
use p2panda_stream::partial::{PartialOrder, PartialOrderError};
use thiserror::Error;

use crate::group::{GroupCrdt, GroupCrdtError, GroupCrdtInnerState};
use crate::traits::{Conditions, IdentityHandle, Operation, OperationId, Resolver};

impl IdentityHandle for PublicKey {}
impl OperationId for Hash {}

/// Process a new groups operation.
///
/// Processed operations are first partially ordered, and only processed on the auth groups state
/// if all their dependencies have been met. If other operations become "ready" by this one, then
/// they will be all processed in order.
pub async fn process<M, C, RS>(
    store: &Store<M, C>,
    operation: &M,
) -> Result<(), ProcessorError<M, C, RS>>
where
    M: Operation<PublicKey, Hash, C> + Clone + Debug,
    C: Conditions,
    RS: Resolver<PublicKey, Hash, M, C, State = GroupCrdtInnerState<PublicKey, Hash, M, C>> + Debug,
{
    let mut y = store.get_state().await?;
    y.operation_buffer.insert(operation.id(), operation.clone());

    let mut orderer = PartialOrder::new(y.orderer.clone());
    orderer
        .process(operation.id(), &operation.dependencies())
        .await?;

    while let Some(hash) = orderer.next().await? {
        let operation = match y.operation_buffer.remove(&hash) {
            Some(operation) => operation,
            None => return Err(ProcessorError::MissingOperation(hash)),
        };
        y.crdt = GroupCrdt::<_, _, _, C, RS>::process(y.crdt, &operation)?;
    }

    y.orderer = orderer.store();
    store.set_state(y).await?;

    Ok(())
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Error, RenameAll)]
pub enum ProcessorError<M, C, RS>
where
    M: Operation<PublicKey, Hash, C> + Clone + Debug,
    C: Conditions,
    RS: Resolver<PublicKey, Hash, M, C, State = GroupCrdtInnerState<PublicKey, Hash, M, C>> + Debug,
{
    #[error(transparent)]
    Orderer(#[from] PartialOrderError),

    #[error(transparent)]
    Groups(#[from] GroupCrdtError<PublicKey, Hash, M, C, RS>),

    #[error("missing operation: {0}")]
    MissingOperation(Hash),

    #[error(transparent)]
    Store(#[from] StoreError),
}
