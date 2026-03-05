// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::{fmt::Debug, ops::Deref};

use named_id::RenameNone;
use p2panda_core::{Hash, PublicKey};
use p2panda_stream::partial::MemoryStore;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    group::GroupCrdtState,
    traits::{Conditions, Operation},
};

/// All state material required for ordering and processing group messages.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthState<M, C = ()>
where
    M: Operation<PublicKey, Hash, C>,
    C: Conditions,
{
    pub crdt: GroupCrdtState<PublicKey, Hash, M, C>,
    pub orderer: MemoryStore<Hash>,
    pub operation_buffer: HashMap<Hash, M>,
}

impl<M, C> Default for AuthState<M, C>
where
    M: Operation<PublicKey, Hash, C>,
    C: Conditions,
{
    fn default() -> Self {
        Self {
            crdt: GroupCrdtState::default(),
            orderer: MemoryStore::default(),
            operation_buffer: HashMap::default(),
        }
    }
}

/// Memory store for retrieving and setting auth state.
///
/// NOTE: this in-memory implementation will be replaced with SQLite stores in the near future.
#[derive(Clone)]
pub struct Store<M, C = ()>
where
    M: Operation<PublicKey, Hash, C>,
    C: Conditions,
{
    state: Arc<Mutex<Option<AuthState<M, C>>>>,
}

impl<M, C> Default for Store<M, C>
where
    M: Operation<PublicKey, Hash, C>,
    C: Conditions,
{
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(Some(AuthState::default()))),
        }
    }
}

impl<M, C> Store<M, C>
where
    M: Operation<PublicKey, Hash, C> + Clone + Debug,
    C: Conditions,
{
    pub async fn get_state(&self) -> Result<AuthState<M, C>, StoreError> {
        match self.state.lock().await.deref() {
            Some(y) => Ok(y.clone()),
            None => Err(StoreError::StateMissing),
        }
    }

    pub async fn set_state(&self, y: AuthState<M, C>) -> Result<(), StoreError> {
        self.state.lock().await.replace(y);
        Ok(())
    }
}

#[derive(Debug, Error, RenameNone)]
pub enum StoreError {
    #[error("auth state missing")]
    StateMissing,
}
