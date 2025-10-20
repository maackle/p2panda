// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;

use p2panda_auth::traits::Conditions;
use p2panda_encryption::key_manager::PreKeyBundlesState;
use p2panda_encryption::key_registry::{KeyRegistry, KeyRegistryState};
use tokio::sync::RwLock;

use crate::OperationId;
use crate::auth::orderer::AuthOrderer;
use crate::space::SpaceState;
use crate::test_utils::{TestConditions, TestMessage, TestSpaceId};
use crate::traits::{
    AuthStore, KeyRegistryStore, KeySecretStore, MessageStore, SpaceId, SpaceStore,
};
use crate::types::{ActorId, AuthGroupState};

pub type TestStore = MemoryStore<TestSpaceId, TestMessage, TestConditions>;

#[derive(Debug)]
pub struct MemoryStoreInner<I, M, C>
where
    C: Conditions,
{
    auth: AuthGroupState<C>,
    spaces: HashMap<I, SpaceState<I, M, C>>,
    messages: HashMap<OperationId, M>,
}

#[derive(Debug, Clone)]
pub struct MemoryStore<I, M, C>
where
    C: Conditions,
{
    pub(crate) inner: Arc<RwLock<MemoryStoreInner<I, M, C>>>,
}

impl<I, M, C> MemoryStore<I, M, C>
where
    C: Conditions,
{
    pub fn new() -> Self {
        let orderer_y = AuthOrderer::init();
        let auth_y = AuthGroupState::new(orderer_y);
        let inner = MemoryStoreInner {
            auth: auth_y,
            spaces: HashMap::new(),
            messages: HashMap::new(),
        };
        Self {
            inner: Arc::new(RwLock::new(inner)),
        }
    }
}

impl<I, M, C> SpaceStore<I, M, C> for MemoryStore<I, M, C>
where
    I: SpaceId + std::hash::Hash + Eq,
    M: Clone,
    C: Conditions,
{
    type Error = Infallible;

    async fn space(&self, id: &I) -> Result<Option<SpaceState<I, M, C>>, Self::Error> {
        let inner = self.inner.read().await;
        Ok(inner.spaces.get(id).cloned())
    }

    async fn has_space(&self, id: &I) -> Result<bool, Self::Error> {
        let inner = self.inner.read().await;
        Ok(inner.spaces.contains_key(id))
    }

    async fn spaces_ids(&self) -> Result<Vec<I>, Self::Error> {
        let inner = self.inner.read().await;
        Ok(inner.spaces.keys().cloned().collect())
    }

    async fn set_space(&self, id: &I, y: SpaceState<I, M, C>) -> Result<(), Self::Error> {
        let mut inner = self.inner.write().await;
        inner.spaces.insert(*id, y);
        Ok(())
    }
}

impl<I, M, C> AuthStore<C> for MemoryStore<I, M, C>
where
    I: SpaceId + std::hash::Hash + Eq,
    C: Conditions,
{
    type Error = Infallible;

    async fn auth(&self) -> Result<AuthGroupState<C>, Self::Error> {
        let inner = self.inner.read().await;
        Ok(inner.auth.clone())
    }

    async fn set_auth(&self, y: &AuthGroupState<C>) -> Result<(), Self::Error> {
        let mut inner = self.inner.write().await;
        inner.auth = y.clone();
        Ok(())
    }
}

impl<I, M, C> MessageStore<M> for MemoryStore<I, M, C>
where
    I: SpaceId + std::hash::Hash + Eq,
    M: Clone,
    C: Conditions,
{
    type Error = Infallible;

    async fn message(&self, id: &OperationId) -> Result<Option<M>, Self::Error> {
        let inner = self.inner.read().await;
        Ok(inner.messages.get(id).cloned())
    }

    async fn set_message(&self, id: &OperationId, message: &M) -> Result<(), Self::Error> {
        let mut inner = self.inner.write().await;
        inner.messages.insert(*id, message.clone());
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TestKeyStore {
    pub(crate) inner: Arc<RwLock<TestKeyStoreInner>>,
}

#[derive(Debug)]
pub struct TestKeyStoreInner {
    prekey_secrets: PreKeyBundlesState,
    key_registry: KeyRegistryState<ActorId>,
}

impl TestKeyStore {
    pub fn new() -> Self {
        let inner = TestKeyStoreInner {
            prekey_secrets: PreKeyBundlesState::default(),
            key_registry: KeyRegistry::init(),
        };
        Self {
            inner: Arc::new(RwLock::new(inner)),
        }
    }
}

impl KeyRegistryStore for TestKeyStore {
    type Error = Infallible;

    async fn key_registry(&self) -> Result<KeyRegistryState<ActorId>, Self::Error> {
        let inner = self.inner.read().await;
        Ok(inner.key_registry.clone())
    }

    async fn set_key_registry(&self, y: &KeyRegistryState<ActorId>) -> Result<(), Self::Error> {
        let mut inner = self.inner.write().await;
        inner.key_registry = y.clone();
        Ok(())
    }
}

impl KeySecretStore for TestKeyStore {
    type Error = Infallible;

    async fn prekey_secrets(&self) -> Result<PreKeyBundlesState, Self::Error> {
        let inner = self.inner.read().await;
        Ok(inner.prekey_secrets.clone())
    }

    async fn set_prekey_secrets(&self, y: &PreKeyBundlesState) -> Result<(), Self::Error> {
        let mut inner = self.inner.write().await;
        inner.prekey_secrets = y.clone();
        Ok(())
    }
}
