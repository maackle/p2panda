// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::Infallible;
use std::hash::Hash as StdHash;
use std::marker::PhantomData;

use p2panda_auth::Access;
use p2panda_auth::group::GroupMember;
use p2panda_auth::traits::Conditions;
use p2panda_core::{Hash, PrivateKey, PublicKey};
use p2panda_encryption::Rng;
use p2panda_encryption::crypto::x25519::SecretKey;
use p2panda_encryption::data_scheme::DirectMessage;
use p2panda_encryption::key_bundle::Lifetime;
use p2panda_encryption::key_manager::KeyManager;

use p2panda_spaces::auth::orderer::AuthOrderer;
use p2panda_spaces::event::Event;
use p2panda_spaces::forge::Forge;
use p2panda_spaces::manager::Manager;
use p2panda_spaces::message::{AuthoredMessage, SpacesArgs, SpacesMessage};
use p2panda_spaces::space::SpaceError;
use p2panda_spaces::store::{AuthStore, SpaceStore};
use p2panda_spaces::test_utils::MemoryStore;
use p2panda_spaces::traits::SpaceId;
use p2panda_spaces::types::{
    ActorId, AuthControlMessage, AuthGroupAction, AuthGroupState, OperationId, StrongRemoveResolver,
};
use serde::{Deserialize, Serialize};

type SeqNum = u64;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Copy, derive_more::From)]
pub struct Id(pub i32);

// Implement SpaceId for i32 which is what we use space identifiers in the tests.
impl SpaceId for Id {}

#[derive(Clone, Debug)]
pub struct TestMessage<ID> {
    seq_num: SeqNum,
    public_key: PublicKey,
    spaces_args: SpacesArgs<ID, TestConditions>,
}

impl<ID> AuthoredMessage for TestMessage<ID>
where
    ID: SpaceId,
{
    fn id(&self) -> OperationId {
        let mut buffer: Vec<u8> = self.public_key.as_bytes().to_vec();
        buffer.extend_from_slice(&self.seq_num.to_be_bytes());
        Hash::new(buffer).into()
    }

    fn author(&self) -> ActorId {
        self.public_key.into()
    }
}

impl<ID> SpacesMessage<ID, TestConditions> for TestMessage<ID> {
    fn args(&self) -> &SpacesArgs<ID, TestConditions> {
        &self.spaces_args
    }
}

#[derive(Debug)]
pub struct TestForge<ID> {
    next_seq_num: SeqNum,
    private_key: PrivateKey,
    _phantom: PhantomData<ID>,
}

impl<ID> TestForge<ID> {
    pub fn new(private_key: PrivateKey) -> Self {
        Self {
            next_seq_num: 0,
            private_key,
            _phantom: PhantomData,
        }
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct TestConditions {}

impl Conditions for TestConditions {}

impl<ID> Forge<ID, TestMessage<ID>, TestConditions> for TestForge<ID>
where
    ID: SpaceId,
{
    type Error = Infallible;

    fn public_key(&self) -> PublicKey {
        self.private_key.public_key()
    }

    async fn forge(
        &mut self,
        args: SpacesArgs<ID, TestConditions>,
    ) -> Result<TestMessage<ID>, Self::Error> {
        let seq_num = self.next_seq_num;
        self.next_seq_num += 1;
        Ok(TestMessage {
            seq_num,
            public_key: self.public_key(),
            spaces_args: args,
        })
    }

    async fn forge_ephemeral(
        &mut self,
        private_key: PrivateKey,
        args: SpacesArgs<ID, TestConditions>,
    ) -> Result<TestMessage<ID>, Self::Error> {
        Ok(TestMessage {
            // Will always be first entry in the "log" as we're dropping the private key.
            seq_num: 0,
            public_key: private_key.public_key(),
            spaces_args: args,
        })
    }
}

type TestStore<ID> = MemoryStore<ID, TestMessage<ID>, TestConditions>;

type TestManager<ID> = Manager<
    ID,
    TestStore<ID>,
    TestForge<ID>,
    TestMessage<ID>,
    TestConditions,
    StrongRemoveResolver<TestConditions>,
>;

type TestSpaceError<ID> = SpaceError<
    ID,
    TestStore<ID>,
    TestForge<ID>,
    TestMessage<ID>,
    TestConditions,
    StrongRemoveResolver<TestConditions>,
>;

pub struct TestPeer<ID = Id> {
    id: u8,
    pub manager: TestManager<ID>,
}

impl<ID> TestPeer<ID>
where
    ID: SpaceId + StdHash,
{
    pub fn new(peer_id: u8) -> Self {
        let rng = Rng::from_seed([peer_id; 32]);

        let private_key = PrivateKey::from_bytes(&rng.random_array().unwrap());
        let my_id: ActorId = private_key.public_key().into();

        let key_manager_y = {
            let identity_secret = SecretKey::from_bytes(rng.random_array().unwrap());
            KeyManager::init(&identity_secret, Lifetime::default(), &rng).unwrap()
        };

        let orderer_y = AuthOrderer::init();
        let auth_y = AuthGroupState::new(orderer_y);
        let store = TestStore::new(my_id, key_manager_y, auth_y);
        let forge = TestForge::new(private_key);

        let manager = TestManager::new(store, forge, rng).unwrap();

        Self {
            id: peer_id,
            manager,
        }
    }
}
