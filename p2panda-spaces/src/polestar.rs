use std::fmt::Debug;

use p2panda_auth::{Access, group::GroupAction};
use serde::{Deserialize, Serialize};

use crate::{ActorId, SpacesArgs};

#[derive(Debug, Serialize, Deserialize)]
pub enum Action<ID, C> {
    Space(SpacesArgs<ID, C>),
}

pub fn emit_event<ID: Debug, C: Debug>(author: ActorId, action: Action<ID, C>) {
    tracing::info!("EMIT: {:?}", (author, action));
}

// pub enum GroupAction

// #[derive(Debug, Serialize, Deserialize)]
// pub enum SpaceAction<ID> {
//     RegisterMember {
//         member: ActorId,
//     },
//     CreateGroup {
//         initial_members: Vec<(ActorId, Access)>,
//     },
//     CreateSpace {
//         space_id: ID,
//         group_id: ActorId,
//         initial_members: Vec<(ActorId, Access)>,
//     },
//     AddMember {
//         member: ActorId,
//         access: Access,
//     },
// }
