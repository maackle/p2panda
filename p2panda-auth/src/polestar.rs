use std::fmt::Debug;

use crate::group::GroupAction;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum Action<ID, C> {
    // Space(SpaceAction<ID>),
    Group(GroupAction<ID, C>),
}

pub(crate) fn emit_event<ID: Debug, C: Debug>(author: ID, action: Action<ID, C>) {
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
