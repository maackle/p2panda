use std::fmt::Debug;

use crate::{
    group::GroupAction,
    traits::{Conditions, IdentityHandle},
};
use named_id::{AnyNameable, Nameables, Renamed};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, named_id::derive::Nameables)]
pub enum Action<ID: Nameables, C: Nameables> {
    // Space(SpaceAction<ID>),
    Group(GroupAction<ID, C>),
}

pub(crate) fn emit_event<ID: IdentityHandle, C: Conditions>(author: ID, action: Action<ID, C>)
where
    Action<ID, C>: Nameables,
{
    let ns = &[AnyNameable::new(author.clone())];
    let action: Renamed<Action<ID, C>> = action.renamed();
    tracing::info!("EMIT: {:?}", (named_id::rename(&author, ns, false), action));
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
