use std::fmt::Debug;

use named_id::*;
use serde::{Deserialize, Serialize};

use crate::{ActorId, SpacesArgs};

#[derive(Debug, Serialize, Deserialize, RenameAll)]
pub enum Action<ID, C> {
    Space(SpacesArgs<ID, C>),
}

pub fn emit_event<ID, C>(author: ActorId, action: Action<ID, C>)
where
    ID: Rename,
    C: Rename,
    Action<ID, C>: Rename,
{
    tracing::info!("EMIT: {:?}", (author.renamed(), action.renamed()));
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
