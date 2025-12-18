use std::fmt::Debug;

use crate::group::GroupAction;
use named_id::RenameAll;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, RenameAll)]
pub struct AuthEvent<ID, C> {
    actor: ID,
    action: Action<ID, C>,
}

impl<ID, C> AuthEvent<ID, C> {
    pub fn new(actor: ID, action: Action<ID, C>) -> Self {
        Self { actor, action }
    }
}

#[derive(Debug, Serialize, Deserialize, RenameAll)]
pub enum Action<ID, C> {
    // Space(SpaceAction<ID>),
    Group(GroupAction<ID, C>),
}

#[macro_export]
macro_rules! emit_event {
    ($event:expr) => {{
        use ::named_id::Rename;
        let event: AuthEvent<_, _> = $event;
        let event = event.renamed();
        println!("EVENT: {event:?}");
        // tracing::info!(?event, module = "p2panda-auth", "EVENT");
    }};
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
