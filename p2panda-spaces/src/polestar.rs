use std::fmt::Debug;

use named_id::*;
use serde::{Deserialize, Serialize};

use crate::SpacesArgs;

#[derive(Debug, Serialize, Deserialize, RenameAll)]
pub struct SpacesEvent<ID, S, C> {
    actor: ID,
    action: Action<S, C>,
}

impl<ID, S, C> SpacesEvent<ID, S, C> {
    pub fn new(actor: ID, action: Action<S, C>) -> Self {
        Self { actor, action }
    }
}

#[derive(Debug, Serialize, Deserialize, RenameAll)]
pub enum Action<S, C> {
    Space(SpacesArgs<S, C>),
}

#[macro_export]
macro_rules! emit_event {
    ($event:expr) => {{
        use ::named_id::Rename;
        let event: SpacesEvent<_, _, _> = $event;
        let event = event.renamed();
        println!("EVENT: {event:?}");
        // tracing::info!(?event, module = "p2panda-spaces", "EVENT");
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
