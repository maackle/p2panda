use std::fmt::Debug;

use crate::group::GroupAction;
use named_id::RenameAll;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, RenameAll)]
pub struct AuthEvent<ID, G, C> {
    // author: Option<ID>,
    action: Action<ID, G, C>,
}

impl<ID, G, C> AuthEvent<ID, G, C> {
    pub fn new(action: Action<ID, G, C>) -> Self {
        Self {
            // author: None,
            action,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, RenameAll)]
pub enum Action<ID, G, C> {
    // Space(SpaceAction<ID>),
    Group {
        group_id: G,
        author: ID,
        action: GroupAction<ID, C>,
    },
}

#[macro_export]
macro_rules! emit_event {
    ($event:expr) => {{
        use ::named_id::Rename;
        let event: AuthEvent<_, _, _> = $event;
        let event = event.renamed();
        // println!("EVENT: {event:?}");
        tracing::info!(?event, module = "p2panda-auth", "EVENT");
        // println!("BACKTRACE: {}", std::backtrace::Backtrace::capture());
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
