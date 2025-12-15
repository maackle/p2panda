use std::fmt::Debug;

use named_id::*;
use serde::{Deserialize, Serialize};

use crate::SpacesArgs;

#[derive(Debug, Serialize, Deserialize, RenameAll)]
pub enum Action<ID, C> {
    Space(SpacesArgs<ID, C>),
}

#[macro_export]
macro_rules! emit_event {
    ($author:expr, $action:expr) => {{
        use ::named_id::Rename;
        let author = $author.renamed();
        let action = $action.renamed();
        tracing::info!(?author, ?action, module = "p2panda-spaces", "EVENT");
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
