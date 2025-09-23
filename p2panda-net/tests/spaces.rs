mod impls;
use impls::{Id, TestPeer};

#[tokio::test]
async fn test_spaces() {
    let alice = TestPeer::<Id>::new(0);
    let bob = TestPeer::<Id>::new(1);

    let space_id = Id(0);

    alice.manager.create_space(space_id, &[]).await.unwrap();

    todo!();
}
