//! Verify the decoder used by the Hub rejects forged evaluator output proofs.
use mpz_garble_core::{
    Delta,
    store::{EvaluatorFlush, EvaluatorStore, GarblerStore},
};
use mpz_memory_core::{MemoryExt, ViewExt, binary::U8};
use mpz_ot_core::ideal::cot::IdealCOT;

#[test]
fn forged_provider_output_mac_is_rejected() {
    let delta = Delta::random(&mut rand::rng());
    let cot = IdealCOT::new(delta.into_inner());
    let mut hub = GarblerStore::new([0; 16], delta, cot.clone());
    let mut provider = EvaluatorStore::new(cot);
    let a = hub.alloc::<U8>().unwrap();
    let b = provider.alloc::<U8>().unwrap();
    hub.mark_blind(a).unwrap();
    provider.mark_private(b).unwrap();
    provider.assign(b, 42).unwrap();
    hub.commit(a).unwrap();
    provider.commit(b).unwrap();
    let h = hub.send_flush().unwrap();
    let p = provider.send_flush().unwrap();
    hub.acquire_cot().flush().unwrap();
    hub.receive_flush(p).unwrap();
    provider.receive_flush(h).unwrap();
    let mut output = hub.decode(a).unwrap();
    drop(provider.decode(b).unwrap());
    let _ = hub.send_flush().unwrap();
    let proof = provider.send_flush().unwrap();
    let mut json = serde_json::to_value(proof).unwrap();
    let bytes = json["mac_proof"]["proof"]
        .as_array_mut()
        .expect("MAC proof is a byte array");
    let byte = bytes[0].as_u64().unwrap() ^ 1;
    bytes[0] = serde_json::json!(byte);
    let forged: EvaluatorFlush = serde_json::from_value(json).unwrap();
    assert!(hub.receive_flush(forged).is_err());
    assert!(output.try_recv().unwrap().is_none());
}
