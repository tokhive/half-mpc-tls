//! Hub garbles; Provider evaluates. All decoded outputs are authenticated.
//! Hub-only outputs are XOR-masked by fresh Hub-private randomness in-circuit.
//! Provider learns only masked outputs; no DEAP finalization is necessary.
use crate::{Result, schedule::Secret};
use crate::{fail, schedule};
use key_exchange::{KeyExchange, MpcKeyExchange};
use mpz_common::Context;
use mpz_core::{Block, bitvec::BitVec};
use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
use mpz_garble_core::Delta;
use mpz_memory_core::{DecodeFutureTyped, binary::Binary};
use mpz_memory_core::{Vector, binary::U8};
use mpz_ole::{Receiver as OleReceiver, Sender as OleSender};
use mpz_ot::{
    chou_orlandi as co,
    cot::{DerandCOTReceiver, DerandCOTSender},
    kos,
    rcot::shared::{SharedRCOTReceiver, SharedRCOTSender},
    rot::{
        any::{AnyReceiver, AnySender},
        randomize::{RandomizeRCOTReceiver, RandomizeRCOTSender},
    },
};
use mpz_share_conversion::{ShareConversionReceiver, ShareConversionSender};
use mpz_vm_core::{Vm, prelude::*};
use rand::Rng;
use serio::{SinkExt, stream::IoStreamExt};
use zeroize::Zeroizing;

type Sender = SharedRCOTSender<kos::Sender<co::Receiver>, Block>;
type Receiver = SharedRCOTReceiver<kos::Receiver<co::Sender>, bool, Block>;
type ProviderVm = Evaluator<DerandCOTReceiver<Receiver>>;
type HubVm = Garbler<DerandCOTSender<Sender>>;

pub struct HubOutput {
    future: DecodeFutureTyped<BitVec, Vec<u8>>,
    mask: Option<Zeroizing<Vec<u8>>>,
}
impl HubOutput {
    pub async fn receive(self) -> Result<Option<Vec<u8>>> {
        let mut value = Zeroizing::new(self.future.await?);
        match self.mask {
            Some(mask) => {
                if value.len() != mask.len() {
                    return Err(fail("masked output length"));
                }
                for (a, b) in value.iter_mut().zip(mask.iter()) {
                    *a ^= b;
                }
                Ok(Some(value.to_vec()))
            }
            None => Ok(None),
        }
    }
}
pub enum EngineVm {
    Provider(ProviderVm),
    Hub(HubVm),
}
impl EngineVm {
    pub fn vm(&mut self) -> &mut (dyn Vm<Binary> + Send) {
        match self {
            Self::Provider(vm) => vm,
            Self::Hub(vm) => vm,
        }
    }
    pub fn private_output(&mut self, value: impl Into<Vector<U8>>) -> Result<HubOutput> {
        let value = value.into();
        let is_hub = matches!(self, Self::Hub(_));
        let vm = self.vm();
        let mask_ref = vm.alloc_vec::<U8>(value.len())?;
        let mask = if is_hub {
            let mut bytes = Zeroizing::new(vec![0; value.len()]);
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
            vm.mark_private(mask_ref)?;
            vm.assign(mask_ref, bytes.to_vec())?;
            Some(bytes)
        } else {
            vm.mark_blind(mask_ref)?;
            None
        };
        vm.commit(mask_ref)?;
        let masked = schedule::xor_bytes(vm, value, mask_ref)?;
        Ok(HubOutput {
            future: vm.decode(masked)?,
            mask,
        })
    }
}

pub struct Party {
    pub vm: EngineVm,
    pub ctx: Context,
    ke: Box<dyn KeyExchange + Send + Sync>,
    pub pms: Secret,
    pub provider: bool,
    pub prefix_inputs: (Vector<U8>, Vector<U8>),
}
impl Party {
    pub async fn new(provider: bool, ctx: Context) -> Result<Self> {
        let _phase = crate::diagnostics::Phase::new(provider, "tls13_key_exchange_setup");
        let mut party = Self::build(provider, ctx)?;
        party.ke.setup(&mut party.ctx).await?;
        _phase.finish();
        Ok(party)
    }
    fn build(provider: bool, ctx: Context) -> Result<Self> {
        let mut rng = rand::rng();
        let delta = Delta::random(&mut rng);
        let send = kos::Sender::new(
            kos::SenderConfig::default(),
            delta.into_inner(),
            co::Receiver::default(),
        );
        let recv = kos::Receiver::new(kos::ReceiverConfig::default(), co::Sender::default());
        // Key exchange has its own OT pool: online VM inputs must not wait on
        // an inactive key-exchange participant at SharedRCOT's flush barrier.
        let ke_send = kos::Sender::new(
            kos::SenderConfig::default(),
            Block::random(&mut rng),
            co::Receiver::default(),
        );
        let ke_recv = kos::Receiver::new(kos::ReceiverConfig::default(), co::Sender::default());
        let mut vm = if provider {
            EngineVm::Provider(Evaluator::new(DerandCOTReceiver::new(
                SharedRCOTReceiver::new(recv),
            )))
        } else {
            EngineVm::Hub(Garbler::new(
                DerandCOTSender::new(SharedRCOTSender::new(send)),
                rng.random(),
                delta,
            ))
        };
        let mut ke: Box<dyn KeyExchange + Send + Sync> = if provider {
            Box::new(MpcKeyExchange::new(
                key_exchange::Role::Leader,
                ShareConversionSender::new(OleSender::new(
                    Block::random(&mut rng),
                    AnySender::new(RandomizeRCOTSender::new(ke_send)),
                )),
                ShareConversionReceiver::new(OleReceiver::new(AnyReceiver::new(
                    RandomizeRCOTReceiver::new(ke_recv),
                ))),
            ))
        } else {
            Box::new(MpcKeyExchange::new(
                key_exchange::Role::Follower,
                ShareConversionReceiver::new(OleReceiver::new(AnyReceiver::new(
                    RandomizeRCOTReceiver::new(ke_recv),
                ))),
                ShareConversionSender::new(OleSender::new(
                    Block::random(&mut rng),
                    AnySender::new(RandomizeRCOTSender::new(ke_send)),
                )),
            ))
        };
        let pms = ke.alloc(vm.vm())?;
        let a = vm.vm().alloc_vec::<U8>(crate::record::PREFIX_CAPACITY)?;
        let b = vm.vm().alloc_vec::<U8>(crate::record::PREFIX_CAPACITY)?;
        if provider {
            vm.vm().mark_blind(a)?;
            vm.vm().mark_private(b)?;
        } else {
            vm.vm().mark_private(a)?;
            vm.vm().mark_blind(b)?;
        }
        Ok(Self {
            vm,
            ctx,
            ke,
            pms,
            provider,
            prefix_inputs: (a, b),
        })
    }
    pub async fn public_key(&mut self) -> Result<Vec<u8>> {
        if self.provider {
            let key = p256::EncodedPoint::from(self.ke.client_key()?)
                .to_bytes()
                .to_vec();
            self.ctx.io_mut().send(key.clone()).await?;
            Ok(key)
        } else {
            Ok(self.ctx.io_mut().expect_next::<Vec<u8>>().await?)
        }
    }
    pub async fn exchange(&mut self, server: &[u8]) -> Result<()> {
        let phase = crate::diagnostics::Phase::new(self.provider, "tls13_ecdhe_shares");
        self.ke
            .set_server_key(p256::PublicKey::from_sec1_bytes(server)?)?;
        self.ke.compute_shares(&mut self.ctx).await?;
        self.ke.assign(self.vm.vm())?;
        phase.finish();
        self.execute().await?;
        self.ke.finalize().await?;
        Ok(())
    }
    pub async fn execute(&mut self) -> Result<()> {
        let _phase = crate::diagnostics::Phase::new(self.provider, "tls13_vm_execute");
        self.vm.vm().execute_all(&mut self.ctx).await?;
        _phase.finish();
        Ok(())
    }
    pub async fn reveal(&mut self, value: Secret) -> Result<Option<[u8; 32]>> {
        let output = self.vm.private_output(value)?;
        self.execute().await?;
        output
            .receive()
            .await?
            .map(|bytes| bytes.try_into().map_err(|_| fail("secret length")))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_common::context::test_st_context;
    #[tokio::test]
    async fn masked_outputs_are_hub_only_and_fresh_with_real_ot() {
        let delta = Delta::random(&mut rand::rng());
        let send = SharedRCOTSender::new(kos::Sender::new(
            kos::SenderConfig::default(),
            delta.into_inner(),
            co::Receiver::default(),
        ));
        let recv = SharedRCOTReceiver::new(kos::Receiver::new(
            kos::ReceiverConfig::default(),
            co::Sender::default(),
        ));
        let hub = EngineVm::Hub(Garbler::new(
            DerandCOTSender::new(send),
            rand::random(),
            delta,
        ));
        let provider = EngineVm::Provider(Evaluator::new(DerandCOTReceiver::new(recv)));
        let (a, b) = test_st_context(128);
        let run = |mut engine: EngineVm, mut ctx: Context, hub: bool| async move {
            let value = engine.vm().alloc_vec::<U8>(32).unwrap();
            if hub {
                engine.vm().mark_blind(value).unwrap();
            } else {
                engine.vm().mark_private(value).unwrap();
                engine.vm().assign(value, vec![42; 32]).unwrap();
            }
            engine.vm().commit(value).unwrap();
            let mut seen = Vec::new();
            for _ in 0..2 {
                let output = engine.private_output(value).unwrap();
                engine.vm().execute_all(&mut ctx).await.unwrap();
                if hub {
                    assert_eq!(output.receive().await.unwrap().unwrap(), vec![42; 32]);
                } else {
                    assert!(output.mask.is_none());
                    let masked = output.future.await.unwrap();
                    assert_ne!(masked, vec![42; 32]);
                    seen.push(masked);
                }
            }
            if !hub {
                assert_ne!(seen[0], seen[1]);
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            tokio::join!(run(hub, a, true), run(provider, b, false))
        })
        .await
        .unwrap();
    }
}
