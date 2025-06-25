// Copyright 2024 PRAGMA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
    consensus::store::ChainStore, is_header::IsHeader, peer::Peer, ConsensusError,
    ConsensusMetrics, NO_KEY_VALUE,
};
use amaru_kernel::{protocol_parameters::GlobalParameters, to_cbor, Hash, Header, Nonce, Point};
use amaru_ouroboros::{praos, Nonces};
use amaru_ouroboros_traits::{HasStakeDistribution, Praos};
use pallas_math::math::FixedDecimal;
use pure_stage::{Effects, ExternalEffect, ExternalEffectAPI, StageRef, Void};
use std::{fmt, sync::Arc};
use tokio::sync::Mutex;
use tracing::{instrument, Level, Span};

use super::{store::NoncesError, DecodedChainSyncEvent};

#[instrument(
    level = Level::TRACE,
    skip_all,
    fields(
        issuer.key = %header.header_body.issuer_vkey,
    ),
)]
pub fn header_is_valid(
    point: &Point,
    header: &Header,
    raw_header_body: &[u8],
    epoch_nonce: &Nonce,
    ledger: &dyn HasStakeDistribution,
    global_parameters: &GlobalParameters,
) -> Result<(), ConsensusError> {
    let active_slot_coeff: FixedDecimal = FixedDecimal::from(1_u64)
        / FixedDecimal::from(global_parameters.active_slot_coeff_inverse as u64);

    praos::header::assert_all(
        header,
        raw_header_body,
        ledger,
        epoch_nonce,
        &active_slot_coeff,
    )
    .and_then(|assertions| {
        use rayon::prelude::*;
        assertions.into_par_iter().try_for_each(|assert| assert())
    })
    .map_err(|e| ConsensusError::InvalidHeader(point.clone(), e))
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidateHeader {
    #[serde(skip, default = "default_ledger")]
    pub ledger: Arc<dyn HasStakeDistribution>,
    #[serde(skip, default = "default_store")]
    pub store: Arc<Mutex<dyn ChainStore<Header>>>,
    #[serde(skip)]
    pub metrics: Option<ConsensusMetrics>,
}

impl PartialEq for ValidateHeader {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

fn default_ledger() -> Arc<dyn HasStakeDistribution> {
    struct Fake;
    impl HasStakeDistribution for Fake {
        fn get_pool(
            &self,
            _slot: amaru_kernel::Slot,
            _pool: &amaru_kernel::PoolId,
        ) -> Option<amaru_ouroboros::PoolSummary> {
            unimplemented!()
        }

        fn slot_to_kes_period(&self, _slot: amaru_kernel::Slot) -> u64 {
            unimplemented!()
        }

        fn max_kes_evolutions(&self) -> u64 {
            unimplemented!()
        }

        fn latest_opcert_sequence_number(&self, _pool: &amaru_kernel::PoolId) -> Option<u64> {
            unimplemented!()
        }
    }
    Arc::new(Fake)
}

impl fmt::Debug for ValidateHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidateHeader")
            .field("ledger", &"<dyn HasStakeDistribution>")
            .field("store", &"<dyn ChainStore>")
            .finish()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvolveNonceEffect {
    #[serde(skip, default = "default_store")]
    store: Arc<Mutex<dyn ChainStore<Header>>>,
    header: Header,
    global_parameters: GlobalParameters,
}

impl PartialEq for EvolveNonceEffect {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header && self.global_parameters == other.global_parameters
    }
}

fn default_store() -> Arc<Mutex<dyn ChainStore<Header>>> {
    Arc::new(Mutex::new(super::store::FakeStore::default()))
}

impl EvolveNonceEffect {
    fn new(
        store: Arc<Mutex<dyn ChainStore<Header>>>,
        header: Header,
        global_parameters: GlobalParameters,
    ) -> Self {
        Self {
            store,
            header,
            global_parameters,
        }
    }
}

impl fmt::Debug for EvolveNonceEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EvolveNonceEffect")
            .field("header", &self.header.hash().to_string())
            .field("global_parameters", &self.global_parameters)
            .finish()
    }
}

impl ExternalEffect for EvolveNonceEffect {
    fn run(self: Box<Self>) -> pure_stage::BoxFuture<'static, Box<dyn pure_stage::SendData>> {
        Box::pin(async move {
            let result = self
                .store
                .lock()
                .await
                .evolve_nonce(&self.header, &self.global_parameters);
            Box::new(result) as Box<dyn pure_stage::SendData>
        })
    }
}

impl ExternalEffectAPI for EvolveNonceEffect {
    type Response = Result<Nonces, NoncesError>;
}

impl ValidateHeader {
    pub fn new(
        metrics: Option<ConsensusMetrics>,
        ledger: Arc<dyn HasStakeDistribution>,
        store: Arc<Mutex<dyn ChainStore<Header>>>,
    ) -> Self {
        Self {
            ledger,
            store,
            metrics,
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        name = "consensus.roll_forward",
        fields(
            point.slot = %point.slot_or_default(),
            point.hash = %Hash::<32>::from(&point),
        )
    )]
    pub async fn handle_roll_forward(
        &mut self,
        peer: Peer,
        point: Point,
        header: Header,
        global_parameters: &GlobalParameters,
        span: Span,
    ) -> Result<DecodedChainSyncEvent, ConsensusError> {
        let Nonces {
            active: ref epoch_nonce,
            ..
        } = self
            .store
            .lock()
            .await
            .evolve_nonce(&header, global_parameters)?;

        header_is_valid(
            &point,
            &header,
            to_cbor(&header.header_body).as_slice(),
            epoch_nonce,
            self.ledger.as_ref(),
            global_parameters,
        )?;

        self.header_validated();

        Ok(DecodedChainSyncEvent::RollForward {
            peer,
            point,
            header,
            span,
        })
    }

    pub async fn handle_roll_forward_new(
        &mut self,
        eff: &Effects<
            DecodedChainSyncEvent,
            (
                ValidateHeader,
                GlobalParameters,
                StageRef<DecodedChainSyncEvent, Void>,
            ),
        >,
        peer: Peer,
        point: Point,
        header: Header,
        global_parameters: &GlobalParameters,
    ) -> Result<DecodedChainSyncEvent, ConsensusError> {
        let Nonces {
            active: ref epoch_nonce,
            ..
        } = eff
            .external(EvolveNonceEffect::new(
                self.store.clone(),
                header.clone(),
                global_parameters.clone(),
            ))
            .await?;

        header_is_valid(
            &point,
            &header,
            to_cbor(&header.header_body).as_slice(),
            epoch_nonce,
            self.ledger.as_ref(),
            global_parameters,
        )?;

        Ok(DecodedChainSyncEvent::RollForward {
            peer,
            point,
            header,
            span: Span::current(),
        })
    }

    pub async fn handle_chain_sync(
        &mut self,
        chain_sync: DecodedChainSyncEvent,
        global_parameters: &GlobalParameters,
    ) -> Result<DecodedChainSyncEvent, ConsensusError> {
        match chain_sync {
            DecodedChainSyncEvent::RollForward {
                peer,
                point,
                header,
                span,
            } => {
                self.handle_roll_forward(peer, point, header, global_parameters, span)
                    .await
            }
            DecodedChainSyncEvent::Rollback { .. } => Ok(chain_sync),
        }
    }

    pub async fn validate_header(
        &mut self,
        eff: &Effects<
            DecodedChainSyncEvent,
            (
                ValidateHeader,
                GlobalParameters,
                StageRef<DecodedChainSyncEvent, Void>,
            ),
        >,
        chain_sync: DecodedChainSyncEvent,
        global_parameters: &GlobalParameters,
    ) -> Result<DecodedChainSyncEvent, ConsensusError> {
        match chain_sync {
            DecodedChainSyncEvent::RollForward {
                peer,
                point,
                header,
                ..
            } => {
                self.handle_roll_forward_new(eff, peer, point, header, global_parameters)
                    .await
            }
            DecodedChainSyncEvent::Rollback { .. } => Ok(chain_sync),
        }
    }

    fn header_validated(&mut self) {
        if let Some(metrics) = self.metrics.as_mut() {
            metrics.count_validated_headers.add(1, &NO_KEY_VALUE);
        }
    }
}
