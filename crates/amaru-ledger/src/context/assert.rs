// Copyright 2025 PRAGMA
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

use crate::context::{
    AccountState, AccountsSlice, CCMember, CommitteeSlice, DRepState, DRepsSlice, DelegateError,
    Hash, PoolsSlice, PotsSlice, PreparationContext, PrepareAccountsSlice, PrepareDRepsSlice,
    PreparePoolsSlice, PrepareUtxoSlice, ProposalsSlice, RegisterError, UnregisterError,
    UpdateError, UtxoSlice, ValidationContext, WitnessSlice,
};
use amaru_kernel::{
    stake_credential_hash, stake_credential_type, Anchor, CertificatePointer, DRep, Epoch,
    Lovelace, PoolId, PoolParams, Proposal, ProposalId, ProposalPointer, StakeCredential,
    TransactionInput, TransactionOutput,
};
use core::mem;
use std::collections::{BTreeMap, BTreeSet};
use tracing::{instrument, Level};

// ------------------------------------------------------------------------------------- Preparation

/// A Fake block preparation context that can used for testing. The context is expected to be
/// provided upfront as test data, and all `require` method merely checks that the requested data
/// pre-exists in the context.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct AssertPreparationContext<'b> {
    pub utxo: BTreeMap<TransactionInput, TransactionOutput<'b>>,
}

impl<'b> From<AssertPreparationContext<'b>> for AssertValidationContext<'b> {
    fn from(ctx: AssertPreparationContext<'b>) -> AssertValidationContext<'b> {
        AssertValidationContext {
            utxo: ctx.utxo,
            required_signers: BTreeSet::default(),
            required_bootstrap_signers: BTreeSet::default(),
        }
    }
}

impl<'b> PreparationContext<'_> for AssertPreparationContext<'b> {}

impl<'b> PrepareUtxoSlice<'_> for AssertPreparationContext<'b> {
    #[allow(clippy::panic)]
    fn require_input(&mut self, input: &TransactionInput) {
        if !self.utxo.contains_key(input) {
            panic!("unknown required input: {input:?}");
        }
    }
}

impl<'b> PreparePoolsSlice<'_> for AssertPreparationContext<'b> {
    fn require_pool(&mut self, _pool: &PoolId) {
        unimplemented!();
    }
}

impl<'b> PrepareAccountsSlice<'_> for AssertPreparationContext<'b> {
    fn require_account(&mut self, _credential: &StakeCredential) {
        unimplemented!();
    }
}

impl<'b> PrepareDRepsSlice<'_> for AssertPreparationContext<'b> {
    fn require_drep(&mut self, _drep: &StakeCredential) {
        unimplemented!();
    }
}

// -------------------------------------------------------------------------------------- Validation

#[derive(Debug, serde::Deserialize)]
pub struct AssertValidationContext<'b> {
    utxo: BTreeMap<TransactionInput, TransactionOutput<'b>>,
    required_signers: BTreeSet<Hash<28>>,
    required_bootstrap_signers: BTreeSet<Hash<28>>,
}

impl<'b> ValidationContext<'b> for AssertValidationContext<'b> {
    type FinalState = ();
}

impl From<AssertValidationContext<'_>> for () {
    fn from(_ctx: AssertValidationContext<'_>) {}
}

impl<'b> PotsSlice for AssertValidationContext<'b> {
    #[instrument(
        level = Level::TRACE,
        fields(
            fee = %_fees,
        )
        skip_all,
        name = "add_fees"
    )]
    fn add_fees(&mut self, _fees: Lovelace) {}
}

impl<'b> UtxoSlice<'b> for AssertValidationContext<'b> {
    fn lookup(&self, input: &TransactionInput) -> Option<&TransactionOutput<'b>> {
        self.utxo.get(input)
    }

    fn consume(&mut self, input: TransactionInput) {
        self.utxo.remove(&input);
    }

    fn produce(&mut self, input: TransactionInput, output: TransactionOutput<'b>) {
        self.utxo.insert(input, output);
    }
}

impl<'b> PoolsSlice for AssertValidationContext<'b> {
    fn lookup(&self, _pool: &PoolId) -> Option<&PoolParams> {
        unimplemented!()
    }
    fn register(&mut self, _params: PoolParams) {
        unimplemented!()
    }
    fn retire(&mut self, _pool: PoolId, _epoch: Epoch) {
        unimplemented!()
    }
}

impl<'b> AccountsSlice for AssertValidationContext<'b> {
    fn lookup(&self, _credential: &StakeCredential) -> Option<&AccountState> {
        unimplemented!()
    }

    fn register(
        &mut self,
        _credential: StakeCredential,
        _state: AccountState,
    ) -> Result<(), RegisterError<AccountState, StakeCredential>> {
        unimplemented!()
    }

    fn delegate_pool(
        &mut self,
        _credential: StakeCredential,
        _pool: PoolId,
    ) -> Result<(), DelegateError<StakeCredential, PoolId>> {
        unimplemented!()
    }

    fn delegate_vote(
        &mut self,
        _credential: StakeCredential,
        _drep: DRep,
        _pointer: CertificatePointer,
    ) -> Result<(), DelegateError<StakeCredential, DRep>> {
        unimplemented!()
    }

    fn unregister(&mut self, _credential: StakeCredential) {
        unimplemented!()
    }

    #[instrument(
        level = Level::TRACE,
        fields(
            credential.type = %stake_credential_type(&credential),
            credential.hash = %stake_credential_hash(&credential),
        )
        skip_all,
        name = "withdraw_from"
    )]
    fn withdraw_from(&mut self, credential: StakeCredential) {
        // We don't actually do any VolatileState updates here
    }
}

impl<'b> DRepsSlice for AssertValidationContext<'b> {
    fn lookup(&self, _credential: &StakeCredential) -> Option<&DRepState> {
        unimplemented!()
    }

    fn register(
        &mut self,
        _drep: StakeCredential,
        _state: DRepState,
    ) -> Result<(), RegisterError<DRepState, StakeCredential>> {
        unimplemented!()
    }

    fn update(
        &mut self,
        _drep: StakeCredential,
        _anchor: Option<Anchor>,
    ) -> Result<(), UpdateError<StakeCredential>> {
        unimplemented!()
    }

    fn unregister(
        &mut self,
        _drep: StakeCredential,
        _refund: Lovelace,
        _pointer: CertificatePointer,
    ) {
        unimplemented!()
    }

    #[instrument(
        level = Level::TRACE,
        fields(
            credential.type = %stake_credential_type(&_drep),
            credential.hash = %stake_credential_hash(&_drep),
        )
        skip_all,
        name = "vote"
    )]
    fn vote(&mut self, _drep: StakeCredential) {
        // TODO: IMPLEMENT
    }
}

impl<'b> CommitteeSlice for AssertValidationContext<'b> {
    fn delegate_cold_key(
        &mut self,
        _cc_member: StakeCredential,
        _delegate: StakeCredential,
    ) -> Result<(), DelegateError<StakeCredential, StakeCredential>> {
        unimplemented!()
    }

    fn resign(
        &mut self,
        _cc_member: StakeCredential,
        _anchor: Option<Anchor>,
    ) -> Result<(), UnregisterError<CCMember, StakeCredential>> {
        unimplemented!()
    }
}

impl<'b> ProposalsSlice for AssertValidationContext<'b> {
    fn acknowledge(&mut self, _id: ProposalId, _pointer: ProposalPointer, _proposal: Proposal) {}
}

impl<'b> WitnessSlice for AssertValidationContext<'b> {
    #[instrument(
        level = Level::TRACE,
        fields(
            credential.type = %stake_credential_type(&credential),
            credential.hash = %stake_credential_hash(&credential),
        )
        skip_all,
        name = "require_witness"
    )]
    fn require_witness(&mut self, credential: StakeCredential) {
        match credential {
            StakeCredential::AddrKeyhash(vk_hash) => {
                self.required_signers.insert(vk_hash);
            }
            StakeCredential::ScriptHash(..) => {
                // FIXME: Also account for native scripts. We should pre-fetch necessary scripts
                // before hand, and here, check whether additional signatures are needed.
            }
        }
    }

    #[instrument(
        level = Level::TRACE,
        fields(
            bootstrap_witness.hash = %root,
        )
        skip_all,
        name = "require_bootstrap_witness"
    )]
    fn require_bootstrap_witness(&mut self, root: Hash<28>) {
        self.required_bootstrap_signers.insert(root);
    }

    fn required_signers(&mut self) -> BTreeSet<Hash<28>> {
        mem::take(&mut self.required_signers)
    }

    fn required_bootstrap_signers(&mut self) -> BTreeSet<Hash<28>> {
        mem::take(&mut self.required_bootstrap_signers)
    }
}
