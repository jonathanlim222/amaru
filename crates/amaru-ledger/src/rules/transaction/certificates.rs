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
    PoolsSlice, RegisterError, UnregisterError, UpdateError, WitnessSlice,
};
use amaru_kernel::{
    Certificate, CertificatePointer, DRep, Lovelace, NonEmptySet, PoolId, PoolParams,
    StakeCredential, TransactionPointer, STAKE_CREDENTIAL_DEPOSIT,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InvalidCertificates {
    #[error("stake credential already registered: {0}")]
    StakeCredentialAlreadyRegistered(#[from] RegisterError<AccountState, StakeCredential>),

    #[error("invalid stake credential pool delegation: {0}")]
    StakeCredentialInvalidPoolDelegation(#[from] DelegateError<StakeCredential, PoolId>),

    #[error("invalid stake credential vote delegation: {0}")]
    StakeCredentialInvalidVoteDelegation(#[from] DelegateError<StakeCredential, DRep>),

    #[error("drep already registered: {0}")]
    DRepAlreadyRegistered(#[from] RegisterError<DRepState, StakeCredential>),

    #[error("invalid drep attempted update: {0}")]
    DRepInvalidUpdate(#[from] UpdateError<StakeCredential>),

    #[error("unknown cc member: {0}")]
    CCMemberUnknown(#[from] UnregisterError<CCMember, StakeCredential>),

    #[error("invalid cc member hot credential delegation: {0}")]
    CCMemberInvalidDelegation(#[from] DelegateError<StakeCredential, StakeCredential>),
}

pub(crate) fn execute<C>(
    context: &mut C,
    transaction: TransactionPointer,
    certificates: Option<NonEmptySet<Certificate>>,
) -> Result<(), InvalidCertificates>
where
    C: PoolsSlice + AccountsSlice + DRepsSlice + CommitteeSlice + WitnessSlice,
{
    certificates
        .map(|xs| xs.to_vec())
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .try_for_each(|(certificate_index, certificate)| {
            execute_one(
                context,
                CertificatePointer {
                    transaction,
                    certificate_index,
                },
                certificate,
            )
        })
}

// FIXME: Perform all necessary rules validations down here.
fn execute_one<C>(
    context: &mut C,
    pointer: CertificatePointer,
    certificate: Certificate,
) -> Result<(), InvalidCertificates>
where
    C: PoolsSlice + AccountsSlice + DRepsSlice + CommitteeSlice + WitnessSlice,
{
    match certificate {
        Certificate::PoolRegistration {
            operator: id,
            vrf_keyhash: vrf,
            pledge,
            cost,
            margin,
            reward_account,
            pool_owners: owners,
            relays,
            pool_metadata: metadata,
        } => {
            context.require_witness(StakeCredential::AddrKeyhash(id));
            let params = PoolParams {
                id,
                vrf,
                pledge,
                cost,
                margin,
                reward_account,
                owners,
                relays,
                metadata,
            };
            PoolsSlice::register(context, params);
            Ok(())
        }

        Certificate::PoolRetirement(id, epoch) => {
            context.require_witness(StakeCredential::AddrKeyhash(id));
            PoolsSlice::retire(context, id, epoch);
            Ok(())
        }

        Certificate::StakeRegistration(credential) => {
            AccountsSlice::register(
                context,
                credential,
                AccountState {
                    deposit: STAKE_CREDENTIAL_DEPOSIT as Lovelace,
                    pool: None,
                    drep: None,
                },
            )?;
            Ok(())
        }

        Certificate::Reg(credential, deposit) => {
            // The "old behavior of not requiring a witness for staking credential registration" is mantained:
            // - Only during the "transitional period of Conway"
            // - Only for staking credential registration certificates without a deposit
            //
            // See https://github.com/IntersectMBO/cardano-ledger/blob/81637a1c2250225fef47399dd56f80d87384df32/eras/conway/impl/src/Cardano/Ledger/Conway/TxCert.hs#L698
            if deposit > 0 {
                context.require_witness(credential.clone());
            }

            AccountsSlice::register(
                context,
                credential,
                AccountState {
                    deposit,
                    pool: None,
                    drep: None,
                },
            )?;
            Ok(())
        }

        Certificate::StakeDeregistration(credential) | Certificate::UnReg(credential, _) => {
            context.require_witness(credential.clone());
            AccountsSlice::unregister(context, credential);
            Ok(())
        }

        Certificate::StakeDelegation(credential, pool) => {
            context.require_witness(credential.clone());
            context.delegate_pool(credential, pool)?;
            Ok(())
        }

        Certificate::RegDRepCert(drep, deposit, anchor) => {
            context.require_witness(drep.clone());
            DRepsSlice::register(
                context,
                drep,
                DRepState {
                    deposit,
                    registered_at: pointer,
                    anchor,
                },
            )?;
            Ok(())
        }

        Certificate::UnRegDRepCert(drep, refund) => {
            context.require_witness(drep.clone());
            DRepsSlice::unregister(context, drep, refund, pointer);
            Ok(())
        }

        Certificate::UpdateDRepCert(drep, anchor) => {
            context.require_witness(drep.clone());
            DRepsSlice::update(context, drep, anchor)?;
            Ok(())
        }

        Certificate::VoteDeleg(credential, drep) => {
            context.require_witness(credential.clone());
            AccountsSlice::delegate_vote(context, credential, drep, pointer)?;
            Ok(())
        }

        Certificate::AuthCommitteeHot(cold_credential, hot_credential) => {
            context.require_witness(cold_credential.clone());
            CommitteeSlice::delegate_cold_key(context, cold_credential, hot_credential)?;
            Ok(())
        }

        Certificate::ResignCommitteeCold(cold_credential, anchor) => {
            context.require_witness(cold_credential.clone());
            CommitteeSlice::resign(context, cold_credential, anchor)?;
            Ok(())
        }

        Certificate::StakeVoteDeleg(credential, pool, drep) => {
            let drep_deleg = Certificate::VoteDeleg(credential.clone(), drep);
            execute_one(context, pointer, drep_deleg)?;
            let pool_deleg = Certificate::StakeDelegation(credential, pool);
            execute_one(context, pointer, pool_deleg)
        }

        Certificate::StakeRegDeleg(credential, pool, coin) => {
            let reg = Certificate::Reg(credential.clone(), coin);
            execute_one(context, pointer, reg)?;
            let pool_deleg = Certificate::StakeDelegation(credential, pool);
            execute_one(context, pointer, pool_deleg)
        }

        Certificate::StakeVoteRegDeleg(credential, pool, drep, coin) => {
            let reg = Certificate::Reg(credential.clone(), coin);
            execute_one(context, pointer, reg)?;
            let pool_deleg = Certificate::StakeDelegation(credential.clone(), pool);
            execute_one(context, pointer, pool_deleg)?;
            let drep_deleg = Certificate::VoteDeleg(credential, drep);
            execute_one(context, pointer, drep_deleg)
        }

        Certificate::VoteRegDeleg(credential, drep, coin) => {
            let reg = Certificate::Reg(credential.clone(), coin);
            execute_one(context, pointer, reg)?;
            let drep_deleg = Certificate::VoteDeleg(credential, drep);
            execute_one(context, pointer, drep_deleg)
        }
    }
}
