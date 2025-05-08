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

#![feature(try_trait_v2)]

use amaru_kernel::Point;
use tracing::Span;

pub type RawBlock = Vec<u8>;

#[derive(Debug, Clone)]
pub enum ValidateBlockEvent {
    Validated {
        point: Point,
        block: RawBlock,
        span: Span,
    },
    Rollback {
        rollback_point: Point,
        span: Span,
    },
}

#[derive(Debug, Clone)]
pub enum BlockValidationResult {
    BlockValidated { point: Point, span: Span },
    BlockValidationFailed { point: Point, span: Span },
    RolledBackTo { rollback_point: Point, span: Span },
}

pub mod context;
pub mod rules;
pub mod state;
pub mod store;
pub mod summary;

#[cfg(test)]
pub(crate) mod tests {
    use amaru_kernel::{
        Bytes, Hash, KeepRaw, PostAlonzoTransactionOutput, TransactionInput, TransactionOutput,
        Value,
    };

    pub(crate) fn fake_input(transaction_id: &str, index: u64) -> TransactionInput {
        TransactionInput {
            transaction_id: Hash::from(hex::decode(transaction_id).unwrap().as_slice()),
            index,
        }
    }

    pub(crate) fn fake_output(address: &str) -> TransactionOutput<'_> {
        amaru_kernel::GenTransactionOutput::PostAlonzo(KeepRaw::from(PostAlonzoTransactionOutput {
            address: Bytes::from(hex::decode(address).expect("Invalid hex address")),
            value: Value::Coin(0),
            datum_option: None,
            script_ref: None,
        }))
    }
}
