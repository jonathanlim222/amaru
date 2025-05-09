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

use ::rocksdb::{self, checkpoint, OptimisticTransactionDB, Options, SliceTransform};
use amaru_kernel::{
    CertificatePointer, Epoch, EraHistory, Lovelace, Point, PoolId, StakeCredential,
    TransactionInput,
};
use amaru_ledger::{
    store::{
        columns as scolumns, Columns, EpochTransitionProgress, HistoricalStores, OpenErrorKind,
        ReadOnlyStore, Snapshot, Store, StoreError, TipErrorKind, TransactionalContext,
    },
    summary::Pots,
};
use iter_borrow::{self, borrowable_proxy::BorrowableProxy, IterBorrow};
use pallas_codec::minicbor::{self as cbor};
use rocksdb::Transaction;
use std::{
    collections::BTreeSet,
    fmt, fs,
    path::{Path, PathBuf},
};
use tracing::{info, instrument, trace, warn, Level};

pub mod ledger;
use ledger::columns::*;

pub mod common;
use common::{as_value, PREFIX_LEN};

pub mod consensus;

mod transaction;
use transaction::OngoingTransaction;

const EVENT_TARGET: &str = "amaru::ledger::store";

/// Special key where we store the tip of the database (most recently applied delta)
const KEY_TIP: &str = "tip";

/// Special key where we store the progress of the database
const KEY_PROGRESS: &str = "progress";

/// Name of the directory containing the live ledger stable database.
const DIR_LIVE_DB: &str = "live";

/// An opaque handle for a store implementation of top of RocksDB. The database has the
/// following structure:
///
/// * ========================*=============================================== *
/// * key                     * value                                          *
/// * ========================*=============================================== *
/// * 'tip'                   * Point                                          *
/// * 'progress'              * EpochTransitionProgress                        *
/// * 'pots'                  * (Lovelace, Lovelace, Lovelace)                 *
/// * 'utxo:'TransactionInput * TransactionOutput                              *
/// * 'pool:'PoolId           * (PoolParams, Vec<(Option<PoolParams>, Epoch)>) *
/// * 'acct:'StakeCredential  * (Option<PoolId>, Lovelace, Lovelace)           *
/// * 'slot':slot             * PoolId                                         *
/// * ========================*=============================================== *
///
/// CBOR is used to serialize objects (as keys or values) into their binary equivalent.
pub struct RocksDB {
    /// The working directory where we store the various key/value stores.
    dir: PathBuf,

    /// Whether to allow saving data incrementally (i.e. calling multiple times 'save' with the
    /// same point). This is only sound when importing static data, but not when running live.
    incremental_save: bool,

    /// An instance of RocksDB.
    db: OptimisticTransactionDB,

    /// The `EraHistory` of the network this database is tied to
    era_history: EraHistory,

    ongoing_transaction: OngoingTransaction,
}

impl RocksDB {
    pub fn snapshots(dir: &Path) -> Result<Vec<Epoch>, StoreError> {
        let mut snapshots: Vec<Epoch> = Vec::new();

        for entry in fs::read_dir(dir)
            .map_err(|err| StoreError::Open(OpenErrorKind::IO(err)))?
            .by_ref()
        {
            let entry = entry.map_err(|err| StoreError::Open(OpenErrorKind::IO(err)))?;

            if let Ok(epoch) = entry
                .file_name()
                .to_str()
                .unwrap_or_default()
                .parse::<Epoch>()
            {
                snapshots.push(epoch);
            } else if entry.file_name() != DIR_LIVE_DB {
                warn!(
                    target: EVENT_TARGET,
                    filename = entry.file_name().to_str().unwrap_or_default(),
                    "new.unexpected_file"
                );
            }
        }

        snapshots.sort();

        Ok(snapshots)
    }

    pub fn new(dir: &Path, era_history: &EraHistory) -> Result<RocksDB, StoreError> {
        let snapshots = RocksDB::snapshots(dir)?;

        info!(target: EVENT_TARGET, snapshots = ?snapshots, "new.known_snapshots");

        if snapshots.is_empty() {
            return Err(StoreError::Open(OpenErrorKind::NoStableSnapshot));
        }

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(PREFIX_LEN));

        Ok(RocksDB {
            dir: dir.to_path_buf(),
            incremental_save: false,
            db: OptimisticTransactionDB::open(&opts, dir.join("live"))
                .map_err(|err| StoreError::Internal(err.into()))?,
            era_history: era_history.clone(), // TODO: remove clone?
            ongoing_transaction: OngoingTransaction::new(),
        })
    }

    pub fn empty(dir: &Path, era_history: &EraHistory) -> Result<RocksDB, StoreError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(PREFIX_LEN));
        Ok(RocksDB {
            dir: dir.to_path_buf(),
            incremental_save: true,
            db: OptimisticTransactionDB::open(&opts, dir.join("live"))
                .map_err(|err| StoreError::Internal(err.into()))?,
            era_history: era_history.clone(),
            ongoing_transaction: OngoingTransaction::new(),
        })
    }

    fn transaction_ended(&self) {
        self.ongoing_transaction.set(false);
    }

    fn get<T: for<'d> cbor::decode::Decode<'d, ()>>(
        &self,
        key: &str,
    ) -> Result<Option<T>, StoreError> {
        self.db
            .get(key)
            .map_err(|err| StoreError::Internal(err.into()))?
            .map(|bytes| cbor::decode(&bytes))
            .transpose()
            .map_err(StoreError::Undecodable)
    }
}

#[allow(clippy::panic)]
#[allow(clippy::unwrap_used)]
fn iter<'a, K: Clone + for<'d> cbor::Decode<'d, ()>, V: Clone + for<'d> cbor::Decode<'d, ()>>(
    db: &OptimisticTransactionDB,
    prefix: [u8; PREFIX_LEN],
) -> Result<impl Iterator<Item = (K, V)> + use<'_, K, V>, StoreError> {
    Ok(db.prefix_iterator(prefix).map(|e| {
        let (key, value) = e.unwrap();
        let decoded_key = cbor::decode(&key[PREFIX_LEN..])
            .unwrap_or_else(|e| panic!("unable to decode key ({}): {e:?}", hex::encode(&key)));
        let decoded_value = cbor::decode(&value).unwrap_or_else(|e| {
            panic!(
                "unable to decode value ({}) for key ({}): {e:?}",
                hex::encode(&key),
                hex::encode(&value)
            )
        });
        (decoded_key, decoded_value)
    }))
}

macro_rules! impl_ReadOnlyStore {
    (for $($s:ty),+) => {
        $(impl ReadOnlyStore for $s {
            fn pool(&self, pool: &PoolId) -> Result<Option<scolumns::pools::Row>, StoreError> {
                pools::get(&self.db, pool)
            }

            fn account(
                &self,
                credential: &StakeCredential,
            ) -> Result<Option<scolumns::accounts::Row>, StoreError> {
                accounts::get(&self.db, credential)
            }

            fn utxo(&self, input: &TransactionInput) -> Result<Option<scolumns::utxo::Value>, StoreError> {
                utxo::get(&self.db, input)
            }

            fn pots(&self) -> Result<Pots, StoreError> {
                pots::get(&self.db.transaction()).map(|row| Pots::from(&row))
            }

            fn iter_utxos(
                &self,
            ) -> Result<impl Iterator<Item = (scolumns::utxo::Key, scolumns::utxo::Value)>, StoreError>
            {
                iter::<scolumns::utxo::Key, scolumns::utxo::Value>(&self.db, utxo::PREFIX)
            }

            fn iter_accounts(
                &self,
            ) -> Result<impl Iterator<Item = (scolumns::accounts::Key, scolumns::accounts::Row)>, StoreError>
            {
                iter::<scolumns::accounts::Key, scolumns::accounts::Row>(&self.db, accounts::PREFIX)
            }

            fn iter_block_issuers(
                &self,
            ) -> Result<impl Iterator<Item = (scolumns::slots::Key, scolumns::slots::Value)>, StoreError>
            {
                iter::<scolumns::slots::Key, scolumns::slots::Value>(&self.db, slots::PREFIX)
            }

            fn iter_pools(
                &self,
            ) -> Result<impl Iterator<Item = (scolumns::pools::Key, scolumns::pools::Row)>, StoreError>
            {
                iter::<scolumns::pools::Key, scolumns::pools::Row>(&self.db, pools::PREFIX)
            }

            fn iter_dreps(
                &self,
            ) -> Result<impl Iterator<Item = (scolumns::dreps::Key, scolumns::dreps::Row)>, StoreError>
            {
                iter::<scolumns::dreps::Key, scolumns::dreps::Row>(&self.db, dreps::PREFIX)
            }

            fn iter_proposals(
                &self,
            ) -> Result<
                impl Iterator<Item = (scolumns::proposals::Key, scolumns::proposals::Row)>,
                StoreError,
            > {
                iter::<scolumns::proposals::Key, scolumns::proposals::Row>(&self.db, proposals::PREFIX)
            }
        })*
    }
}

// For now RocksDB and RocksDBSnapshot share their implementation of ReadOnlyStore
impl_ReadOnlyStore!(for RocksDB, RocksDBSnapshot);

/// An generic column iterator, provided that rows from the column are (de)serialisable.
#[allow(clippy::panic)]
fn with_prefix_iterator<
    K: Clone + fmt::Debug + for<'d> cbor::Decode<'d, ()> + cbor::Encode<()>,
    V: Clone + fmt::Debug + for<'d> cbor::Decode<'d, ()> + cbor::Encode<()>,
    DB,
>(
    db: &rocksdb::Transaction<'_, DB>,
    prefix: [u8; PREFIX_LEN],
    mut with: impl FnMut(IterBorrow<'_, '_, K, Option<V>>),
) -> Result<(), StoreError> {
    let mut iterator =
        iter_borrow::new::<PREFIX_LEN, _, _>(db.prefix_iterator(prefix).map(|item| {
            // FIXME: clarify what kind of errors can come from the database at this point.
            // We are merely iterating over a collection.
            item.unwrap_or_else(|e| panic!("unexpected database error: {e:?}"))
        }));

    with(iterator.as_iter_borrow());

    for (k, v) in iterator.into_iter_updates() {
        match v {
            Some(v) => db.put(k, as_value(v)),
            None => db.delete(k),
        }
        .map_err(|err| StoreError::Internal(err.into()))?;
    }
    Ok(())
}

struct RocksDBTransactionalContext<'a> {
    db: &'a RocksDB,
    transaction: Transaction<'a, OptimisticTransactionDB>,
}

impl TransactionalContext<'_> for RocksDBTransactionalContext<'_> {
    fn commit(self) -> Result<(), StoreError> {
        let res = self
            .transaction
            .commit()
            .map_err(|err| StoreError::Internal(err.into()));
        self.db.transaction_ended();
        res
    }

    fn rollback(mut self) -> Result<(), StoreError> {
        let transaction = std::mem::replace(&mut self.transaction, self.db.db.transaction());
        let res = transaction
            .rollback()
            .map_err(|err| StoreError::Internal(err.into()));
        self.db.transaction_ended();
        res
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
    )]
    fn try_epoch_transition(
        &self,
        from: Option<EpochTransitionProgress>,
        to: Option<EpochTransitionProgress>,
    ) -> Result<bool, StoreError> {
        let previous_progress = self
            .transaction
            .get(KEY_PROGRESS)
            .map_err(|err| StoreError::Internal(err.into()))?
            .map(|bytes| cbor::decode(&bytes))
            .transpose()
            .map_err(StoreError::Undecodable)?;

        if previous_progress != from {
            return Ok(false);
        }

        match to {
            None => self.transaction.delete(KEY_PROGRESS),
            Some(to) => self.transaction.put(KEY_PROGRESS, as_value(to)),
        }
        .map_err(|err| StoreError::Internal(err.into()))?;

        Ok(true)
    }

    /// Refund a deposit into an account. If the account no longer exists, returns the unrefunded
    /// deposit.
    fn refund(
        &self,
        credential: &scolumns::accounts::Key,
        deposit: Lovelace,
    ) -> Result<Lovelace, StoreError> {
        accounts::set(&self.transaction, credential, |balance| balance + deposit)
    }

    fn save(
        &self,
        point: &Point,
        issuer: Option<&scolumns::pools::Key>,
        add: Columns<
            impl Iterator<Item = (scolumns::utxo::Key, scolumns::utxo::Value)>,
            impl Iterator<Item = scolumns::pools::Value>,
            impl Iterator<Item = (scolumns::accounts::Key, scolumns::accounts::Value)>,
            impl Iterator<Item = (scolumns::dreps::Key, scolumns::dreps::Value)>,
            impl Iterator<Item = (scolumns::cc_members::Key, scolumns::cc_members::Value)>,
            impl Iterator<Item = (scolumns::proposals::Key, scolumns::proposals::Value)>,
        >,
        remove: Columns<
            impl Iterator<Item = scolumns::utxo::Key>,
            impl Iterator<Item = (scolumns::pools::Key, Epoch)>,
            impl Iterator<Item = scolumns::accounts::Key>,
            impl Iterator<Item = (scolumns::dreps::Key, CertificatePointer)>,
            impl Iterator<Item = scolumns::cc_members::Key>,
            impl Iterator<Item = scolumns::proposals::Key>,
        >,
        withdrawals: impl Iterator<Item = scolumns::accounts::Key>,
        voting_dreps: BTreeSet<StakeCredential>,
    ) -> Result<(), StoreError> {
        match (point, self.db.tip().ok()) {
            (Point::Specific(new, _), Some(Point::Specific(current, _)))
                if *new <= current && !self.db.incremental_save =>
            {
                trace!(target: EVENT_TARGET, ?point, "save.point_already_known");
            }
            _ => {
                self.transaction
                    .put(KEY_TIP, as_value(point))
                    .map_err(|err| StoreError::Internal(err.into()))?;

                if let Some(issuer) = issuer {
                    slots::put(
                        &self.transaction,
                        &point.slot_or_default(),
                        scolumns::slots::Row::new(*issuer),
                    )?;
                }

                utxo::add(&self.transaction, add.utxo)?;
                pools::add(&self.transaction, add.pools)?;
                dreps::add(&self.transaction, add.dreps)?;
                accounts::add(&self.transaction, add.accounts)?;
                cc_members::add(&self.transaction, add.cc_members)?;
                proposals::add(&self.transaction, add.proposals)?;

                accounts::reset_many(&self.transaction, withdrawals)?;
                dreps::tick(&self.transaction, voting_dreps, {
                    let slot = point.slot_or_default();
                    self.db
                        .era_history
                        .slot_to_epoch(slot)
                        .map_err(|err| StoreError::Internal(err.into()))?
                })?;

                utxo::remove(&self.transaction, remove.utxo)?;
                pools::remove(&self.transaction, remove.pools)?;
                accounts::remove(&self.transaction, remove.accounts)?;
                dreps::remove(&self.transaction, remove.dreps)?;
                proposals::remove(&self.transaction, remove.proposals)?;
            }
        }
        Ok(())
    }

    fn with_pots<'db>(
        &self,
        mut with: impl FnMut(Box<dyn std::borrow::BorrowMut<scolumns::pots::Row> + '_>),
    ) -> Result<(), StoreError> {
        let mut err = None;
        let proxy = Box::new(BorrowableProxy::new(
            pots::get(&self.transaction)?,
            |pots| {
                let put = pots::put(&self.transaction, pots);
                if let Err(e) = put {
                    err = Some(e);
                }
            },
        ));

        with(proxy);

        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn with_utxo(&self, with: impl FnMut(scolumns::utxo::Iter<'_, '_>)) -> Result<(), StoreError> {
        with_prefix_iterator(&self.transaction, utxo::PREFIX, with)
    }

    fn with_pools(
        &self,
        with: impl FnMut(scolumns::pools::Iter<'_, '_>),
    ) -> Result<(), StoreError> {
        with_prefix_iterator(&self.transaction, pools::PREFIX, with)
    }

    fn with_accounts(
        &self,
        with: impl FnMut(scolumns::accounts::Iter<'_, '_>),
    ) -> Result<(), StoreError> {
        with_prefix_iterator(&self.transaction, accounts::PREFIX, with)
    }

    fn with_block_issuers(
        &self,
        with: impl FnMut(scolumns::slots::Iter<'_, '_>),
    ) -> Result<(), StoreError> {
        with_prefix_iterator(&self.transaction, slots::PREFIX, with)
    }

    fn with_dreps(
        &self,
        with: impl FnMut(scolumns::dreps::Iter<'_, '_>),
    ) -> Result<(), StoreError> {
        with_prefix_iterator(&self.transaction, dreps::PREFIX, with)
    }

    fn with_proposals(
        &self,
        with: impl FnMut(scolumns::proposals::Iter<'_, '_>),
    ) -> Result<(), StoreError> {
        with_prefix_iterator(&self.transaction, proposals::PREFIX, with)
    }
}

impl Store for RocksDB {
    fn snapshots(&self) -> Result<Vec<Epoch>, StoreError> {
        RocksDB::snapshots(&self.dir)
    }

    #[instrument(level = Level::INFO, target = EVENT_TARGET, name = "snapshot", skip_all, fields(epoch))]
    fn next_snapshot(&'_ self, epoch: Epoch) -> Result<(), StoreError> {
        let path = self.dir.join(epoch.to_string());

        if path.exists() {
            // RocksDB error can't be created externally, so panic instead
            // It might be better to come up with a global error type
            fs::remove_dir_all(&path).map_err(|_| {
                StoreError::Internal("Unable to remove existing snapshot directory".into())
            })?;
        }

        checkpoint::Checkpoint::new(&self.db)
            .and_then(|handle| handle.create_checkpoint(path))
            .map_err(|err| StoreError::Internal(err.into()))?;

        Ok(())
    }

    #[allow(clippy::panic)]
    fn create_transaction(&self) -> impl TransactionalContext<'_> {
        if self.ongoing_transaction.get() {
            // Thats a bug in the code, we should never have two transactions at the same time
            panic!("RocksDB already has an ongoing transaction");
        }
        let transaction = self.db.transaction();
        self.ongoing_transaction.set(true);
        RocksDBTransactionalContext {
            transaction,
            db: self,
        }
    }

    fn tip(&self) -> Result<Point, StoreError> {
        self.get(KEY_TIP)?
            .ok_or(StoreError::Tip(TipErrorKind::Missing))
    }
}

pub struct RocksDBHistoricalStores {
    dir: PathBuf,
}

impl RocksDBHistoricalStores {
    pub fn for_epoch_with(base_dir: &Path, epoch: Epoch) -> Result<RocksDBSnapshot, StoreError> {
        let mut opts = Options::default();
        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(PREFIX_LEN));

        Ok(RocksDBSnapshot {
            epoch,
            db: OptimisticTransactionDB::open(
                &opts,
                base_dir.join(PathBuf::from(format!("{epoch:?}"))),
            )
            .map_err(|err| StoreError::Internal(err.into()))?,
        })
    }

    pub fn new(dir: &Path) -> Self {
        RocksDBHistoricalStores {
            dir: dir.to_path_buf(),
        }
    }
}

pub struct RocksDBSnapshot {
    epoch: Epoch,
    db: OptimisticTransactionDB,
}

impl Snapshot for RocksDBSnapshot {
    #[allow(clippy::panic)]
    fn epoch(&'_ self) -> Epoch {
        self.epoch
    }
}

impl HistoricalStores for RocksDBHistoricalStores {
    fn for_epoch(&self, epoch: Epoch) -> Result<impl Snapshot, StoreError> {
        RocksDBHistoricalStores::for_epoch_with(&self.dir, epoch)
    }
}
