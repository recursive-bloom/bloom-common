
use std::ops::Deref;

use crate::{BlockNumber, TxIndex, Error};

use ethereum_types::{H256, H160, Address, U256, BigEndianHash};
use parity_crypto::publickey::{Signature, Secret, Public, recover, public_to_address};
use keccak_hash::keccak;
use parity_bytes::Bytes;


use rlp::{self, RlpStream, Rlp, DecoderError, Encodable};


/// Fake address for unsigned transactions as defined by EIP-86.
pub const UNSIGNED_SENDER: Address = H160([0xff; 20]);

/// System sender address for internal state updates.
pub const SYSTEM_ADDRESS: Address = H160([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,0xff, 0xff, 0xff, 0xff,0xff, 0xff, 0xff, 0xff,0xff, 0xff, 0xff, 0xfe]);

/// Transaction action type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Create creates new contract.
    Create,
    /// Calls contract at given address.
    /// In the case of a transfer, this is the receiver's address.'
    Call(Address),
}

impl Default for Action {
    fn default() -> Action { Action::Create }
}

impl rlp::Decodable for Action {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.is_empty() {
            if rlp.is_data() {
                Ok(Action::Create)
            } else {
                Err(DecoderError::RlpExpectedToBeData)
            }
        } else {
            Ok(Action::Call(rlp.as_val()?))
        }
    }
}

impl rlp::Encodable for Action {
    fn rlp_append(&self, s: &mut RlpStream) {
        match *self {
            Action::Create => s.append_internal(&""),
            Action::Call(ref addr) => s.append_internal(addr),
        };
    }
}

/// Transaction activation condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// Valid at this block number or later.
    Number(BlockNumber),
    /// Valid at this unix time or later.
    Timestamp(u64),
}

/// Replay protection logic for v part of transaction's signature
pub mod signature {
    /// Adds chain id into v
    pub fn add_chain_replay_protection(v: u64, chain_id: Option<u64>) -> u64 {
        v + if let Some(n) = chain_id { 35 + n * 2 } else { 27 }
    }

    /// Returns refined v
    /// 0 if `v` would have been 27 under "Electrum" notation, 1 if 28 or 4 if invalid.
    pub fn check_replay_protection(v: u64) -> u8 {
        match v {
            v if v == 27 => 0,
            v if v == 28 => 1,
            v if v >= 35 => ((v - 1) % 2) as u8,
            _ => 4
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct UsignedTx {
    pub nonce: U256,
    pub gas_price: U256,
    pub gas: U256,
    pub action: Action,
    pub value: U256,
    pub data: Bytes,
}

impl UsignedTx {
    /// Append object with a without signature into RLP stream
    pub fn rlp_append_unsigned_tx(&self, s: &mut RlpStream, chain_id: Option<u64>) {
        let len = if chain_id.is_none() {
            6
        } else {
            9
        };
        s.begin_list(len);
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas);
        s.append(&self.action);
        s.append(&self.value);
        s.append(&self.data);
        if let Some(n) = chain_id {
            s.append(&n);
            s.append(&0u8);
            s.append(&0u8);
        }
    }
}


impl UsignedTx {
    /// The message hash of the transaction.
    pub fn hash(&self, chain_id: Option<u64>) -> H256 {
        let mut stream = RlpStream::new();
        self.rlp_append_unsigned_tx(&mut stream, chain_id);
        keccak(stream.as_raw())
    }

    /// Signs the transaction as coming from `sender`.
    pub fn sign(self, secret: &Secret, chain_id: Option<u64>) -> SignedTx {
        let sig = parity_crypto::publickey::sign(secret, &self.hash(chain_id))
            .expect("data is valid and context has signing capabilities; qed");
        SignedTx::new(self.with_signature(sig, chain_id))
            .expect("secret is valid so it's recoverable")
    }

    /// Signs the transaction with signature.
    pub fn with_signature(self, sig: Signature, chain_id: Option<u64>) -> UnverifiedTx {
        UnverifiedTx {
            us_tx: self,
            r: sig.r().into(),
            s: sig.s().into(),
            v: signature::add_chain_replay_protection(sig.v() as u64, chain_id),
            hash: H256::zero(),
        }.compute_hash()
    }

    /// Useful for test incorrectly signed transactions.
    #[cfg(test)]
    pub fn invalid_sign(self) -> UnverifiedTx {
        UnverifiedTx {
            us_tx: self,
            r: U256::one(),
            s: U256::one(),
            v: 0,
            hash: H256::zero(),
        }.compute_hash()
    }

    /// Specify the sender; this won't survive the serialize/deserialize process, but can be cloned.
    pub fn fake_sign(self, from: Address) -> SignedTx {
        SignedTx {
            uv_tx: UnverifiedTx {
                us_tx: self,
                r: U256::one(),
                s: U256::one(),
                v: 0,
                hash: H256::zero(),
            }.compute_hash(),
            sender: from,
            public: None,
        }
    }

    /// Legacy EIP-86 compatible empty signature.
    /// This method is used in json tests as well as
    /// signature verification tests.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn null_sign(self, chain_id: u64) -> SignedTx {
        SignedTx {
            uv_tx: UnverifiedTx {
                us_tx: self,
                r: U256::zero(),
                s: U256::zero(),
                v: chain_id,
                hash: H256::zero(),
            }.compute_hash(),
            sender: UNSIGNED_SENDER,
            public: None,
        }
    }
}

/// Signed transaction information without verified signature.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnverifiedTx {
    us_tx: UsignedTx,
    v: u64,
    r: U256,
    s: U256,
    hash: H256,
}

impl Deref for UnverifiedTx {
    type Target = UsignedTx;

    fn deref(&self) -> &Self::Target {
        &self.us_tx
    }
}

impl rlp::Decodable for UnverifiedTx {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        if d.item_count()? != 9 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        let hash = keccak(d.as_raw());
        Ok(UnverifiedTx {
            us_tx: UsignedTx {
                nonce: d.val_at(0)?,
                gas_price: d.val_at(1)?,
                gas: d.val_at(2)?,
                action: d.val_at(3)?,
                value: d.val_at(4)?,
                data: d.val_at(5)?,
            },
            v: d.val_at(6)?,
            r: d.val_at(7)?,
            s: d.val_at(8)?,
            hash,
        })
    }
}

impl rlp::Encodable for UnverifiedTx {
    fn rlp_append(&self, s: &mut RlpStream) { self.rlp_append_sealed_tx(s) }
}

impl UnverifiedTx {
    /// Used to compute hash of created transactions
    fn compute_hash(mut self) -> UnverifiedTx {
        let hash = keccak(&*self.rlp_bytes());
        self.hash = hash;
        self
    }

    /// Returns transaction receiver, if any
    pub fn receiver(&self) -> Option<Address> {
        match self.us_tx.action {
            Action::Create => None,
            Action::Call(receiver) => Some(receiver),
        }
    }

    /// Append object with a signature into RLP stream
    fn rlp_append_sealed_tx(&self, s: &mut RlpStream) {
        s.begin_list(9);
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas);
        s.append(&self.action);
        s.append(&self.value);
        s.append(&self.data);
        s.append(&self.v);
        s.append(&self.r);
        s.append(&self.s);
    }

    ///	Reference to unsigned part of this transaction.
    pub fn as_unsigned(&self) -> &UsignedTx {
        &self.us_tx
    }

    /// Returns standardized `v` value (0, 1 or 4 (invalid))
    pub fn standard_v(&self) -> u8 { signature::check_replay_protection(self.v) }

    /// The `v` value that appears in the RLP.
    pub fn original_v(&self) -> u64 { self.v }

    /// The chain ID, or `None` if this is a global transaction.
    pub fn chain_id(&self) -> Option<u64> {
        match self.v {
            v if v >= 35 => Some((v - 35) / 2),
            _ => None,
        }
    }

    /// Construct a signature object from the sig.
    pub fn signature(&self) -> Signature {
        let r: H256 = BigEndianHash::from_uint(&self.r);
        let s: H256 = BigEndianHash::from_uint(&self.s);
        Signature::from_rsv(&r, &s, self.standard_v())
    }

    /// Checks whether the signature has a low 's' value.
    pub fn check_low_s(&self) -> Result<(), parity_crypto::publickey::Error> {
        if !self.signature().is_low_s() {
            Err(parity_crypto::publickey::Error::InvalidSignature)
        } else {
            Ok(())
        }
    }

    /// Get the hash of this transaction (keccak of the RLP).
    pub fn hash(&self) -> H256 {
        self.hash
    }

    /// Recovers the public key of the sender.
    pub fn recover_public(&self) -> Result<Public, parity_crypto::publickey::Error> {
        Ok(recover(&self.signature(), &self.us_tx.hash(self.chain_id()))?)
    }

    /// Verify basic signature params. Does not attempt sender recovery.
    pub fn verify_basic(&self, check_low_s: bool, chain_id: Option<u64>) -> Result<(), Error> {
        if check_low_s {
            self.check_low_s()?;
        }
        match (self.chain_id(), chain_id) {
            (None, _) => {},
            (Some(n), Some(m)) if n == m => {},
            _ => return Err(Error::InvalidChainId),
        };
        Ok(())
    }

    /// Try to verify transaction and recover sender.
    pub fn verify_unordered(self) -> Result<SignedTx, parity_crypto::publickey::Error> {
        SignedTx::new(self)
    }
}

/// A `UnverifiedTransaction` with successfully recovered `sender`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SignedTx {
    uv_tx: UnverifiedTx,
    sender: Address,
    public: Option<Public>,
}

impl rlp::Encodable for SignedTx {
    fn rlp_append(&self, s: &mut RlpStream) { self.uv_tx.rlp_append_sealed_tx(s) }
}

impl Deref for SignedTx {
    type Target = UnverifiedTx;
    fn deref(&self) -> &Self::Target {
        &self.uv_tx
    }
}

impl From<SignedTx> for UnverifiedTx {
    fn from(tx: SignedTx) -> Self {
        tx.uv_tx
    }
}

impl SignedTx {
    /// Try to verify transaction and recover sender.
    pub fn new(uv_tx: UnverifiedTx) -> Result<Self, parity_crypto::publickey::Error> {
        let public = uv_tx.recover_public()?;
        let sender = public_to_address(&public);
        Ok(SignedTx {
            uv_tx: uv_tx,
            sender,
            public: Some(public),
        })
    }

    /// Returns transaction sender.
    pub fn sender(&self) -> Address {
        self.sender
    }

    /// Returns a public key of the sender.
    pub fn public_key(&self) -> Option<Public> {
        self.public
    }

    /// Deconstructs this transaction back into `UnverifiedTransaction`
    pub fn deconstruct(self) -> (UnverifiedTx, Address, Option<Public>) {
        (self.uv_tx, self.sender, self.public)
    }
}

/// Signed Transaction that is a part of canon blockchain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalizedTx {
    /// Signed part.
    pub signed: UnverifiedTx,
    /// Block number.
    pub block_number: BlockNumber,
    /// Block hash.
    pub block_hash: H256,
    /// Transaction index within block.
    pub tx_index: usize,
    /// Cached sender
    pub cached_sender: Option<Address>,
}

impl LocalizedTx {
    /// Returns transaction sender.
    /// Panics if `LocalizedTransaction` is constructed using invalid `UnverifiedTransaction`.
    pub fn sender(&mut self) -> Address {
        if let Some(sender) = self.cached_sender {
            return sender;
        }
        let sender = public_to_address(&self.recover_public()
            .expect("Localized txs are always constructed from blockchain which only stores verified txs."));
        self.cached_sender = Some(sender);
        sender
    }
}

impl Deref for LocalizedTx {
    type Target = UnverifiedTx;

    fn deref(&self) -> &Self::Target {
        &self.signed
    }
}

/// Queued transaction with additional information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTx {
    /// Signed transaction data.
    pub s_tx: SignedTx,
    /// To be activated at this condition. `None` for immediately.
    pub condition: Option<Condition>,
}

impl PendingTx {
    /// Create a new pending transaction from signed transaction.
    pub fn new(signed: SignedTx, condition: Option<Condition>) -> Self {
        PendingTx {
            s_tx: signed,
            condition: condition,
        }
    }
}

impl Deref for PendingTx {
    type Target = SignedTx;

    fn deref(&self) -> &SignedTx { &self.s_tx }
}

impl From<SignedTx> for PendingTx {
    fn from(s_tx: SignedTx) -> Self {
        PendingTx {
            s_tx: s_tx,
            condition: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxLocationError {
    DuplicatedLocation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxLocation {
    pub block_hash: H256,
    pub block_number: BlockNumber,
    pub tx_index: TxIndex,
}

impl TxLocation {
    pub fn new(block_hash: H256, block_number: BlockNumber, index: TxIndex) -> Self {
        TxLocation {
            block_hash,
            block_number,
            tx_index: index,
        }
    }
}

impl Default for TxLocation {
    fn default() -> Self {
        TxLocation {
            block_hash: H256::default(),
            block_number: 0,
            tx_index: 0,
        }
    }
}

impl rlp::Encodable for TxLocation {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.block_hash);
        s.append(&self.block_number);
        s.append(&self.tx_index);
    }
}

impl rlp::Decodable for TxLocation {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        if d.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        Ok(TxLocation {
            block_hash: d.val_at(0)?,
            block_number: d.val_at(1)?,
            tx_index: d.val_at(2)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxBody {
    pub uv_tx: UnverifiedTx,
    pub locations: Vec<TxLocation>,
}

impl Deref for TxBody {
    type Target = UnverifiedTx;

    fn deref(&self) -> &Self::Target {
        &self.uv_tx
    }
}

impl TxBody {
    pub fn new(tx: UnverifiedTx) -> Self {
        TxBody {
            uv_tx: tx,
            locations: vec![],
        }
    }

    pub fn append_location(&mut self, loc: TxLocation) -> Result<(), TxLocationError>{
        match self.locations.iter().filter(|item| item.block_hash == (&loc).block_hash).count() {
            0 => {
                self.locations.push(loc);
                Ok(())
            },
            _ => {
                Err(TxLocationError::DuplicatedLocation)
            }
        }
    }
}



impl rlp::Decodable for TxBody {
    fn decode(rlp: &Rlp) -> Result<Self, rlp::DecoderError> {
        if rlp.as_raw().len() != rlp.payload_info()?.total() {
            return Err(rlp::DecoderError::RlpIsTooBig);
        }
        if rlp.item_count()? != 2 {
            return Err(rlp::DecoderError::RlpIncorrectListLen);
        }
        Ok(TxBody {
            uv_tx: rlp.val_at(0)?,
            locations: rlp.list_at(1)?,
        })
    }
}

impl rlp::Encodable for TxBody {
    /// Get the RLP-encoding of the block with the seal.
    fn rlp_append(&self, s: &mut RlpStream){
        s.begin_list(2);
        s.append(&self.uv_tx);
        s.append_list(&self.locations);
    }
}


#[derive(Debug, Clone, PartialEq)]
pub struct TxHashList(pub Vec<H256>);


impl Default for TxHashList {
    fn default() -> Self {
        TxHashList(vec![])
    }
}

impl TxHashList {

    pub fn new(tx_vec: Vec<H256>) -> Self {
        TxHashList(tx_vec)
    }

    pub fn tx_vec(&self) -> &Vec<H256> {
        &self.0
    }
}

impl From<Vec<UnverifiedTx>> for TxHashList {
    fn from(u: Vec<UnverifiedTx>) -> Self {
        let mut hashes = vec![];
        for t in &u {
            hashes.push(t.hash())
        }
        TxHashList(hashes)
    }
}

impl rlp::Decodable for TxHashList {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.as_raw().len() != rlp.payload_info()?.total() {
            return Err(DecoderError::RlpIsTooBig);
        }
        if rlp.item_count()? != 1 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        Ok(TxHashList(rlp.list_at(0)?))
    }
}

impl rlp::Encodable for TxHashList {
    /// Get the RLP-encoding of the block with the seal.
    fn rlp_append(&self, s: &mut RlpStream){
        s.begin_list(1);
        s.append_list(&self.0);
    }
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use ethereum_types::{U256, Address};
    use keccak_hash::keccak;
    use rustc_hex::FromHex;

    #[test]
    fn sender_test() {
        let bytes: Vec<u8> = FromHex::from_hex("f85f800182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804").unwrap();
        let t: UnverifiedTx = rlp::decode(&bytes).expect("decoding UnverifiedTransaction failed");
        assert_eq!(t.data, b"");
        assert_eq!(t.gas, U256::from(0x5208u64));
        assert_eq!(t.gas_price, U256::from(0x01u64));
        assert_eq!(t.nonce, U256::from(0x00u64));
        if let Action::Call(ref to) = t.action {
            assert_eq!(*to, Address::from_str("095e7baea6a6c7c4c2dfeb977efac326af552d87").unwrap());
        } else { panic!(); }
        assert_eq!(t.value, U256::from(0x0au64));
        assert_eq!(public_to_address(&t.recover_public().unwrap()), Address::from_str("0f65fe9276bc9a24ae7083ae28e2660ef72df99e").unwrap());
        assert_eq!(t.chain_id(), None);
    }

    #[test]
    fn empty_atom_as_create_action() {
        let empty_atom = [0x80];
        let action: Action = rlp::decode(&empty_atom).unwrap();
        assert_eq!(action, Action::Create);
    }

    #[test]
    fn empty_list_as_create_action_rejected() {
        let empty_list = [0xc0];
        let action: Result<Action, DecoderError> = rlp::decode(&empty_list);
        assert_eq!(action, Err(DecoderError::RlpExpectedToBeData));
    }

    #[test]
    fn signing_eip155_zero_chainid() {
        use parity_crypto::publickey::{Random, Generator};

        let key = Random.generate();
        let t = UsignedTx {
            action: Action::Create,
            nonce: U256::from(42),
            gas_price: U256::from(3000),
            gas: U256::from(50_000),
            value: U256::from(1),
            data: b"Hello!".to_vec()
        };

        let hash = t.hash(Some(0));
        let sig = parity_crypto::publickey::sign(&key.secret(), &hash).unwrap();
        let u = t.with_signature(sig, Some(0));

        assert!(SignedTx::new(u).is_ok());
    }

    #[test]
    fn signing() {
        use parity_crypto::publickey::{Random, Generator};

        let key = Random.generate();
        let t = UsignedTx {
            action: Action::Create,
            nonce: U256::from(42),
            gas_price: U256::from(3000),
            gas: U256::from(50_000),
            value: U256::from(1),
            data: b"Hello!".to_vec()
        }.sign(&key.secret(), None);
        assert_eq!(Address::from(keccak(key.public())), t.sender());
        assert_eq!(t.chain_id(), None);
    }

    #[test]
    fn fake_signing() {
        let t = UsignedTx {
            action: Action::Create,
            nonce: U256::from(42),
            gas_price: U256::from(3000),
            gas: U256::from(50_000),
            value: U256::from(1),
            data: b"Hello!".to_vec()
        }.fake_sign(Address::from_low_u64_be(0x69));
        assert_eq!(Address::from_low_u64_be(0x69), t.sender());
        assert_eq!(t.chain_id(), None);

        let t = t.clone();
        assert_eq!(Address::from_low_u64_be(0x69), t.sender());
        assert_eq!(t.chain_id(), None);
    }

    #[test]
    fn should_reject_null_signature() {
        let t = UsignedTx {
            nonce: U256::zero(),
            gas_price: U256::from(10000000000u64),
            gas: U256::from(21000),
            action: Action::Call(Address::from_str("d46e8dd67c5d32be8058bb8eb970870f07244567").unwrap()),
            value: U256::from(1),
            data: vec![]
        }.null_sign(1);

        let res = SignedTx::new(t.uv_tx);
        match res {
            Err(parity_crypto::publickey::Error::InvalidSignature) => {}
            _ => panic!("null signature should be rejected"),
        }
    }

    #[test]
    fn should_recover_from_chain_specific_signing() {
        use parity_crypto::publickey::{Random, Generator};
        let key = Random.generate();
        let t = UsignedTx {
            action: Action::Create,
            nonce: U256::from(42),
            gas_price: U256::from(3000),
            gas: U256::from(50_000),
            value: U256::from(1),
            data: b"Hello!".to_vec()
        }.sign(&key.secret(), Some(69));
        assert_eq!(Address::from(keccak(key.public())), t.sender());
        assert_eq!(t.chain_id(), Some(69));
    }

    #[test]
    fn should_agree_with_vitalik() {
        let test_vector = |tx_data: &str, address: &'static str| {
            let bytes = rlp::decode(&tx_data.from_hex::<Vec<u8>>().unwrap()).expect("decoding tx data failed");
            let signed = SignedTx::new(bytes).unwrap();
            assert_eq!(signed.sender(), Address::from_str(&address[2..]).unwrap());
            println!("chainid: {:?}", signed.chain_id());
        };

        test_vector("f864808504a817c800825208943535353535353535353535353535353535353535808025a0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116da0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d", "0xf0f6f18bca1b28cd68e4357452947e021241e9ce");
        test_vector("f864018504a817c80182a410943535353535353535353535353535353535353535018025a0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bcaa0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6", "0x23ef145a395ea3fa3deb533b8a9e1b4c6c25d112");
        test_vector("f864028504a817c80282f618943535353535353535353535353535353535353535088025a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5", "0x2e485e0c23b4c3c542628a5f672eeab0ad4888be");
        test_vector("f865038504a817c803830148209435353535353535353535353535353535353535351b8025a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4e0a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4de", "0x82a88539669a3fd524d669e858935de5e5410cf0");
        test_vector("f865048504a817c80483019a28943535353535353535353535353535353535353535408025a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c063a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c060", "0xf9358f2538fd5ccfeb848b64a96b743fcc930554");
        test_vector("f865058504a817c8058301ec309435353535353535353535353535353535353535357d8025a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1", "0xa8f7aba377317440bc5b26198a363ad22af1f3a4");
        test_vector("f866068504a817c80683023e3894353535353535353535353535353535353535353581d88025a06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2fa06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2d", "0xf1f571dc362a0e5b2696b8e775f8491d3e50de35");
        test_vector("f867078504a817c807830290409435353535353535353535353535353535353535358201578025a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021", "0xd37922162ab7cea97c97a87551ed02c9a38b7332");
        test_vector("f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c12a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c10", "0x9bddad43f934d313c2b79ca28a432dd2b7281029");
        test_vector("f867098504a817c809830334509435353535353535353535353535353535353535358202d98025a052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afba052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb", "0x3c24d7329e92f84f08556ceb6df1cdb0104ca49f");
    }

    #[test]
    fn tx_location_test() {
        let mut loc1 = TxLocation::default();
        let block_hash = H256::from_str("40eb088232727a64c88d5e98d25e7b16ee7e9acc267c25c0088c7d1432745896").unwrap();
        loc1.block_hash = block_hash.clone();
        loc1.block_number = 100;
        loc1.tx_index = 2;

        let b = loc1.rlp_bytes();
        let loc2 = rlp::decode(b.as_slice()).expect("wrong");
        assert_eq!(loc1,loc2);
    }


    #[test]
    fn tx_body_test() {
        let bytes: Vec<u8> = FromHex::from_hex("f85f800182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804").unwrap();
        let t: UnverifiedTx = rlp::decode(&bytes).expect("decoding UnverifiedTransaction failed");

        let mut loc1 = TxLocation::default();
        let block_hash = H256::from_str("40eb088232727a64c88d5e98d25e7b16ee7e9acc267c25c0088c7d1432745896").unwrap();
        loc1.block_hash = block_hash.clone();
        loc1.block_number = 100;
        loc1.tx_index = 2;

        let mut body = TxBody::new(t);
        body.append_location(loc1);

        let body_bytes = body.rlp_bytes();
        let new_body: TxBody = rlp::decode(body_bytes.as_slice()).expect("decode error for transaction body");


        assert_eq!(new_body.data, b"");
        assert_eq!(new_body.gas, U256::from(0x5208u64));
        assert_eq!(new_body.gas_price, U256::from(0x01u64));
        assert_eq!(new_body.nonce, U256::from(0x00u64));
        if let Action::Call(ref to) = new_body.action {
            assert_eq!(*to, Address::from_str("095e7baea6a6c7c4c2dfeb977efac326af552d87").unwrap());
        } else { panic!(); }
        assert_eq!(new_body.value, U256::from(0x0au64));
        assert_eq!(public_to_address(&new_body.recover_public().unwrap()), Address::from_str("0f65fe9276bc9a24ae7083ae28e2660ef72df99e").unwrap());
        assert_eq!(new_body.chain_id(), None);
    }

    #[test]
    fn tx_list_test(){
        let tx_hash1 = H256::from_str("40eb088232727a64c88d5e98d25e7b16ee7e9acc267c25c0088c7d1432745896").unwrap();
        let tx_hash2 = H256::from_str("40eb088232727a64c88d5e98d25e7b16ee7e9acc267c25c0088c7d1432745896").unwrap();
        let txs = vec![tx_hash1,tx_hash2];
        let tx_list = TxHashList::new(txs);
        let tx_bytes = tx_list.rlp_bytes();
        let tx_list_temp: TxHashList = rlp::decode(tx_bytes.as_slice()).unwrap();
        assert_eq!(tx_list,tx_list_temp);
    }

    #[test]
    fn tx_list_from_test() {
        let bytes: Vec<u8> = FromHex::from_hex("f85f800182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804").unwrap();
        let t: UnverifiedTx = rlp::decode(&bytes).expect("decoding UnverifiedTransaction failed");
        let utrxs = vec![t.clone()];
        let tx_list = TxHashList::from(utrxs.clone());
        assert_eq!(tx_list.tx_vec(), &[t.compute_hash().hash])
    }
}
