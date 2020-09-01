
use hex_literal::hex;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use ethereum_types::{H256,U256,Address};
use parity_bytes::Bytes;
use rlp_derive::{RlpEncodable, RlpDecodable};

use crate::transaction::{UnverifiedTx};
use crate::header::Header;
use log::{debug, error};
use zmq::Socket;


/// RLP-Encode( method(string), id(number), param(rlp-encoded-list) );
#[derive(Default, Debug, Clone, PartialEq)]
pub struct IpcRequest {
    pub method: String,
    pub id: u64,
    pub params: Vec<u8>,
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct IpcReply {
    pub id: u64,
    pub result: Vec<u8>,
}

impl Encodable for IpcRequest {
    fn rlp_append(&self, s: &mut RlpStream){
        s.begin_list(3);
        s.append(&self.method);
        s.append(&self.id);
        s.append(&self.params);
    }
}

impl Decodable for IpcRequest {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.as_raw().len() != rlp.payload_info()?.total() {
            return Err(DecoderError::RlpIsTooBig);
        }
        if rlp.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        Ok(IpcRequest {
            method: rlp.val_at(0)?,
            id: rlp.val_at(1)?,
            params: rlp.val_at(2)?,
        })
    }
}

impl Encodable for IpcReply {
    fn rlp_append(&self, s: &mut RlpStream){
        s.begin_list(2);
        s.append(&self.id);
        s.append(&self.result);
    }
}

impl Decodable for IpcReply {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.as_raw().len() != rlp.payload_info()?.total() {
            return Err(DecoderError::RlpIsTooBig);
        }
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        Ok(IpcReply {
            id: rlp.val_at(0)?,
            result: rlp.val_at(1)?,
        })
    }
}

/// method: CreateHeader, Request
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct CreateHeaderReq {
    pub parent_block_hash: H256,
    pub author: Address,
    pub extra_data: Bytes,
    pub gas_limit: U256,
    pub difficulty: U256,
    pub transactions: Vec<UnverifiedTx>,
}

impl CreateHeaderReq {
    pub fn new(parent_block_hash: H256,
               author: Address,
               extra_data: Bytes,
               gas_limit: U256,
               difficulty: U256,
               transactions: Vec<UnverifiedTx>) -> Self{
        CreateHeaderReq {
            parent_block_hash,
            author,
            extra_data,
            gas_limit,
            difficulty,
            transactions,
        }
    }
}

/// method: CreateHeader, Response
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct CreateHeaderResp(pub Header);


/// method: LatestBlocks, Request
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct LatestBlocksReq(pub u64);
/// method: LatestBlocks, Response
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct LatestBlocksResp(pub Vec<Header>);


/// method: ApplyBlock, Request
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct ApplyBlockReq(pub Header,pub Vec<UnverifiedTx>);
/// method: ApplyBlock, Response
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct ApplyBlockResp(pub bool);


/// method: AccountInfo, Request
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct AccountInfoReq(pub Address);
/// method: ApplyBlock, Response
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct AccountInfoResp(pub U256, pub U256);


/// method: TxHashList, Request
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct TxHashListReq(pub H256);
/// method: TxHashList, Response
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct TxHashListResp(pub Vec<H256>);


pub fn ipc_request(socket: &Socket, request: IpcRequest) -> IpcReply {
    socket.send(rlp::encode(&request), 0).unwrap();
    let mut received_parts = socket.recv_multipart(0).unwrap();
    let msg_bytes = received_parts.pop().unwrap();
    rlp::decode(&msg_bytes).unwrap()
}


pub fn query_account_info(socket: &Socket, account: &Address) -> (U256, U256) {
    let request = IpcRequest {
        method: "AccountInfo".into(),
        id: 1,
        params: rlp::encode(&AccountInfoReq(*account)),
    };

    let reply = ipc_request(socket, request);
    let resp: AccountInfoResp = rlp::decode(&reply.result).unwrap();

    let (nonce, balance) = (resp.0, resp.1);
    debug!("query accout info: {}, {}, {}", account, nonce, balance);
    (nonce, balance)
}

pub fn query_last_block(socket: &Socket) -> Header {
    let request = IpcRequest {
        method: "LatestBlocks".into(),
        id: 1,
        params: rlp::encode(&LatestBlocksReq(1)),
    };

    let reply = ipc_request(&socket, request);
    let resp: LatestBlocksResp = rlp::decode(&reply.result).unwrap();

    let last_block_header = resp.0.get(0).unwrap().clone();
    last_block_header
}

pub fn query_latest_blocks(socket: &Socket, n: u64) -> Vec<Header> {
    let request = IpcRequest {
        method: "LatestBlocks".into(),
        id: 1,
        params: rlp::encode(&LatestBlocksReq(n)),
    };

    let reply = ipc_request(&socket, request);
    let resp: LatestBlocksResp = rlp::decode(&reply.result).unwrap();

    let headers_vec = resp.0;
    headers_vec
}

pub fn query_tx_hash_list(socket: &Socket, block_hash: H256) -> Vec<H256> {
    let request = IpcRequest {
        method: "TxHashList".into(),
        id: 1,
        params: rlp::encode(&TxHashListReq(block_hash)),
    };

    let reply = ipc_request(&socket, request);
    let resp: TxHashListResp = rlp::decode(&reply.result).unwrap();

    let hash_list = resp.0;
    hash_list
}


