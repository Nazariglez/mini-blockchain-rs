use std::error;
use std::fmt;
use chrono::prelude::*;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use num_bigint::BigUint;
use num_traits::One;

const HASH_BYTE_SIZE:usize = 32;
const DIFFICULTY:usize = 4;
const MAX_NONCE:u64 = 1000000;

pub type Sha256Hash = [u8; HASH_BYTE_SIZE];

#[derive(Debug)]
pub enum MiningError {
    Iteration,
    NoParent,
}

impl fmt::Display for MiningError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MiningError::Iteration => write!(f, "could not mine block, hit iteration limit"),
            MiningError::NoParent => write!(f, "block has no parent"),
        }
    }
}

impl error::Error for MiningError {
    fn description(&self) -> &str {
        match self {
            MiningError::Iteration => "could not mine block, hit iteration limit",
            MiningError::NoParent => "block has no parent"
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

#[derive(Debug)]
pub struct Block {
    timestamp: i64,
    prev_block_hash: Sha256Hash,

    data: Vec<u8>,
    nonce: u64
}

impl Block {
    pub fn new(data: &str, prev_hash: Sha256Hash) -> Result<Block, MiningError> {
        let mut b = Block {
            prev_block_hash: prev_hash,
            data: data.into(),
            timestamp: Utc::now().timestamp(),
            nonce: 0,
        };

        b.try_hash()
            .ok_or(MiningError::Iteration)
            .and_then(|nonce| {
                b.nonce = nonce;
                Ok(b)
            })
    }

    fn try_hash(&self) -> Option<u64> {
        let target = BigUint::one() << (256 - 4 * DIFFICULTY);

        for nonce in 0..MAX_NONCE {
            let hash = Block::calculate_hash(&self, nonce);
            let hash_int = BigUint::from_bytes_be(&hash);

            //println!("target: {}, nonce: {}, hash: {:?}, hash_int: {}", target, nonce, hash, hash_int);
            if hash_int < target {
                return Some(nonce)
            }
        }

        None
    }

    pub fn hash(&self) -> Sha256Hash {
        Block::calculate_hash(&self, self.nonce)
    }

    fn calculate_hash(block: &Block, nonce: u64) -> Sha256Hash {
        let mut headers = block.headers();
        headers.extend_from_slice(&convert_u64_to_u8_array(nonce));

        let mut hasher = Sha256::new();
        hasher.input(&headers);
        let mut hash = Sha256Hash::default();

        hasher.result(&mut hash);

        hash
    }

    pub fn headers(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend(&convert_u64_to_u8_array(self.timestamp as u64));
        vec.extend_from_slice(&self.prev_block_hash);

        vec
    }

    pub fn genesis() -> Result<Block, MiningError> {
        Block::new("Genesis block", Sha256Hash::default())
    }
}

pub fn convert_u64_to_u8_array(val: u64) -> [u8; 8] {
    return [
        val as u8,
        (val >> 8) as u8,
        (val >> 16) as u8,
        (val >> 24) as u8,
        (val >> 32) as u8,
        (val >> 40) as u8,
        (val >> 48) as u8,
        (val >> 56) as u8,
    ]
}

pub struct Blockchain {
    blocks: Vec<Block> 
}

impl Blockchain {
    pub fn new() -> Result<Blockchain, MiningError> {
        let blocks = Block::genesis()?;
        Ok(Blockchain { 
            blocks: vec![blocks]
        })
    }

    pub fn add_block(&mut self, data: &str) -> Result<(), MiningError> {
        let block = match self.blocks.last() {
            Some(prev) => Block::new(data, prev.hash())?,
            None => return Err(MiningError::NoParent),
        };

        self.blocks.push(block);
        Ok(())
    }

    pub fn traverse(&self) {
        for (i, block) in self.blocks.iter().enumerate() {
            println!("block: {}", i);
            println!("hash: {:?}", block.hash());
            println!("parent: {:?}", block.prev_block_hash);
            println!("data: {:?}", block.data);
            println!();
        }
    }
}

fn main() {
    run_blockchain()
        .unwrap_or_else(|e| {
            println!("Error: {}", e);
        });
}

fn run_blockchain() -> Result<(), MiningError> {
    let mut blockchain = Blockchain::new()?;
    println!("Send 1 RC to foo");
    blockchain.add_block("enjoy, foo!")?;
    blockchain.add_block("enjoy, foo2!")?;
    blockchain.add_block("enjoy, foo3!")?;

    println!("Traversing blockchain: \n");
    blockchain.traverse();

    Ok(())
}
