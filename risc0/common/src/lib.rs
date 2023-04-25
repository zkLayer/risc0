// Copyright 2023 RISC Zero, Inc.
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

#![doc = include_str!("../README.md")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]

use std::{collections::HashMap, fmt, str::FromStr, string::ToString};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const ZKVM_PLATFORM_VER: &str = "ZKVM_PLATFORM_VER";
const ZKVM_CIRCUIT_VER: &str = "ZKVM_CIRCUIT_VER";
const ZKVM_PROVER_HASH: &str = "ZKVM_PROVER_HASH";

const REQUIRED_KEYS: &[&str] = &[ZKVM_PLATFORM_VER, ZKVM_CIRCUIT_VER, ZKVM_PROVER_HASH];

/// Sha256 hash value
pub const ZKVM_HASH_SHA256: &str = "sha256";
/// Poseidon hash value
pub const ZKVM_HASH_POSEIDON: &str = "poseidon";

/// Errors for the risc0-common crate
#[derive(Error, Debug)]
pub enum CommonErr {
    /// Invalid hashing string identifier
    #[error("The requested hash `{0}` is not supported")]
    InvalidHash(String),

    /// Inner [BodyType] does not match requested conversion
    #[error("Invalid inner data type: `{0}`")]
    InvalidDataType(String),

    /// Failure to deserialize the inner data
    #[error("bincode failed to deserialize inner type")]
    BincodeErr(#[from] Box<bincode::ErrorKind>),

    /// Metadata is invalid, or missing required keys
    #[error("Metadata was constructed with invalid key/value pairs")]
    BadMetadata,
}

/// Types of supported hashes in the zkvm
pub enum Hashes {
    /// Sha256 hashing function
    Sha256,
    /// poseidon hashing function
    Poseidon,
}

impl FromStr for Hashes {
    type Err = CommonErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            ZKVM_HASH_SHA256 => Ok(Self::Sha256),
            ZKVM_HASH_POSEIDON => Ok(Self::Poseidon),
            _ => Err(CommonErr::InvalidHash(s.to_string())),
        }
    }
}

impl ToString for Hashes {
    fn to_string(&self) -> String {
        match self {
            Self::Sha256 => ZKVM_HASH_SHA256.to_string(),
            Self::Poseidon => ZKVM_HASH_POSEIDON.to_string(),
        }
    }
}

impl Default for Hashes {
    fn default() -> Self {
        Self::Sha256 // Default hashing scheme
    }
}

/// Risc Zero metadata for the [Envelope]
#[derive(Deserialize, Serialize)]
pub struct MetaData(pub HashMap<String, String>);

impl MetaData {
    fn hash_from_prover_env() -> Hashes {
        let mut res = Hashes::default();

        let r0_prover = std::env::var("RISC0_PROVER");
        let r0_prover = if let Ok(prover_var) = r0_prover {
            prover_var
        } else {
            return res;
        };

        let splits: Vec<&str> = r0_prover.split(':').collect();
        if splits.len() < 2 {
            return res;
        }
        let hash_str = splits[1];

        res = Hashes::from_str(hash_str)
            .unwrap_or_else(|_| panic!("Invalid hash string in RISC0_PROVER env var: {hash_str}"));
        res
    }

    /// Construct [MetaData] from a [Hashes] selection
    pub fn from_env() -> Self {
        let mut inner: HashMap<String, String> = HashMap::new();
        inner.insert(
            ZKVM_CIRCUIT_VER.to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        );
        inner.insert(
            ZKVM_PLATFORM_VER.to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        );

        let hash = Self::hash_from_prover_env();

        inner.insert(ZKVM_PROVER_HASH.to_string(), hash.to_string());
        Self(inner)
    }

    /// Construct [MetaData] from supplied key values
    pub fn from_user(values: &[(&str, &str)]) -> Result<Self, CommonErr> {
        let mut inner = HashMap::new();
        for (key, val) in values {
            inner.insert(key.to_string(), val.to_string());
        }

        let res = Self(inner);

        if !res.valid() {
            return Err(CommonErr::BadMetadata);
        }

        Ok(res)
    }

    /// Check if this [MetaData] has the required keys
    pub fn valid(&self) -> bool {
        for key in REQUIRED_KEYS {
            if !self.0.contains_key(&key.to_string()) {
                return false;
            }
        }
        true
    }

    /// Check the if provided key-value pairs match the metadata
    pub fn compatible(&self, values: &[(&str, &str)]) -> bool {
        for (key, val) in values {
            let fetched = self.0.get(&key.to_string());
            if let Some(self_val) = fetched {
                if self_val.as_str() != *val {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }

    /// Helper to access ZKVM_PLATFORM_VER
    pub fn zkvm_platform_version(&self) -> &str {
        self.0.get(ZKVM_PLATFORM_VER).unwrap()
    }

    /// Helper to access ZKVM_CIRCUIT_VER
    pub fn zkvm_circuit_version(&self) -> &str {
        self.0.get(ZKVM_CIRCUIT_VER).unwrap()
    }

    /// Helper to access ZKVM_PROVER_HASH
    pub fn zkvm_prover_hash(&self) -> &str {
        self.0.get(ZKVM_PROVER_HASH).unwrap()
    }
}

/// Type of data contained within the [Envelope]
#[derive(Deserialize, Serialize, PartialEq, Debug)]
pub enum BodyType {
    /// Segment data
    Segment,
    /// Session data
    Session,
    /// Memory Image Data
    MemoryImage,
    /// Segment Receipt Data
    SegmentReceipt,
    /// Session Receipt Data
    SessionReceipt,
}

impl fmt::Display for BodyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BodyType::Segment => write!(f, "Segment"),
            BodyType::Session => write!(f, "Session"),
            BodyType::MemoryImage => write!(f, "MemoryImage"),
            BodyType::SegmentReceipt => write!(f, "SegmentReceipt"),
            BodyType::SessionReceipt => write!(f, "SessionReceipt"),
        }
    }
}

/// Risc Zero version agnostic serializable data wrapper
///
/// TODO: Explainer on usage
#[derive(Deserialize, Serialize)]
pub struct Envelope {
    /// [MetaData] associated with the contained data
    pub metadata: MetaData,
    /// Type of data contained within the envelope
    pub body_type: BodyType,
    body: Vec<u8>,
}

/// Convertions methods for working with data within [Envelope]
#[cfg(feature = "zkvm")]
pub mod conversion {
    use risc0_zkvm::{MemoryImage, Segment, SegmentReceipt, Session, SessionReceipt};

    use crate::{BodyType, CommonErr, Envelope, MetaData};

    // TryFrom Deserialization methods:
    macro_rules! declare_tryfrom_deserial {
        ($name:ident) => {
            impl TryFrom<Envelope> for $name {
                type Error = CommonErr;
                fn try_from(value: Envelope) -> Result<Self, Self::Error> {
                    if !matches!(value.body_type, BodyType::$name) {
                        return Err(CommonErr::InvalidDataType(value.body_type.to_string()));
                    }
                    let res = bincode::deserialize(&value.body)?;
                    Ok(res)
                }
            }
        };
    }

    declare_tryfrom_deserial!(Segment);
    declare_tryfrom_deserial!(Session);
    declare_tryfrom_deserial!(MemoryImage);
    declare_tryfrom_deserial!(SegmentReceipt);
    declare_tryfrom_deserial!(SessionReceipt);

    // TryFrom Serialization methods
    macro_rules! declare_tryfrom_serialize {
        ($name:ident) => {
            impl TryFrom<$name> for Envelope {
                type Error = CommonErr;
                fn try_from(value: $name) -> Result<Self, Self::Error> {
                    Ok(Self {
                        metadata: MetaData::from_env(),
                        body_type: BodyType::$name,
                        body: bincode::serialize(&value)?,
                    })
                }
            }
        };
    }

    declare_tryfrom_serialize!(Segment);
    declare_tryfrom_serialize!(Session);
    declare_tryfrom_serialize!(MemoryImage);
    declare_tryfrom_serialize!(SegmentReceipt);
    declare_tryfrom_serialize!(SessionReceipt);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_simple() {
        let metadata = MetaData::from_env();
        assert_eq!(metadata.zkvm_prover_hash(), "sha256");
        assert_eq!(metadata.zkvm_circuit_version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(metadata.zkvm_platform_version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn metadata_from_user() {
        let values = [
            (ZKVM_PLATFORM_VER, "0.1"),
            (ZKVM_CIRCUIT_VER, "0.1"),
            (ZKVM_PROVER_HASH, "sha256"),
        ];
        let metadata = MetaData::from_user(&values).unwrap();
        assert_eq!(metadata.zkvm_prover_hash(), "sha256");

        let values = [(ZKVM_PLATFORM_VER, "0.1"), (ZKVM_CIRCUIT_VER, "0.1")];
        let metadata = MetaData::from_user(&values);
        assert!(metadata.is_err())
    }

    #[test]
    fn metadata_valid() {
        let mut metadata = MetaData::from_env();
        assert!(metadata.valid());

        metadata.0.insert("TEST_KEY".into(), "TEST_VALUE".into());
        assert!(metadata.valid());

        metadata.0.remove(ZKVM_PLATFORM_VER);
        assert!(!metadata.valid());
    }

    #[test]
    fn metadata_compatible() {
        let mut metadata = MetaData::from_env();
        let cargo_ver = env!("CARGO_PKG_VERSION");

        // Only base keys
        let values = [
            (ZKVM_CIRCUIT_VER, cargo_ver),
            (ZKVM_PLATFORM_VER, cargo_ver),
            (ZKVM_PROVER_HASH, &Hashes::default().to_string()),
        ];
        assert!(metadata.compatible(&values));

        // missing key
        let values = [
            (ZKVM_CIRCUIT_VER, cargo_ver),
            (ZKVM_PLATFORM_VER, cargo_ver),
        ];
        assert!(metadata.compatible(&values));

        // additional custom key
        let values = [
            (ZKVM_CIRCUIT_VER, cargo_ver),
            (ZKVM_PLATFORM_VER, cargo_ver),
            (ZKVM_PROVER_HASH, &Hashes::default().to_string()),
            ("TEST_KEY", "TEST_VAL"),
        ];
        assert!(!metadata.compatible(&values));

        metadata.0.insert("TEST_KEY".into(), "TEST_VAL".into());
        assert!(metadata.compatible(&values));
    }

    #[test]
    #[cfg(feature = "zkvm")]
    fn envelope_simple() {
        use risc0_zkvm::SessionReceipt;

        let session_receipt = SessionReceipt {
            journal: vec![],
            segments: vec![],
        };

        let envelope = Envelope::try_from(session_receipt).unwrap();
        assert_eq!(envelope.body.len(), 16);
        assert_eq!(envelope.body_type, BodyType::SessionReceipt);
        assert!(envelope.metadata.valid());
    }
}
