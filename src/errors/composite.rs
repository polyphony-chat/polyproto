// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use spki::ObjectIdentifier;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::base::{ConstraintError, InvalidInput};

#[derive(Error, Debug, PartialEq, Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum InvalidCert {
    #[error("The signature does not match the contents of the certificate")]
    InvalidSignature,
    #[error("The subject presented on the certificate is malformed or otherwise invalid")]
    InvalidSubject(ConstraintError),
    #[error("The issuer presented on the certificate is malformed or otherwise invalid")]
    InvalidIssuer(ConstraintError),
    #[error("The validity period of the certificate is invalid, or the certificate is expired")]
    InvalidValidity,
    #[error("The capabilities presented on the certificate are invalid or otherwise malformed")]
    InvalidCapabilities(ConstraintError),
}

#[derive(Error, Debug, PartialEq, Hash, Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum PublicKeyError {
    #[error("The signature does not match the data")]
    BadSignature,
    #[error("The provided PublicKeyInfo could not be made into a PublicKey")]
    BadPublicKeyInfo,
}

#[derive(Error, Debug, PartialEq, Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum ConversionError {
    #[error(transparent)]
    ConstraintError(#[from] ConstraintError),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInput),
    #[error("Encountered DER encoding error")]
    DerError(der::Error),
    #[error("Encountered DER OID error")]
    ConstOidError(der::oid::Error),
    #[error("Critical extension cannot be converted")]
    UnknownCriticalExtension { oid: ObjectIdentifier },
    #[error(transparent)]
    IdCertError(#[from] PublicKeyError),
}

impl From<der::Error> for ConversionError {
    fn from(value: der::Error) -> Self {
        Self::DerError(value)
    }
}

impl From<der::oid::Error> for ConversionError {
    fn from(value: der::oid::Error) -> Self {
        Self::ConstOidError(value)
    }
}
