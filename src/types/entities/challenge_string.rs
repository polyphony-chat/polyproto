// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};

use der::asn1::Ia5String;
use der::Length;

use crate::errors::base::ConstraintError;
use crate::errors::composite::ConversionError;
use crate::key::PrivateKey;
use crate::signature::Signature;
use crate::Constrained;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug, Clone, PartialEq, Eq)]
/// A challenge string, used to prove that an actor possesses a private key, without revealing it.
pub struct Challenge {
    pub(crate) challenge: Ia5String,
    pub expires: u64,
}

impl Challenge {
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    /// Creates a new challenge string.
    ///
    /// ## Arguments
    ///
    /// - **challenge**: The challenge string.
    /// - **expires**: The UNIX timestamp when the challenge expires.
    pub fn new(challenge: &str, expires: u64) -> Result<Self, ConversionError> {
        Ok(Self {
            challenge: Ia5String::new(challenge)?,
            expires,
        })
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    /// Completes the challenge by signing it with the private key.
    pub fn complete<S: Signature, V: PrivateKey<S>>(&self, key: &V) -> CompletedChallenge<S> {
        let s = key.sign(self.challenge.as_bytes());
        CompletedChallenge {
            challenge: self.clone(),
            signature: s,
        }
    }
}

impl Deref for Challenge {
    type Target = Ia5String;

    fn deref(&self) -> &Self::Target {
        &self.challenge
    }
}

impl DerefMut for Challenge {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.challenge
    }
}

impl Constrained for Challenge {
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    fn validate(&self) -> Result<(), crate::errors::base::ConstraintError> {
        if self.challenge.len() < Length::new(32) {
            return Err(ConstraintError::OutOfBounds {
                lower: 32,
                upper: 256,
                actual: self.challenge.len().to_string(),
                reason: "Challenge string must be at least 32 characters long".to_string(),
            });
        }

        if self.challenge.len() > Length::new(256) {
            return Err(ConstraintError::OutOfBounds {
                lower: 32,
                upper: 256,
                actual: self.challenge.len().to_string(),
                reason: "Challenge string must be at most 256 characters long".to_string(),
            });
        }

        Ok(())
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
/// A completed challenge, containing the challenge and the signature.
pub struct CompletedChallenge<S: Signature> {
    /// The challenge.
    pub challenge: Challenge,
    /// The signature of the challenge.
    pub signature: S,
}
