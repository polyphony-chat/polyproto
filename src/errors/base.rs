// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use thiserror::Error;
#[cfg(feature = "wasm_bindgen")]
use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ConstraintError {
    #[error("The value did not meet the set validation criteria and is considered malformed")]
    Malformed(Option<String>),
    #[error("The value was expected to be between {lower:?} and {upper:?} but was {actual:?}")]
    OutOfBounds {
        lower: i32,
        upper: i32,
        actual: String,
        reason: String,
    },
}

/// Represents errors for invalid input in IdCsr or IdCert generation.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Error, Debug, PartialEq, Clone)]
pub enum InvalidInput {
    #[error("The value is malformed and cannot be used as input: {0}")]
    Malformed(String),
    #[error("The value was expected to be between {min_length:?} and {max_length:?} but was {actual_length:?}")]
    Length {
        min_length: usize,
        max_length: usize,
        actual_length: String,
    },
}
