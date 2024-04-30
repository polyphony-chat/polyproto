// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use spki::{AlgorithmIdentifierOwned, SignatureBitStringEncoding};
#[cfg(feature = "wasm_bindgen")]
use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
/// A signature value, generated using a [SignatureAlgorithm]
pub trait Signature: PartialEq + Eq + SignatureBitStringEncoding + Clone + ToString {
    type Signature;
    /// The signature value
    fn as_signature(&self) -> &Self::Signature;
    /// The [AlgorithmIdentifierOwned] associated with this signature
    fn algorithm_identifier() -> AlgorithmIdentifierOwned;
    /// From a bit string signature value, create a new [Self]
    fn from_bitstring(signature: &[u8]) -> Self;
}
