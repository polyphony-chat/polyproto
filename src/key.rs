// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::signature::{Signature, SignatureAlgorithm};

/// A cryptographic private key generated by a [`SignatureAlgorithm`], with
/// a corresponding [`PublicKey`]
pub trait PrivateKey<T: SignatureAlgorithm> {
    type PrivateKey;
    type PublicKey: PublicKey<T>;
    type Signature: Signature;
    /// Returns a shared reference to [`Self::PrivateKey`]
    fn key(&self) -> &Self::PrivateKey;
    /// Returns an exclusive reference to [`Self::PrivateKey`]
    fn key_mut(&mut self) -> &mut Self::PrivateKey;
    /// The public key corresponding to this private key.
    fn pubkey(&self) -> &Self::PublicKey;
    /// Creates a [`Signature`] for the given data.
    fn sign(&self, data: &[u8]) -> Self::Signature;
}

/// A cryptographic public key generated by a [`SignatureAlgorithm`].
pub trait PublicKey<T: SignatureAlgorithm> {
    type PublicKey;
    type Signature: Signature;
    //TODO type Error?
    /// Returns a shared reference to [`Self::PublicKey`]
    fn key(&self) -> &Self::PublicKey;
    /// Returns an exclusive reference to [`Self::PublicKey`]
    fn key_mut(&mut self) -> &mut Self::PublicKey;
    /// Verify the correctness of a given [`Signature`] for a given piece of data.
    ///
    /// Implementations of this associated method should mitigate against signature malleability
    fn verify_signature(
        &self,
        signature: &Self::Signature,
        data: &[u8],
    ) -> Result<(), impl std::fmt::Debug>;
}
