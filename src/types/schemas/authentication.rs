// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::certs::idcert::IdCert;
use crate::errors::composite::ConversionError;
use crate::key::PublicKey;
use crate::signature::Signature;
use crate::types::entities::{Challenge, CompletedChallenge};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
/// Schema for creating a new session.
///
/// `/p2core/session/trust`
pub struct CreateSessionRequest {
    /// The name of the actor that is creating the session.
    pub actor_name: String,
    /// PEM encoded [IdCsr]
    pub csr: String,
    /// Optional authentication payload.
    pub auth_payload: Option<String>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
/// Response counterpart of [CreateSessionSchema].
pub struct CreateSessionResponse {
    /// PEM encoded [IdCert]
    pub id_cert: String,
    /// An authentication (bearer) token.
    pub token: String,
}

impl<S: Signature, P: PublicKey<S>> TryFrom<CreateSessionResponse> for IdCert<S, P> {
    type Error = ConversionError;

    fn try_from(value: CreateSessionResponse) -> Result<Self, Self::Error> {
        Self::from_pem(&value.id_cert)
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
/// Schema for getting a challenge. Can be converted to [Challenge] using [TryFrom].
///
/// `/p2core/challenge`
pub struct GetChallengeResponse {
    /// The challenge string.
    pub challenge: String,
    /// UNIX timestamp when the challenge expires.
    pub expires: u64,
}

impl TryFrom<GetChallengeResponse> for Challenge {
    type Error = ConversionError;

    fn try_from(value: GetChallengeResponse) -> Result<Self, Self::Error> {
        Challenge::new(&value.challenge, value.expires)
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
/// Completed challenge payload.
// TODO: Move this to /types/entities or another, more appropriate module.
pub struct ChallengePayload {
    /// The challenge string.
    pub challenge: String,
    /// The signature of the challenge.
    pub signature: String,
}

impl<S: Signature> From<CompletedChallenge<S>> for ChallengePayload {
    fn from(value: CompletedChallenge<S>) -> Self {
        Self {
            challenge: value.challenge.to_string(),
            signature: value.signature.to_string(),
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
/// Identify payload to log a session in.
///
/// `/p2core/session/identify`
pub struct IdentifyRequest {
    /// A completed challenge.
    pub challenge_signature: ChallengePayload,
    /// PEM encoded [IdCert]
    pub id_cert: String,
    /// Optional authentication payload.
    pub auth_payload: Option<String>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
/// Response counterpart of [IdentifyRequest].
pub struct IdentifyResponse {
    /// An authentication (bearer) token.
    pub token: String,
    /// Optional payload from the server.
    pub payload: Option<String>,
}
