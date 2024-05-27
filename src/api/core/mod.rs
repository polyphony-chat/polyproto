// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::str::FromStr;

use url::Url;
use x509_cert::serial_number::SerialNumber;

use crate::certs::idcert::IdCert;
use crate::certs::idcsr::IdCsr;
use crate::certs::{PublicKeyInfo, SessionId};
use crate::key::PublicKey;
use crate::signature::Signature;
use crate::types::routes::core::v1::*;
use crate::types::ChallengeString;

use super::{HttpClient, HttpResult};

// TODO: MLS routes still missing

impl HttpClient {
    fn normalize_url(url: &str, path: &str) -> Result<String, url::ParseError> {
        let parsed_url = Url::from_str(url)?;
        Ok(parsed_url.join(path)?.to_string())
    }
}

// Core Routes: No registration needed
impl HttpClient {
    /// Request a [ChallengeString] from the server.
    pub async fn get_challenge_string(&self, url: &str) -> HttpResult<ChallengeString> {
        let request_url = HttpClient::normalize_url(url, GET_CHALLENGE_STRING.path)?;
        let request_response = self
            .client
            .request(GET_CHALLENGE_STRING.method.clone(), request_url)
            .send()
            .await;
        HttpClient::handle_response(request_response).await
    }

    /// Request the server to rotate its identity key and return the new [IdCert]. This route is
    /// only available to server administrators.
    pub async fn rotate_server_identity_key<S: Signature, P: PublicKey<S>>(
        &self,
        url: &str,
    ) -> HttpResult<IdCert<S, P>> {
        let request_url = HttpClient::normalize_url(url, ROTATE_SERVER_IDENTITY_KEY.path)?;
        let request_response = self
            .client
            .request(ROTATE_SERVER_IDENTITY_KEY.method.clone(), request_url)
            .send()
            .await;
        let pem = HttpClient::handle_response::<String>(request_response).await?;
        Ok(IdCert::from_pem(pem.as_str(), None)?)
    }

    pub async fn get_server_id_cert<S: Signature, P: PublicKey<S>>(
        &self,
        url: &str,
    ) -> HttpResult<IdCert<S, P>> {
        todo!()
    }

    pub async fn get_server_public_key_info(&self, url: &str) -> HttpResult<PublicKeyInfo> {
        todo!()
    }

    pub async fn get_actor_id_certs<S: Signature, P: PublicKey<S>>(
        &self,
        url: &str,
    ) -> HttpResult<Vec<IdCert<S, P>>> {
        todo!()
    }

    pub async fn update_session_id_cert<S: Signature, P: PublicKey<S>>(
        &self,
        url: &str,
        new_cert: IdCert<S, P>,
    ) -> HttpResult<()> {
        todo!()
    }

    pub async fn delete_session(&self, url: &str, session_id: &SessionId) -> HttpResult<()> {
        todo!()
    }
}

// Core Routes: Registration needed
impl HttpClient {
    pub async fn rotate_session_id_cert<S: Signature, P: PublicKey<S>>(
        &self,
        url: &str,
        csr: IdCsr<S, P>,
    ) -> HttpResult<(IdCert<S, P>, String)> {
        todo!()
    }

    pub async fn upload_encrypted_pkm(&self, url: &str, data: Vec<EncryptedPkm>) -> HttpResult<()> {
        todo!()
    }

    pub async fn get_encrypted_pkm(
        &self,
        url: &str,
        serials: Vec<SerialNumber>,
    ) -> HttpResult<Vec<EncryptedPkm>> {
        todo!()
    }

    pub async fn delete_encrypted_pkm(
        &self,
        url: &str,
        serials: Vec<SerialNumber>,
    ) -> HttpResult<()> {
        todo!()
    }

    pub async fn get_pkm_upload_size_limit(&self, url: &str) -> HttpResult<u64> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPkm {
    pub serial: SerialNumber, // TODO[ser_der](bitfl0wer): Impl Serialize, Deserialize for SerialNumber
    pub encrypted_pkm: String,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_challenge_string() {
        let client = HttpClient::new();
        let url = "https://example.com/";
        let result = client.get_challenge_string(url);
        assert!(result.is_err());
    }
}
