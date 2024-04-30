// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::marker::PhantomData;

use der::pem::LineEnding;
use der::{Decode, DecodePem, Encode, EncodePem};
use spki::AlgorithmIdentifierOwned;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
use x509_cert::attr::Attributes;
use x509_cert::name::Name;
use x509_cert::request::{CertReq, CertReqInfo};

use crate::errors::composite::ConversionError;
use crate::key::{PrivateKey, PublicKey};
use crate::signature::Signature;
use crate::{Constrained, ConstraintError};

use super::capabilities::Capabilities;
use super::{PkcsVersion, PublicKeyInfo};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
/// A polyproto Certificate Signing Request, compatible with [IETF RFC 2986 "PKCS #10"](https://datatracker.ietf.org/doc/html/rfc2986).
/// Can be exchanged for an [IdCert] by requesting one from a certificate authority in exchange
/// for this [IdCsr].
///
/// In the context of PKCS #10, this is a `CertificationRequest`:
///
/// ```md
/// CertificationRequest ::= SEQUENCE {
///     certificationRequestInfo CertificationRequestInfo,
///     signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
///     signature          BIT STRING
/// }
/// ```
pub struct IdCsr<S: Signature, P: PublicKey<S>> {
    /// The CSRs main contents.
    pub inner_csr: IdCsrInner<S, P>,
    /// The signature algorithm, with which the [Signature] was created.
    pub signature_algorithm: AlgorithmIdentifierOwned,
    /// [Signature] value for the `inner_csr`
    pub signature: S,
}

impl<S: Signature, P: PublicKey<S>> IdCsr<S, P> {
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    /// Performs basic input validation and creates a new polyproto ID-Cert CSR, according to
    /// PKCS#10. The CSR is being signed using the subjects' supplied signing key ([PrivateKey])
    ///
    /// ## Arguments
    ///
    /// - **subject**: A [Name], comprised of:
    ///   - Common Name: The federation ID of the subject (actor)
    ///   - Domain Component: Actor home server subdomain, if applicable. May be repeated, depending
    ///                       on how many subdomain levels there are.
    ///   - Domain Component: Actor home server domain.
    ///   - Domain Component: Actor home server TLD, if applicable.
    ///   - Organizational Unit: Optional. May be repeated.
    /// - **signing_key**: Subject signing key. Will NOT be included in the certificate. Is used to
    ///                    sign the CSR.
    /// - **subject_unique_id**: [Uint], subject (actor) session ID. MUST NOT exceed 32 characters
    ///                          in length.
    pub fn new(
        subject: &Name,
        signing_key: &impl PrivateKey<S, PublicKey = P>,
        capabilities: &Capabilities,
    ) -> Result<IdCsr<S, P>, ConversionError> {
        subject.validate()?;
        let inner_csr = IdCsrInner::<S, P>::new(subject, signing_key.pubkey(), capabilities)?;
        let signature = signing_key.sign(&inner_csr.clone().to_der()?);
        let signature_algorithm = S::algorithm_identifier();

        Ok(IdCsr {
            inner_csr,
            signature_algorithm,
            signature,
        })
    }

    /// Validates the well-formedness of the [IdCsr] and its contents. Fails, if the [Name] or
    /// [Capabilities] do not meet polyproto validation criteria for actor CSRs, or if
    /// the signature fails to be verified.
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn valid_actor_csr(&self) -> Result<(), ConversionError> {
        self.validate()?;
        if self.inner_csr.capabilities.basic_constraints.ca {
            return Err(ConversionError::ConstraintError(
                ConstraintError::Malformed(Some("Actor CSR must not be a CA".to_string())),
            ));
        }
        Ok(())
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    /// Validates the well-formedness of the [IdCsr] and its contents. Fails, if the [Name] or
    /// [Capabilities] do not meet polyproto validation criteria for home server CSRs, or if
    /// the signature fails to be verified.
    pub fn valid_home_server_csr(&self) -> Result<(), ConversionError> {
        self.validate()?;
        if !self.inner_csr.capabilities.basic_constraints.ca {
            return Err(ConversionError::ConstraintError(
                ConstraintError::Malformed(Some("Actor CSR must be a CA".to_string())),
            ));
        }
        Ok(())
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    /// Create an IdCsr from a byte slice containing a DER encoded PKCS #10 CSR.
    pub fn from_der(bytes: &[u8]) -> Result<Self, ConversionError> {
        IdCsr::try_from(CertReq::from_der(bytes)?)
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    /// Encode this type as DER, returning a byte vector.
    pub fn to_der(self) -> Result<Vec<u8>, ConversionError> {
        Ok(CertReq::try_from(self)?.to_der()?)
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    /// Create an IdCsr from a string containing a PEM encoded PKCS #10 CSR.
    pub fn from_pem(pem: &str) -> Result<Self, ConversionError> {
        IdCsr::try_from(CertReq::from_pem(pem)?)
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    /// Encode this type as PEM, returning a string.
    pub fn to_pem(self, line_ending: LineEnding) -> Result<String, ConversionError> {
        Ok(CertReq::try_from(self)?.to_pem(line_ending)?)
    }
}

/// In the context of PKCS #10, this is a `CertificationRequestInfo`:
///
/// ```md
/// CertificationRequestInfo ::= SEQUENCE {
///     version       INTEGER { v1(0) } (v1,...),
///     subject       Name,
///     subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
///     attributes    [0] Attributes{{ CRIAttributes }}
/// }
/// ```
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IdCsrInner<S: Signature, P: PublicKey<S>> {
    /// `PKCS#10` version. Default: 0 for `PKCS#10` v1
    pub version: PkcsVersion,
    /// Information about the subject (actor).
    pub subject: Name,
    /// The subjects' public key: [PublicKey].
    pub subject_public_key: P,
    /// Capabilities requested by the subject.
    pub capabilities: Capabilities,
    phantom_data: PhantomData<S>,
}

impl<S: Signature, P: PublicKey<S>> IdCsrInner<S, P> {
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    /// Creates a new [IdCsrInner].
    ///
    /// Fails, if [Name] or [Capabilities] do not meet polyproto validation criteria.
    pub fn new(
        subject: &Name,
        public_key: &P,
        capabilities: &Capabilities,
    ) -> Result<IdCsrInner<S, P>, ConversionError> {
        subject.validate()?;
        capabilities.validate()?;

        let subject = subject.clone();
        let subject_public_key_info = public_key.clone();

        Ok(IdCsrInner {
            version: PkcsVersion::V1,
            subject,
            subject_public_key: subject_public_key_info,
            capabilities: capabilities.clone(),
            phantom_data: PhantomData,
        })
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    /// Create an IdCsrInner from a byte slice containing a DER encoded PKCS #10 CSR.
    pub fn from_der(bytes: &[u8]) -> Result<Self, ConversionError> {
        IdCsrInner::try_from(CertReqInfo::from_der(bytes)?)
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    /// Encode this type as DER, returning a byte vector.
    pub fn to_der(self) -> Result<Vec<u8>, ConversionError> {
        Ok(CertReqInfo::try_from(self)?.to_der()?)
    }
}

impl<S: Signature, P: PublicKey<S>> TryFrom<CertReq> for IdCsr<S, P> {
    type Error = ConversionError;

    fn try_from(value: CertReq) -> Result<Self, Self::Error> {
        Ok(IdCsr {
            inner_csr: IdCsrInner::try_from(value.info)?,
            signature_algorithm: value.algorithm,
            signature: S::from_bitstring(value.signature.raw_bytes()),
        })
    }
}

impl<S: Signature, P: PublicKey<S>> TryFrom<CertReqInfo> for IdCsrInner<S, P> {
    type Error = ConversionError;

    fn try_from(value: CertReqInfo) -> Result<Self, Self::Error> {
        let rdn_sequence = value.subject;
        rdn_sequence.validate()?;
        let public_key_info = PublicKeyInfo {
            algorithm: value.public_key.algorithm,
            public_key_bitstring: value.public_key.subject_public_key,
        };

        Ok(IdCsrInner {
            version: PkcsVersion::V1,
            subject: rdn_sequence,
            subject_public_key: PublicKey::try_from_public_key_info(public_key_info)?,
            capabilities: Capabilities::try_from(value.attributes)?,
            phantom_data: PhantomData,
        })
    }
}

impl<S: Signature, P: PublicKey<S>> TryFrom<IdCsr<S, P>> for CertReq {
    type Error = ConversionError;

    fn try_from(value: IdCsr<S, P>) -> Result<Self, Self::Error> {
        Ok(CertReq {
            info: value.inner_csr.try_into()?,
            algorithm: value.signature_algorithm,
            signature: value.signature.to_bitstring()?,
        })
    }
}

impl<S: Signature, P: PublicKey<S>> TryFrom<IdCsrInner<S, P>> for CertReqInfo {
    type Error = ConversionError;
    fn try_from(value: IdCsrInner<S, P>) -> Result<Self, Self::Error> {
        Ok(CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: value.subject,
            public_key: value.subject_public_key.public_key_info().into(),
            attributes: Attributes::try_from(value.capabilities)?,
        })
    }
}
