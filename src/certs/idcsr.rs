// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::marker::PhantomData;

use der::asn1::BitString;
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attributes;
use x509_cert::name::Name;
use x509_cert::request::{CertReq, CertReqInfo};

use crate::key::{PrivateKey, PublicKey};
use crate::signature::Signature;
use crate::{Constrained, Error};

use super::capabilities::Capabilities;
use super::{PkcsVersion, PublicKeyInfo};

#[derive(Debug, Clone, PartialEq, Eq)]
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
pub struct IdCsr<S: Signature> {
    /// The CSRs main contents.
    pub inner_csr: IdCsrInner<S>,
    /// The signature algorithm, with which the [Signature] was created.
    pub signature_algorithm: AlgorithmIdentifierOwned,
    /// [Signature] value for the `inner_csr`
    pub signature: S,
}

impl<S: Signature> IdCsr<S> {
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
        signing_key: &impl PrivateKey<S>,
        capabilities: &Capabilities,
    ) -> Result<IdCsr<S>, Error> {
        subject.validate()?;
        let inner_csr = IdCsrInner::<S>::new(subject, signing_key.pubkey(), capabilities)?;
        let cert_req_info = CertReqInfo::try_from(inner_csr)?;
        let signature = signing_key.sign(&cert_req_info.to_der()?);
        let inner_csr = IdCsrInner::<S>::try_from(cert_req_info)?;

        let signature_algorithm = S::algorithm_identifier();

        Ok(IdCsr {
            inner_csr,
            signature_algorithm,
            signature,
        })
    }

    /// Validates the well-formedness of the [IdCsr] and its contents. Fails, if the [Name] or
    /// [Capabilities] do not meet polyprotos' validation criteria for actor CSRs.
    ///
    /// ## Signature Verification
    ///
    /// This method does not verify the signature of the [IdCsr]. To verify the signature, use the
    /// [crate::key::PublicKey::verify_signature] method. If you do not have the public key as a
    /// `dyn PublicKey`, you can use the [crate::key::PublicKey::from_public_key_info] method to
    /// create a `dyn PublicKey` from the [PublicKeyInfo] in the [IdCsrInner].
    pub fn valid_actor_csr(&self) -> Result<(), Error> {
        self.inner_csr.subject.validate()?;
        self.inner_csr.capabilities.validate()?;
        if self.inner_csr.capabilities.basic_constraints.ca {
            return Err(Error::ConstraintError(crate::ConstraintError::Malformed(
                Some("Actor CSR must not be a CA".to_string()),
            )));
        }
        Ok(())
    }

    /// Validates the well-formedness of the [IdCsr] and its contents. Fails, if the [Name] or
    /// [Capabilities] do not meet polyprotos' validation criteria for home server CSRs.
    ///
    /// ## Signature Verification
    ///
    /// This method does not verify the signature of the [IdCsr]. To verify the signature, use the
    /// [crate::key::PublicKey::verify_signature] method. If you do not have the public key as a
    /// `dyn PublicKey`, you can use the [crate::key::PublicKey::from_public_key_info] method to
    /// create a `dyn PublicKey` from the [PublicKeyInfo] in the [IdCsrInner].
    pub fn valid_home_server_csr(&self) -> Result<(), Error> {
        self.inner_csr.subject.validate()?;
        self.inner_csr.capabilities.validate()?;
        if !self.inner_csr.capabilities.basic_constraints.ca {
            return Err(Error::ConstraintError(crate::ConstraintError::Malformed(
                Some("Actor CSR must be a CA".to_string()),
            )));
        }
        Ok(())
    }

    /// Create an IdCsr from a byte slice containing a DER encoded PKCS #10 CSR.
    pub fn from_der(bytes: &[u8]) -> Result<Self, Error> {
        IdCsr::try_from(CertReq::from_der(bytes)?)
    }

    /// Encode this type as DER, returning a byte vector.
    pub fn to_der(self) -> Result<Vec<u8>, Error> {
        Ok(CertReq::try_from(self)?.to_der()?)
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
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IdCsrInner<S: Signature> {
    /// `PKCS#10` version. Default: 0 for `PKCS#10` v1
    pub version: PkcsVersion,
    /// Information about the subject (actor).
    pub subject: Name,
    /// The subjects' public key and related metadata.
    pub subject_public_key_info: PublicKeyInfo,
    /// attributes is a collection of attributes providing additional
    /// information about the subject of the certificate.
    pub capabilities: Capabilities,
    phantom_data: PhantomData<S>,
}

impl<S: Signature> IdCsrInner<S> {
    /// Creates a new [IdCsrInner].
    ///
    /// Fails, if [Name] or [Capabilities] do not meet polyproto validation criteria.
    pub fn new(
        subject: &Name,
        public_key: &impl PublicKey<S>,
        capabilities: &Capabilities,
    ) -> Result<IdCsrInner<S>, Error> {
        subject.validate()?;
        capabilities.validate()?;

        let subject_public_key_info = PublicKeyInfo {
            algorithm: public_key.public_key_info().algorithm,
            public_key_bitstring: BitString::from_der(
                &public_key.public_key_info().public_key_bitstring.to_der()?,
            )?,
        };

        let subject = subject.clone();

        Ok(IdCsrInner {
            version: PkcsVersion::V1,
            subject,
            subject_public_key_info,
            capabilities: capabilities.clone(),
            phantom_data: PhantomData,
        })
    }

    /// Create an IdCsrInner from a byte slice containing a DER encoded PKCS #10 CSR.
    pub fn from_der(bytes: &[u8]) -> Result<Self, Error> {
        IdCsrInner::try_from(CertReqInfo::from_der(bytes)?)
    }

    /// Encode this type as DER, returning a byte vector.
    pub fn to_der(self) -> Result<Vec<u8>, Error> {
        Ok(CertReqInfo::try_from(self)?.to_der()?)
    }
}

impl<S: Signature> TryFrom<CertReq> for IdCsr<S> {
    type Error = Error;

    fn try_from(value: CertReq) -> Result<Self, Error> {
        Ok(IdCsr {
            inner_csr: IdCsrInner::try_from(value.info)?,
            signature_algorithm: value.algorithm,
            // TODO: raw_bytes() or as_bytes()?
            signature: S::from_bitstring(value.signature.raw_bytes()),
        })
    }
}

impl<S: Signature> TryFrom<CertReqInfo> for IdCsrInner<S> {
    type Error = Error;

    fn try_from(value: CertReqInfo) -> Result<Self, Self::Error> {
        let rdn_sequence = value.subject;
        rdn_sequence.validate()?;
        let public_key = PublicKeyInfo {
            algorithm: value.public_key.algorithm,
            public_key_bitstring: value.public_key.subject_public_key,
        };

        Ok(IdCsrInner {
            version: PkcsVersion::V1,
            subject: rdn_sequence,
            subject_public_key_info: public_key,
            capabilities: Capabilities::try_from(value.attributes)?,
            phantom_data: PhantomData,
        })
    }
}

impl<S: Signature> TryFrom<IdCsr<S>> for CertReq {
    type Error = Error;

    fn try_from(value: IdCsr<S>) -> Result<Self, Self::Error> {
        Ok(CertReq {
            info: value.inner_csr.try_into()?,
            algorithm: value.signature_algorithm,
            signature: value.signature.to_bitstring()?,
        })
    }
}

impl<S: Signature> TryFrom<IdCsrInner<S>> for CertReqInfo {
    type Error = Error;
    fn try_from(value: IdCsrInner<S>) -> Result<Self, Self::Error> {
        Ok(CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: value.subject,
            public_key: value.subject_public_key_info.into(),
            attributes: Attributes::try_from(value.capabilities)?,
        })
    }
}
