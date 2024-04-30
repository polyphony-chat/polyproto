// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::asn1::Uint;
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
#[cfg(feature = "wasm_bindgen")]
use wasm_bindgen::prelude::*;
use x509_cert::certificate::{Profile, TbsCertificateInner};
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::TbsCertificate;

use crate::errors::base::InvalidInput;
use crate::errors::composite::ConversionError;
use crate::key::PublicKey;
use crate::signature::Signature;
use crate::Constrained;

use super::capabilities::Capabilities;
use super::idcsr::IdCsr;
use super::PublicKeyInfo;

/// An unsigned polyproto ID-Cert.
///
/// ID-Certs are generally more restrictive than general-use X.509-certificates, hence why a
/// conversion between those two types can fail.
///
/// There are generally two ways to obtain an [IdCertTbs]:
/// 1. Creating a self-signed certificate, when the certificate holder is supposed to be a
///    certificate authority.
/// 2. Exchanging an [IdCsr] for an [IdCertTbs] as part of an [IdCert], when the certificate holder
///    is supposed to be an actor.
///
/// ## Compatibility
///
/// This crate aims to be compatible with [x509_cert] in order to utilize the existing
/// typedefs and functionality for creating and verifying X.509 certificates provided by that
/// crate.
///
/// `IdCertTbs` implements `TryFrom<[TbsCertificateInner]<P>>`, where `TbsCertificateInner` is
/// [x509_cert::certificate::TbsCertificateInner]. This crate also provides an implementation for
/// `TryFrom<IdCertTbs<T>> for TbsCertificateInner<P>`.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IdCertTbs<S: Signature, P: PublicKey<S>> {
    /// The certificates' serial number, as issued by the Certificate Authority.
    pub serial_number: Uint,
    /// The signature algorithm used by the Certificate Authority to sign this certificate.
    pub signature_algorithm: AlgorithmIdentifierOwned,
    /// X.501 name, identifying the issuer of the certificate.
    pub issuer: Name,
    /// Validity period of this certificate
    pub validity: Validity,
    /// X.501 name, identifying the subject (actor) of the certificate.
    pub subject: Name,
    /// The subjects' public key: [PublicKey].
    pub subject_public_key: P,
    /// Capabilities assigned to the subject of the certificate.
    pub capabilities: Capabilities,
    /// PhantomData
    s: std::marker::PhantomData<S>,
}

impl<S: Signature, P: PublicKey<S>> IdCertTbs<S, P> {
    /// Create a new [IdCertTbs] by passing an [IdCsr] and other supplementary information. Returns
    /// an error, if the provided IdCsr or issuer [Name] do not pass [Constrained] verification,
    /// i.e. if they are not up to polyproto specification. Also fails if the provided IdCsr has
    /// the [BasicConstraints] "ca" flag set to `true`.
    ///
    /// See [IdCertTbs::from_ca_csr()] when trying to create a new CA certificate for home servers.
    pub(crate) fn from_actor_csr(
        id_csr: IdCsr<S, P>,
        serial_number: Uint,
        signature_algorithm: AlgorithmIdentifierOwned,
        issuer: Name,
        validity: Validity,
    ) -> Result<Self, ConversionError> {
        if id_csr.inner_csr.capabilities.basic_constraints.ca {
            return Err(ConversionError::InvalidInput(InvalidInput::Malformed(
                "Actor ID-Cert cannot have \"CA\" BasicConstraint set to true".to_string(),
            )));
        }
        id_csr.validate()?;
        issuer.validate()?;
        // Verify if signature of IdCsr matches contents
        id_csr.inner_csr.subject_public_key.verify_signature(
            &id_csr.signature,
            id_csr.inner_csr.clone().to_der()?.as_slice(),
        )?;
        Ok(IdCertTbs {
            serial_number,
            signature_algorithm,
            issuer,
            validity,
            subject: id_csr.inner_csr.subject,
            subject_public_key: id_csr.inner_csr.subject_public_key,
            capabilities: id_csr.inner_csr.capabilities,
            s: std::marker::PhantomData,
        })
    }

    /// Create a new [IdCertTbs] by passing an [IdCsr] and other supplementary information. Returns
    /// an error, if the provided IdCsr or issuer [Name] do not pass [Constrained] verification,
    /// i.e. if they are not up to polyproto specification. Also fails if the provided IdCsr has
    /// the [BasicConstraints] "ca" flag set to `false`.
    ///
    /// See [IdCertTbs::from_actor_csr()] when trying to create a new actor certificate.
    pub(crate) fn from_ca_csr(
        id_csr: IdCsr<S, P>,
        serial_number: Uint,
        signature_algorithm: AlgorithmIdentifierOwned,
        issuer: Name,
        validity: Validity,
    ) -> Result<Self, ConversionError> {
        if !id_csr.inner_csr.capabilities.basic_constraints.ca {
            return Err(ConversionError::InvalidInput(InvalidInput::Malformed(
                "CA ID-Cert must have \"CA\" BasicConstraint set to true".to_string(),
            )));
        }
        id_csr.validate()?;
        // Verify if signature of IdCsr matches contents
        id_csr.inner_csr.subject_public_key.verify_signature(
            &id_csr.signature,
            id_csr.inner_csr.clone().to_der()?.as_slice(),
        )?;
        Ok(IdCertTbs {
            serial_number,
            signature_algorithm,
            issuer,
            validity,
            subject: id_csr.inner_csr.subject,
            subject_public_key: id_csr.inner_csr.subject_public_key,
            capabilities: id_csr.inner_csr.capabilities,
            s: std::marker::PhantomData,
        })
    }

    /// Encode this type as DER, returning a byte vector.
    pub fn to_der(self) -> Result<Vec<u8>, ConversionError> {
        Ok(TbsCertificate::try_from(self)?.to_der()?)
    }

    /// Create an IdCsr from a byte slice containing a DER encoded PKCS #10 CSR.
    pub fn from_der(bytes: &[u8]) -> Result<Self, ConversionError> {
        IdCertTbs::try_from(TbsCertificate::from_der(bytes)?)
    }
}

impl<P: Profile, S: Signature, Q: PublicKey<S>> TryFrom<TbsCertificateInner<P>>
    for IdCertTbs<S, Q>
{
    type Error = ConversionError;

    fn try_from(value: TbsCertificateInner<P>) -> Result<Self, Self::Error> {
        value.subject.validate()?;

        let capabilities =
            match value.extensions {
                Some(ext) => Capabilities::try_from(ext)?,
                None => return Err(ConversionError::InvalidInput(
                    crate::errors::base::InvalidInput::Malformed(
                        "field 'extensions' was None. Expected: Some(x509_cert::ext::Extensions)"
                            .to_string(),
                    ),
                )),
            };
        let subject_public_key_info = PublicKey::try_from_public_key_info(PublicKeyInfo::from(
            value.subject_public_key_info,
        ))?;

        let serial_number = Uint::new(value.serial_number.as_bytes())?;

        Ok(Self {
            serial_number,
            signature_algorithm: value.signature,
            issuer: value.issuer,
            validity: value.validity,
            subject: value.subject,
            subject_public_key: subject_public_key_info,
            capabilities,
            s: std::marker::PhantomData,
        })
    }
}

impl<P: Profile, S: Signature, Q: PublicKey<S>> TryFrom<IdCertTbs<S, Q>>
    for TbsCertificateInner<P>
{
    type Error = ConversionError;

    fn try_from(value: IdCertTbs<S, Q>) -> Result<Self, Self::Error> {
        let serial_number = match SerialNumber::<P>::new(value.serial_number.as_bytes()) {
            Ok(sernum) => sernum,
            Err(e) => {
                return Err(ConversionError::InvalidInput(
                    crate::errors::base::InvalidInput::Malformed(format!(
                        "Could not convert serial number: {}",
                        e
                    )),
                ))
            }
        };

        let signature = AlgorithmIdentifierOwned {
            oid: value.signature_algorithm.oid,
            parameters: value.signature_algorithm.parameters,
        };

        Ok(TbsCertificateInner {
            version: x509_cert::Version::V3,
            serial_number,
            signature,
            issuer: value.issuer,
            validity: value.validity,
            subject: value.subject,
            subject_public_key_info: value.subject_public_key.public_key_info().into(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(Extensions::try_from(value.capabilities)?),
        })
    }
}
