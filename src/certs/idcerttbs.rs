// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::asn1::{BitString, Uint};

use spki::AlgorithmIdentifierOwned;
use x509_cert::certificate::{Profile, TbsCertificateInner};
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use crate::{Constrained, Error, IdCertToTbsCert, TbsCertToIdCert};

use super::capabilities::Capabilities;
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
#[derive(Debug, PartialEq, Eq)]
pub struct IdCertTbs {
    /// The certificates' serial number, as issued by the Certificate Authority.
    pub serial_number: Uint,
    /// The signature algorithm used by the Certificate Authority to sign this certificate.
    /// Must be equal to `T` in `IdCert<S: Signature, T: SignatureAlgorithm>`.
    pub signature_algorithm: AlgorithmIdentifierOwned,
    /// X.501 name, identifying the issuer of the certificate.
    pub issuer: Name,
    /// Validity period of this certificate
    pub validity: Validity,
    /// X.501 name, identifying the subject (actor) of the certificate.
    pub subject: Name,
    /// Information regarding the subjects' public key.
    pub subject_public_key_info: PublicKeyInfo,
    /// The session ID of the client. No two valid certificates may exist for one session ID.
    pub subject_session_id: BitString,
    /// X.509 Extensions matching what is described in the polyproto specification document.
    pub capabilities: Capabilities,
}

impl<P: Profile> TryFrom<TbsCertificateInner<P>> for IdCertTbs {
    type Error = Error;

    fn try_from(value: TbsCertificateInner<P>) -> Result<Self, Self::Error> {
        value.subject.validate()?;
        let subject_unique_id = match value.subject_unique_id {
            Some(suid) => suid,
            None => return Err(TbsCertToIdCert::SubjectUid.into()),
        };

        let extensions = match value.extensions {
            Some(ext) => ext,
            None => return Err(TbsCertToIdCert::Extensions.into()),
        };

        let subject_public_key_info = PublicKeyInfo::from(value.subject_public_key_info);

        let serial_number = match Uint::new(value.serial_number.as_bytes()) {
            Ok(snum) => snum,
            Err(e) => return Err(TbsCertToIdCert::Signature(e).into()),
        };

        Ok(IdCertTbs {
            serial_number,
            signature_algorithm: value.signature,
            issuer: value.issuer,
            validity: value.validity,
            subject: value.subject,
            subject_public_key_info,
            subject_session_id: subject_unique_id,
            capabilities: extensions,
        })
    }
}

impl<P: Profile> TryFrom<IdCertTbs> for TbsCertificateInner<P> {
    type Error = IdCertToTbsCert;

    fn try_from(value: IdCertTbs) -> Result<Self, Self::Error> {
        let serial_number = match SerialNumber::<P>::new(value.serial_number.as_bytes()) {
            Ok(sernum) => sernum,
            Err(e) => return Err(IdCertToTbsCert::SerialNumber(e)),
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
            subject_public_key_info: value.subject_public_key_info.into(),
            issuer_unique_id: None,
            subject_unique_id: Some(value.subject_session_id),
            extensions: Some(value.capabilities),
        })
    }
}
