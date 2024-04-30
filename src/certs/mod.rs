// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};

use der::asn1::{BitString, Ia5String};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
use x509_cert::name::Name;

use crate::{Constrained, ConstraintError, OID_RDN_DOMAIN_COMPONENT};

/// Additional capabilities ([x509_cert::ext::Extensions] or [x509_cert::attr::Attributes], depending
/// on the context) of X.509 certificates.
pub mod capabilities;
/// Complete, signed [IdCert]
pub mod idcert;
/// [IdCertTbs] is an [IdCert] which has not yet been signed by
pub mod idcerttbs;
/// Certificate Signing Request for an [IdCert]/[IdCertTbs]
pub mod idcsr;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
/// polyproto client Session ID. Must be unique for each client. Must be between 1 and =32
/// characters in length. The session ID is used to uniquely identify a client in the context of
/// polyproto. Client certificates will change over time, but the session ID of a particular client
/// will remain the same.
///
/// [Constrained] is implemented for this type, meaning it can be validated using `.validate()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionId {
    /// The session ID, represented as an [Ia5String].
    session_id: Ia5String,
}

impl Deref for SessionId {
    type Target = Ia5String;

    fn deref(&self) -> &Self::Target {
        &self.session_id
    }
}

impl DerefMut for SessionId {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session_id
    }
}

impl SessionId {
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    #[allow(clippy::new_ret_no_self)]
    /// Creates a new [SessionId] which can be converted into an [Attribute] using `.as_attribute()`,
    /// if needed. Checks if the input is a valid Ia5String and if the [SessionId] constraints have
    /// been violated.
    pub fn new_validated(id: Ia5String) -> Result<Self, ConstraintError> {
        let session_id = SessionId { session_id: id };
        session_id.validate()?;
        Ok(session_id)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[repr(u8)]
/// `PKCS#10` version. From the PKCS specification document (RFC 2986):
/// > version is the version number, for compatibility with future
/// revisions of this document.  It shall be 0 for this version of
/// the standard.
///
/// The specification also says:
/// > `version       INTEGER { v1(0) } (v1,...),`
///
/// Version "v1" corresponds to enum variant `V1`, which is represented as the `u8`
/// integer zero (0).
pub enum PkcsVersion {
    #[default]
    /// Version 1 (0) of the PKCS#10 specification implementation
    V1 = 0,
}

/// Information regarding a subjects' public key.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct PublicKeyInfo {
    /// Properties of the signature algorithm used to create the public key.
    pub algorithm: AlgorithmIdentifierOwned,
    /// The public key, represented as a [BitString].
    pub public_key_bitstring: BitString,
}

impl From<SubjectPublicKeyInfoOwned> for PublicKeyInfo {
    fn from(value: SubjectPublicKeyInfoOwned) -> Self {
        PublicKeyInfo {
            algorithm: value.algorithm,
            public_key_bitstring: value.subject_public_key,
        }
    }
}

impl From<PublicKeyInfo> for SubjectPublicKeyInfoOwned {
    fn from(value: PublicKeyInfo) -> Self {
        SubjectPublicKeyInfoOwned {
            algorithm: value.algorithm,
            subject_public_key: value.public_key_bitstring,
        }
    }
}

/// Checks, if the domain components of two [Name]s are equal and ordered in the same way. Returns
/// `true`, if the domain components are equal, `false` otherwise.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn equal_domain_components(name_1: &Name, name_2: &Name) -> bool {
    let mut domain_components_1 = Vec::new();
    let mut domain_components_2 = Vec::new();
    for (component_1, component_2) in name_1.0.iter().zip(name_2.0.iter()) {
        for subcomponent_1 in component_1.0.iter() {
            if subcomponent_1.oid.to_string().as_str() == OID_RDN_DOMAIN_COMPONENT {
                domain_components_1.push(subcomponent_1);
            }
        }
        for subcomponent_2 in component_2.0.iter() {
            if subcomponent_2.oid.to_string().as_str() == OID_RDN_DOMAIN_COMPONENT {
                domain_components_2.push(subcomponent_2);
            }
        }
    }
    domain_components_1 == domain_components_2
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use x509_cert::name::RdnSequence;

    use super::*;
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_equal_domain_components_eq() {
        #[allow(clippy::unwrap_used)]
        let rdn_1 = RdnSequence::from_str(
            "CN=root,OU=programmer,DC=www,DC=polyphony,DC=chat,UID=root@polyphony.chat,uniqueIdentifier=root",
        )
        .unwrap();

        #[allow(clippy::unwrap_used)]
        let rdn_2 = RdnSequence::from_str(
            "CN=user1,DC=www,DC=polyphony,DC=chat,UID=user1@polyphony.chat,uniqueIdentifier=user1",
        )
        .unwrap();
        assert!(equal_domain_components(&rdn_1, &rdn_2));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_equal_domain_components_ne() {
        #[allow(clippy::unwrap_used)]
        let rdn_1 = RdnSequence::from_str(
            "CN=root,OU=programmer,DC=www,DC=polyphony,DC=chat,UID=root@polyphony.chat,uniqueIdentifier=root",
        )
        .unwrap();

        #[allow(clippy::unwrap_used)]
        let rdn_2 = RdnSequence::from_str(
            "CN=user1,DC=proto,DC=polyphony,DC=chat,UID=user1@polyphony.chat,uniqueIdentifier=user1",
        )
        .unwrap();
        assert!(!equal_domain_components(&rdn_1, &rdn_2));
    }
}
