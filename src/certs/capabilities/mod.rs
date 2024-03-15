// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/// "basicConstraints" IdCert/Csr capabilities
pub mod basic_constraints;
/// "keyUsage" IdCert/Csr capabilities
pub mod key_usage;
pub use basic_constraints::*;
pub use key_usage::*;

use der::asn1::SetOfVec;
use der::Any;

use spki::ObjectIdentifier;
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::ext::{Extension, Extensions};

use crate::{Constrained, ConstraintError, Error};

/// Object Identifier for the KeyUsage::DigitalSignature variant.
pub const OID_KEY_USAGE_DIGITAL_SIGNATURE: &str = "1.3.6.1.5.5.7.3.3";
/// Object Identifier for the KeyUsage::CrlSign variant.
pub const OID_KEY_USAGE_CRL_SIGN: &str = "1.3.6.1.5.5.7.3.2";
/// Object Identifier for the KeyUsage::ContentCommitment variant.
pub const OID_KEY_USAGE_CONTENT_COMMITMENT: &str = "1.3.6.1.5.5.7.3.8";
/// Object Identifier for the KeyUsage::KeyEncipherment variant.
pub const OID_KEY_USAGE_KEY_ENCIPHERMENT: &str = "1.3.6.1.5.5.7.3.1";
/// Object Identifier for the KeyUsage::DataEncipherment variant.
pub const OID_KEY_USAGE_DATA_ENCIPHERMENT: &str = "1.3.6.1.5.5.7.3.4";
/// Object Identifier for the KeyUsage::KeyAgreement variant.
pub const OID_KEY_USAGE_KEY_AGREEMENT: &str = "1.3.6.1.5.5.7.3.9";
/// Object Identifier for the KeyUsage::KeyCertSign variant.
pub const OID_KEY_USAGE_KEY_CERT_SIGN: &str = "1.3.6.1.5.5.7.3.3";
/// Object Identifier for the KeyUsage::EncipherOnly variant.
pub const OID_KEY_USAGE_ENCIPHER_ONLY: &str = "1.3.6.1.5.5.7.3.7";
/// Object Identifier for the KeyUsage::DecipherOnly variant.
pub const OID_KEY_USAGE_DECIPHER_ONLY: &str = "1.3.6.1.5.5.7.3.6";
/// Object Identifier for the BasicConstraints variant.
pub const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// [Capabilities] acts as a higher-level adapter type to easily work with [Extensions] on IdCerts
/// and [Abilities] on IdCsrs.
///
/// This struct only covers the `certCapability` subtype trees of which at least one of the subtypes
/// are relevant to polyproto certificates.
pub struct Capabilities {
    /// The key usage extension defines the purpose of the key contained in the certificate.
    pub key_usage: Vec<KeyUsage>,
    /// Extension type that defines whether a given certificate is allowed
    /// to sign additional certificates and what path length restrictions may exist.
    pub basic_constraints: BasicConstraints,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            key_usage: Default::default(),
            basic_constraints: BasicConstraints {
                ca: false,
                path_length: None,
            },
        }
    }
}

impl Capabilities {
    /// Sane default for actor [IdCsr]/[IdCert] [Capabilities]. Uses the DigitalSignature flag,
    /// not the ContentCommitment flag.
    pub fn default_actor() -> Self {
        let key_usage = vec![KeyUsage::DigitalSignature(true)];
        let basic_constraints = BasicConstraints {
            ca: false,
            path_length: None,
        };
        Self {
            key_usage,
            basic_constraints,
        }
    }

    /// Sane default for home server [IdCsr]/[IdCert] [Capabilities].
    pub fn default_home_server() -> Self {
        let key_usage = vec![KeyUsage::KeyCertSign(true)];
        let basic_constraints = BasicConstraints {
            ca: true,
            path_length: Some(1),
        };
        Self {
            key_usage,
            basic_constraints,
        }
    }
}

impl TryFrom<Attributes> for Capabilities {
    type Error = Error;

    /// Performs the conversion.
    ///
    /// Fails if the BasicConstraints or KeyUsages are malformed. The constraints returned by
    /// this method are not guaranteed to be valid. You should call `validate()` on the result
    /// to ensure that the constraints are valid according to the X.509 standard and the polyproto
    /// specification.
    fn try_from(value: Attributes) -> Result<Self, Self::Error> {
        let mut key_usages: Vec<KeyUsage> = Vec::new();
        let mut basic_constraints = BasicConstraints::default();
        let mut num_basic_constraints = 0u8;
        for item in value.iter() {
            match item.oid.to_string().as_str() {
                #[allow(unreachable_patterns)] // cargo thinks the below pattern is unreachable.
                OID_KEY_USAGE_CONTENT_COMMITMENT
                | OID_KEY_USAGE_CRL_SIGN
                | OID_KEY_USAGE_DATA_ENCIPHERMENT
                | OID_KEY_USAGE_DECIPHER_ONLY
                | OID_KEY_USAGE_DIGITAL_SIGNATURE
                | OID_KEY_USAGE_ENCIPHER_ONLY
                | OID_KEY_USAGE_KEY_AGREEMENT
                | OID_KEY_USAGE_KEY_CERT_SIGN
                | OID_KEY_USAGE_KEY_ENCIPHERMENT => {
                    key_usages.push(KeyUsage::try_from(item.clone())?);
                }
                OID_BASIC_CONSTRAINTS => {
                    num_basic_constraints += 1;
                    if num_basic_constraints > 1 {
                        return Err(Error::InvalidInput(crate::InvalidInput::IncompatibleVariantForConversion { reason: "Tried inserting > 1 BasicConstraints into Capabilities. Expected 1 BasicConstraints".to_string() }));
                    } else {
                        basic_constraints = BasicConstraints::try_from(item.clone())?;
                    }
                }
                _ => (),
            }
        }
        Ok(Capabilities {
            key_usage: key_usages,
            basic_constraints,
        })
    }
}

impl TryFrom<Capabilities> for Attributes {
    /// Performs the conversion.
    ///
    /// Fails, if `Capabilities::verify()` using the `Constrained` trait fails.
    fn try_from(value: Capabilities) -> Result<Self, Self::Error> {
        value.validate()?;
        let mut sov = SetOfVec::new();
        for item in value.key_usage.iter() {
            let insertion = sov.insert(Attribute::from(*item));
            if insertion.is_err() {
                return Err(ConstraintError::Malformed(Some("Tried inserting non-unique element into SetOfVec. You likely have a duplicate value in your Capabilities".to_string())));
            }
        }
        let insertion = sov.insert(Attribute::from(value.basic_constraints));
        if insertion.is_err() {
            return Err(ConstraintError::Malformed(Some("Tried inserting non-unique element into SetOfVec. You likely have a duplicate value in your Capabilities".to_string())));
        }
        Ok(sov)
    }

    type Error = ConstraintError;
}

impl TryFrom<Capabilities> for Extensions {
    type Error = Error;

    fn try_from(value: Capabilities) -> Result<Self, Self::Error> {
        let mut extension_vec = Vec::new();
        for capability in value.key_usage.iter() {
            let extension = Extension {
                extn_id: capability.to_oid(),
                critical: false,
                extn_value: capability,
            };
        }
        todo!()
    }
}

impl TryFrom<Extensions> for Capabilities {
    type Error = Error;

    fn try_from(value: Extensions) -> Result<Self, Self::Error> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use spki::ObjectIdentifier;

    use super::*;
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_key_usage_to_object_identifier() {
        let _ = ObjectIdentifier::from(KeyUsage::DigitalSignature(true));
        let _ = ObjectIdentifier::from(KeyUsage::CrlSign(true));
        let _ = ObjectIdentifier::from(KeyUsage::ContentCommitment(true));
        let _ = ObjectIdentifier::from(KeyUsage::KeyEncipherment(true));
        let _ = ObjectIdentifier::from(KeyUsage::DataEncipherment(true));
        let _ = ObjectIdentifier::from(KeyUsage::KeyAgreement(true));
        let _ = ObjectIdentifier::from(KeyUsage::KeyCertSign(true));
        let _ = ObjectIdentifier::from(KeyUsage::EncipherOnly(true));
        let _ = ObjectIdentifier::from(KeyUsage::DecipherOnly(true));
    }

    fn test_key_usage_to_attribute(val: bool) {
        let _ = Attribute::from(KeyUsage::DigitalSignature(val));
        let _ = Attribute::from(KeyUsage::CrlSign(val));
        let _ = Attribute::from(KeyUsage::ContentCommitment(val));
        let _ = Attribute::from(KeyUsage::KeyEncipherment(val));
        let _ = Attribute::from(KeyUsage::DataEncipherment(val));
        let _ = Attribute::from(KeyUsage::KeyAgreement(val));
        let _ = Attribute::from(KeyUsage::KeyCertSign(val));
        let _ = Attribute::from(KeyUsage::EncipherOnly(val));
        let _ = Attribute::from(KeyUsage::DecipherOnly(val));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_key_usage_to_attribute_true() {
        test_key_usage_to_attribute(true);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_key_usage_to_attribute_false() {
        test_key_usage_to_attribute(false);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_basic_constraints_to_object_identifier() {
        let bc = BasicConstraints {
            ca: true,
            path_length: None,
        };
        let _ = ObjectIdentifier::from(bc);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_basic_constraints_to_attribute() {
        let mut bc = BasicConstraints {
            ca: false,
            path_length: None,
        };
        let _ = Attribute::from(bc);

        bc.ca = true;
        let _ = Attribute::from(bc);

        bc.path_length = Some(0);
        let _ = Attribute::from(bc);

        // Why not test all sorts of values? :3
        let mut county_count = 2u64;
        while county_count != u64::MAX {
            bc.path_length = Some(county_count);
            let _ = Attribute::from(bc);
            if let Some(res) = county_count.checked_mul(2) {
                county_count = res;
            } else {
                county_count = u64::MAX;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test_key_usage_from_attribute {
    use std::str::FromStr;

    use der::{Any, Tag};
    use spki::ObjectIdentifier;

    use super::*;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_key_usage_from_attribute() {
        let key_usage = KeyUsage::ContentCommitment(true);
        let attribute = Attribute::from(key_usage);
        let result = KeyUsage::try_from(attribute);
        dbg!(&result);
        assert!(result.is_ok());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_key_usage_wrong_value_amount() {
        let key_usage = KeyUsage::ContentCommitment(true);
        let mut attribute = Attribute::from(key_usage);
        attribute
            .values
            .insert(Any::from(KeyUsage::DataEncipherment(false)))
            .unwrap();
        let result = KeyUsage::try_from(attribute);
        dbg!(&result);
        assert!(result.is_err());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_key_usage_tag_mismatch() {
        let mut sov = SetOfVec::new();
        sov.insert(Any::new(Tag::Integer, vec![0x00]).unwrap())
            .unwrap();
        let attribute = Attribute {
            oid: ObjectIdentifier::from_str(OID_KEY_USAGE_CONTENT_COMMITMENT).unwrap(),
            values: sov,
        };
        let result = KeyUsage::try_from(attribute);
        dbg!(&result);
        assert!(result.is_err());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_key_usage_wrong_oid() {
        let mut sov = SetOfVec::new();
        sov.insert(Any::new(Tag::Boolean, vec![0x00]).unwrap())
            .unwrap();
        let attribute = Attribute {
            oid: ObjectIdentifier::from_str("1.2.4.2.1.1.1.1.1.1.1.1.1.1.161.69").unwrap(),
            values: sov,
        };
        let result = KeyUsage::try_from(attribute);
        dbg!(&result);
        assert!(result.is_err());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_key_usage_from_attribute_weird_bool_value() {
        let mut sov = SetOfVec::new();
        sov.insert(Any::new(Tag::Boolean, vec![0x02]).unwrap())
            .unwrap();
        let attribute = Attribute {
            oid: ObjectIdentifier::from_str(OID_KEY_USAGE_CONTENT_COMMITMENT).unwrap(),
            values: sov,
        };
        let result = KeyUsage::try_from(attribute);
        dbg!(&result);
        assert!(result.is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test_basic_constraints_from_attribute {
    use std::str::FromStr;

    use der::asn1::Ia5String;
    use der::{Any, Tag};
    use spki::ObjectIdentifier;

    use super::*;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_basic_constraints_from_attribute() {
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(0),
        };
        let attribute = Attribute::from(bc);
        let result = BasicConstraints::try_from(attribute);
        dbg!(&result);
        assert!(result.is_ok());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_basic_constraints_wrong_value_amount() {
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(0),
        };
        let mut attribute = Attribute::from(bc);
        attribute
            .values
            .insert(Any::from(KeyUsage::DataEncipherment(false)))
            .unwrap();
        let result = BasicConstraints::try_from(attribute);
        dbg!(&result);
        assert!(result.is_err());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_basic_constraints_wrong_value_type() {
        let mut sov = SetOfVec::new();
        sov.insert(Any::new(Tag::Ia5String, Ia5String::new("hello").unwrap().as_bytes()).unwrap())
            .unwrap();
        let attribute = Attribute {
            oid: ObjectIdentifier::from_str(OID_BASIC_CONSTRAINTS).unwrap(),
            values: sov,
        };
        let result = BasicConstraints::try_from(attribute);
        dbg!(&result);
        assert!(result.is_err());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_basic_constraints_wrong_oid() {
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(0),
        };
        let mut attribute = Attribute::from(bc);
        attribute.oid = ObjectIdentifier::from_str("0.0.161.80085").unwrap();
        let result = BasicConstraints::try_from(attribute);
        dbg!(&result);
        assert!(result.is_err());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_basic_constraints_from_attribute_too_many_bools_or_ints() {
        let mut sov = SetOfVec::new();
        sov.insert(Any::new(Tag::Boolean, vec![0x00]).unwrap())
            .unwrap();
        sov.insert(Any::new(Tag::Boolean, vec![0x01]).unwrap())
            .unwrap();
        let attribute = Attribute {
            oid: ObjectIdentifier::from_str(OID_BASIC_CONSTRAINTS).unwrap(),
            values: sov,
        };
        let result = BasicConstraints::try_from(attribute);
        dbg!(&result);
        assert!(result.is_err());

        let mut sov = SetOfVec::new();
        sov.insert(Any::new(Tag::Integer, vec![0x00]).unwrap())
            .unwrap();
        sov.insert(Any::new(Tag::Integer, vec![0x01]).unwrap())
            .unwrap();
        let attribute = Attribute {
            oid: ObjectIdentifier::from_str(OID_BASIC_CONSTRAINTS).unwrap(),
            values: sov,
        };
        let result = BasicConstraints::try_from(attribute);
        dbg!(&result);
        assert!(result.is_err());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_basic_constraints_from_attribute_weird_bool_value() {
        let mut sov = SetOfVec::new();
        sov.insert(Any::new(Tag::Boolean, vec![0x02]).unwrap())
            .unwrap();
        let attribute = Attribute {
            oid: ObjectIdentifier::from_str(OID_BASIC_CONSTRAINTS).unwrap(),
            values: sov,
        };
        let result = BasicConstraints::try_from(attribute);
        dbg!(&result);
        assert!(result.is_err());
    }
}
