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
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::ext::{Extension, Extensions};

use crate::errors::base::InvalidInput;
use crate::errors::composite::ConversionError;
use crate::Constrained;

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
/// Object Identifier for the KeyUsage flag.
pub const OID_KEY_USAGE: &str = "2.5.29.15";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
/// An abstraction over X.509 Extensions and PKCS#10 Attributes, representing the capabilities
/// of a certificate. Capabilities can be converted from and to both [Attributes] and [Extensions].
///
/// This struct only covers the Attributes/Extensions currently relevant to polyproto.
pub struct Capabilities {
    /// The key usage extension defines the purpose of the key contained in the certificate.
    pub key_usage: KeyUsages,
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
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    /// Sane default for actor [IdCsr]/[IdCert] [Capabilities]. Uses the DigitalSignature flag,
    /// not the ContentCommitment flag.
    pub fn default_actor() -> Self {
        let key_usage = KeyUsages::new(&[KeyUsage::DigitalSignature]);
        let basic_constraints = BasicConstraints {
            ca: false,
            path_length: None,
        };
        Self {
            key_usage,
            basic_constraints,
        }
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    /// Sane default for home server [IdCsr]/[IdCert] [Capabilities].
    pub fn default_home_server() -> Self {
        let key_usage = KeyUsages::new(&[KeyUsage::KeyCertSign]);
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
    type Error = ConversionError;

    /// Performs the conversion.
    ///
    /// Fails if the [BasicConstraints] or [KeyUsage]s are malformed. The constraints returned by
    /// this method are not guaranteed to be valid. You should call `validate()` on the result
    /// to ensure that the constraints are valid according to the X.509 standard and the polyproto
    /// specification.
    fn try_from(value: Attributes) -> Result<Self, Self::Error> {
        let mut key_usages = KeyUsages::new(&[]);
        let mut basic_constraints = BasicConstraints::default();
        let mut num_basic_constraints = 0u8;
        for item in value.iter() {
            match item.oid.to_string().as_str() {
                #[allow(unreachable_patterns)] // cargo thinks the below pattern is unreachable.
                OID_KEY_USAGE => {
                    key_usages = KeyUsages::try_from(item.clone())?;
                }
                OID_BASIC_CONSTRAINTS => {
                    num_basic_constraints += 1;
                    if num_basic_constraints > 1 {
                        return Err(ConversionError::InvalidInput(InvalidInput::Malformed("Tried inserting > 1 BasicConstraints into Capabilities. Expected 1 BasicConstraints".to_string())));
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
    type Error = ConversionError;

    /// Performs the conversion.
    ///
    /// Fails, if `Capabilities::verify()` using the `Constrained` trait fails.
    fn try_from(value: Capabilities) -> Result<Self, Self::Error> {
        value.validate()?;
        let mut sov = SetOfVec::new();
        let insertion = sov.insert(Attribute::try_from(value.key_usage)?);
        if insertion.is_err() {
            return Err(ConversionError::InvalidInput(InvalidInput::Malformed("Tried inserting non-unique element into SetOfVec. You likely have a duplicate value in your Capabilities".to_string())));
        }
        let insertion = sov.insert(Attribute::try_from(value.basic_constraints)?);
        if insertion.is_err() {
            return Err(ConversionError::InvalidInput(InvalidInput::Malformed("Tried inserting non-unique element into SetOfVec. You likely have a duplicate value in your Capabilities".to_string())));
        }
        Ok(sov)
    }
}

impl TryFrom<Capabilities> for Extensions {
    type Error = ConversionError;
    /// Performs the conversion.
    ///
    /// try_from does **not** check whether the resulting [Extensions] are well-formed.
    fn try_from(value: Capabilities) -> Result<Self, Self::Error> {
        Ok(vec![
            Extension::try_from(value.basic_constraints)?,
            Extension::try_from(value.key_usage)?,
        ])
    }
}

impl TryFrom<Extensions> for Capabilities {
    type Error = ConversionError;

    /// Performs the conversion.
    ///
    /// try_from does **not** check whether the resulting [Capabilities] are well-formed. If
    /// this property is critical, use the [Constrained] trait to verify the well-formedness of
    /// these resulting [Capabilities].
    fn try_from(value: Extensions) -> Result<Self, Self::Error> {
        let mut basic_constraints: BasicConstraints = BasicConstraints::default();
        let mut key_usage: KeyUsages = KeyUsages::default();
        for item in value.iter() {
            #[allow(unreachable_patterns)] // cargo thinks that we have an unreachable pattern here
            match item.extn_id.to_string().as_str() {
                OID_BASIC_CONSTRAINTS => {
                    basic_constraints = BasicConstraints::try_from(item.clone())?
                }
                OID_KEY_USAGE => {
                    key_usage = KeyUsages::try_from(item.clone())?
                },
                _ => return Err(ConversionError::InvalidInput(InvalidInput::Malformed(format!("Invalid OID found for converting this set of Extensions to Capabilities: {} is not a valid OID for BasicConstraints or KeyUsages", item.extn_id))))
            };
        }
        Ok(Capabilities {
            key_usage,
            basic_constraints,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod test {
    use spki::ObjectIdentifier;

    use super::*;

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
        let _ = Attribute::try_from(bc).unwrap();

        bc.ca = true;
        let _ = Attribute::try_from(bc).unwrap();

        bc.path_length = Some(0);
        let _ = Attribute::try_from(bc).unwrap();

        // Why not test all sorts of values? :3
        let mut county_count = 2u64;
        while county_count != u64::MAX {
            bc.path_length = Some(county_count);
            let _ = Attribute::try_from(bc).unwrap();
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
    fn test_key_usage_tag_mismatch() {
        let mut sov = SetOfVec::new();
        sov.insert(Any::new(Tag::Integer, vec![0x00]).unwrap())
            .unwrap();
        let attribute = Attribute {
            oid: ObjectIdentifier::from_str(OID_KEY_USAGE_CONTENT_COMMITMENT).unwrap(),
            values: sov,
        };
        let result = KeyUsages::try_from(attribute);
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
        let result = KeyUsages::try_from(attribute);
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
        let result = KeyUsages::try_from(attribute);
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
        let attribute = Attribute::try_from(bc).unwrap();
        let result = BasicConstraints::try_from(attribute);
        assert!(result.is_ok());
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
        assert!(result.is_err());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_basic_constraints_wrong_oid() {
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(0),
        };
        let mut attribute = Attribute::try_from(bc).unwrap();
        attribute.oid = ObjectIdentifier::from_str("0.0.161.80085").unwrap();
        let result = BasicConstraints::try_from(attribute);
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
        assert!(result.is_err());
    }
}
