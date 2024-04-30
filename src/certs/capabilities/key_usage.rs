// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::str::FromStr;

use der::asn1::{BitString, OctetString, SetOfVec};
use der::{Any, Decode, Encode, Tag, Tagged};
use spki::ObjectIdentifier;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
use x509_cert::attr::Attribute;
use x509_cert::ext::Extension;

use crate::errors::base::InvalidInput;
use crate::errors::composite::ConversionError;

use super::*;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// The key usage extension defines the purpose of the key contained in the certificate. The usage
/// restriction might be employed when a key that could be used for more than one operation is to
/// be restricted. See <https://cryptography.io/en/latest/x509/reference/#cryptography.x509.KeyUsage>
pub enum KeyUsage {
    /// This purpose is set when the subject public key is used for verifying digital
    /// signatures, other than signatures on certificates (`key_cert_sign`) and CRLs (`crl_sign`).
    DigitalSignature,
    /// This purpose is set when the subject public key is used for verifying digital
    /// signatures, other than signatures on certificates (`key_cert_sign`) and CRLs (`crl_sign`).
    /// It is used to provide a non-repudiation service that protects against the signing entity
    /// falsely denying some action. In the case of later conflict, a reliable third party may
    /// determine the authenticity of the signed data. This was called `non_repudiation` in older
    /// revisions of the X.509 specification.
    ContentCommitment,
    /// This purpose is set when the subject public key is used for enciphering private or
    /// secret keys.
    KeyEncipherment,
    /// This purpose is set when the subject public key is used for directly enciphering raw
    /// user data without the use of an intermediate symmetric cipher.
    DataEncipherment,
    /// This purpose is set when the subject public key is used for key agreement. For
    /// example, when a Diffie-Hellman key is to be used for key management, then this purpose is
    /// set.
    KeyAgreement,
    /// This purpose is set when the subject public key is used for verifying signatures on
    /// public key certificates. If this purpose is set to true then ca must be true in the
    /// `BasicConstraints` extension.
    KeyCertSign,
    /// This purpose is set when the subject public key is used for verifying signatures on
    /// certificate revocation lists.
    CrlSign,
    /// When this purpose is set and the `key_agreement` purpose is also set, the subject
    /// public key may be used only for enciphering data while performing key agreement. The
    /// `KeyAgreement` capability must be set for this.
    EncipherOnly,
    /// When this purpose is set and the `key_agreement` purpose is also set, the subject
    /// public key may be used only for deciphering data while performing key agreement. The
    /// `KeyAgreement` capability must be set for this.
    DecipherOnly,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
/// The KeyUsages struct is a collection of KeyUsage variants.
pub struct KeyUsages {
    /// Vector of KeyUsage variants.
    pub key_usages: Vec<KeyUsage>,
}

impl KeyUsages {
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    /// Creates a new KeyUsages struct from a slice of KeyUsage variants.
    pub fn new(key_usages: &[KeyUsage]) -> Self {
        KeyUsages {
            key_usages: key_usages.to_vec(),
        }
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    /// Converts a byte slice to a KeyUsages struct, given that the byte slice is a bitstring
    /// representing the KeyUsages.
    ///
    /// RFC 5280 says:
    /// ```text
    /// KeyUsage ::= BIT STRING {
    ///     digitalSignature        (0),
    ///     nonRepudiation          (1), -- recent editions of X.509 have
    ///                                  -- renamed this bit to contentCommitment
    ///     keyEncipherment         (2),
    ///     dataEncipherment        (3),
    ///     keyAgreement            (4),
    ///     keyCertSign             (5),
    ///     cRLSign                 (6),
    ///     encipherOnly            (7),
    ///     decipherOnly            (8) }
    /// ```
    pub fn from_bitstring(bitstring: BitString) -> Result<Self, ConversionError> {
        let mut byte_array = bitstring.raw_bytes().to_vec();
        if byte_array.is_empty() || byte_array.len() < 2 {
            return Err(ConversionError::InvalidInput(InvalidInput::Malformed(
                "Passed BitString seems to be invalid".to_string(),
            )));
        }
        byte_array.remove(0);
        let mut key_usages = Vec::new();
        if byte_array.len() == 2 {
            // If the length of the byte array is 2, this means that DecipherOnly is set.
            key_usages.push(KeyUsage::DecipherOnly);
            byte_array.remove(0);
        }
        let mut current_try = 128u8;
        loop {
            // If the first byte is bigger than or equal to the current_try, this means that the
            // KeyUsage belonging to the current_try is set. We can then divide the current_try by 2
            // and continue checking if the KeyUsage belonging to the current_try is set, until we
            // reach current_try == 1.
            if current_try <= byte_array[0] {
                byte_array[0] -= current_try;
                key_usages.push(match current_try {
                    128 => KeyUsage::DigitalSignature,
                    64 => KeyUsage::ContentCommitment,
                    32 => KeyUsage::KeyEncipherment,
                    16 => KeyUsage::DataEncipherment,
                    8 => KeyUsage::KeyAgreement,
                    4 => KeyUsage::KeyCertSign,
                    2 => KeyUsage::CrlSign,
                    1 => KeyUsage::EncipherOnly,
                    // This should never happen, as we are only dividing by 2 until we reach 1.
                    _ => panic!("This should never happen. Please report this error to https://github.com/polyphony-chat/polyproto"),
                })
            }
            if current_try == 1 {
                break;
            }
            current_try /= 2;
        }
        if byte_array[0] != 0 {
            return Err(ConversionError::InvalidInput(InvalidInput::Malformed(
                "Could not properly convert this BitString to KeyUsages. The BitString is malformed".to_string(),
            )));
        }
        Ok(KeyUsages { key_usages })
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    /// Converts the KeyUsages to a [BitString].
    pub fn to_bitstring(self) -> BitString {
        let mut vec = self.key_usages;
        vec.sort();
        vec.dedup();
        let mut encoded_numbers = [0u8; 2];
        let mut unused_bits: u8 = 0;
        /*
        If DecipherOnly is supposed to be set, we need to store this information as a separate
        byte. All other KeyUsages can be stored in the first byte.

        Normally, DigitalSignature would equal 1, ContentCommitment would equal 2, KeyEncipherment
        would equal 4, and so on. However, because of the way DER BitStrings are encoded, we need
        to reverse the order of the bits. This means that DigitalSignature has a value of 128, and
        DecipherOnly has a value of 1.

        We are adding these values to the u8 stored in the second byte of the encoded_numbers array.
         */
        for keyusage in vec.iter() {
            match *keyusage {
                KeyUsage::DigitalSignature => encoded_numbers[1] += 128,
                KeyUsage::ContentCommitment => encoded_numbers[1] += 64,
                KeyUsage::KeyEncipherment => encoded_numbers[1] += 32,
                KeyUsage::DataEncipherment => encoded_numbers[1] += 16,
                KeyUsage::KeyAgreement => encoded_numbers[1] += 8,
                KeyUsage::KeyCertSign => encoded_numbers[1] += 4,
                KeyUsage::CrlSign => encoded_numbers[1] += 2,
                KeyUsage::EncipherOnly => encoded_numbers[1] += 1,
                KeyUsage::DecipherOnly => encoded_numbers[0] += 128,
            }
        }
        let mut encoded_numbers_vec = encoded_numbers.to_vec();
        if encoded_numbers[0] == 0 {
            encoded_numbers_vec.remove(0);
            // {:08b} means that we want to format the number as a binary string with 8 bits.
            let binary = format!("{:08b}", encoded_numbers[1].to_be());
            for bit in binary.chars() {
                // If the bit is 0, increment the unused_bits counter.
                if bit == '0' {
                    unused_bits += 1;
                } else {
                    break;
                }
            }
        } else {
            // If encoded_numbers[0] is not 0, this means that DecipherOnly is set. Since only
            // DecipherOnly can be set in the first byte, we know that there have to be 7 unused
            // bits.
            unused_bits = 7;
        }
        BitString::new(unused_bits, encoded_numbers_vec)
            .expect("Error when converting KeyUsages to BitString. Please report this error to https://github.com/polyphony-chat/polyproto")
    }
}

impl From<KeyUsages> for BitString {
    fn from(value: KeyUsages) -> Self {
        value.to_bitstring()
    }
}

impl TryFrom<Attribute> for KeyUsages {
    type Error = ConversionError;

    fn try_from(value: Attribute) -> Result<Self, Self::Error> {
        if value.tag() != Tag::BitString {
            return Err(ConversionError::InvalidInput(InvalidInput::Malformed(
                format!("Expected BitString, found {}", value.tag(),),
            )));
        }
        match value.values.len() {
            0 => return Ok(KeyUsages::new(&[])),
            1 => (),
            _ => {
                return Err(ConversionError::InvalidInput(InvalidInput::Length {
                    min_length: 0,
                    max_length: 1,
                    actual_length: value.values.len().to_string(),
                }));
            }
        };
        let inner_value = value.values.get(0).expect("Illegal state. Please report this error to https://github.com/polyphony-chat/polyproto");
        KeyUsages::from_bitstring(BitString::from_der(inner_value.value())?)
    }
}

impl TryFrom<Extension> for KeyUsages {
    type Error = ConversionError;

    fn try_from(value: Extension) -> Result<Self, Self::Error> {
        if value.extn_id.to_string().as_str() != OID_KEY_USAGE {
            return Err(ConversionError::InvalidInput(InvalidInput::Malformed(
                format!(
                    "Expected OID {} for KeyUsages, found OID {}",
                    OID_KEY_USAGE, value.extn_id
                ),
            )));
        }
        let any = Any::from_der(value.extn_value.as_bytes())?;
        KeyUsages::from_bitstring(BitString::from_bytes(any.value())?)
    }
}

impl TryFrom<KeyUsages> for Attribute {
    type Error = ConversionError;

    fn try_from(value: KeyUsages) -> Result<Self, Self::Error> {
        let mut sov = SetOfVec::new();
        let bitstring = value.to_bitstring();
        sov.insert(Any::from_der(&bitstring.to_der()?)?)?;
        Ok(Attribute {
            oid: ObjectIdentifier::from_str(OID_KEY_USAGE)?,
            values: sov,
        })
    }
}

impl TryFrom<KeyUsages> for Extension {
    type Error = ConversionError;
    fn try_from(value: KeyUsages) -> Result<Self, Self::Error> {
        let bitstring = value.to_bitstring();
        let any = Any::from_der(&bitstring.to_der()?)?;
        Ok(Extension {
            extn_id: ObjectIdentifier::from_str(OID_KEY_USAGE)?,
            critical: true,
            extn_value: OctetString::new(any.to_der()?)?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod test {
    use super::*;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn key_usages_to_bitstring() {
        let key_usages = KeyUsages::new(&[
            KeyUsage::CrlSign,
            KeyUsage::EncipherOnly,
            KeyUsage::KeyAgreement,
        ]);
        let _bitstring = BitString::from(key_usages);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn key_usages_vec_sorts_correctly() {
        #[allow(clippy::useless_vec)]
        let mut vec = vec![
            KeyUsage::ContentCommitment,
            KeyUsage::EncipherOnly,
            KeyUsage::DataEncipherment,
            KeyUsage::DigitalSignature,
        ];
        vec.sort();
        assert!(*vec.first().unwrap() == KeyUsage::DigitalSignature);
        assert!(*vec.get(1).unwrap() == KeyUsage::ContentCommitment);
        assert!(*vec.get(2).unwrap() == KeyUsage::DataEncipherment);
        assert!(*vec.get(3).unwrap() == KeyUsage::EncipherOnly);
    }
}
