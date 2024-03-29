// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::Length;
use x509_cert::name::Name;

use crate::certs::capabilities::{Capabilities, KeyUsage};
use crate::certs::idcsr::IdCsr;
use crate::certs::SessionId;
use crate::signature::Signature;
use crate::Constrained;

impl Constrained for Name {
    /// [Name] must meet the following criteria to be valid in the context of polyproto:
    /// - Distinguished name MUST have "common name" attribute, which is equal to the actor or
    ///   home server name of the subject in question. Only one "common name" is allowed.
    /// - MUST have AT LEAST one domain component, specifying the home server domain for this
    ///   entity.
    /// - If actor name, MUST include UID (OID 0.9.2342.19200300.100.1.1) and uniqueIdentifier
    ///   (OID 0.9.2342.19200300.100.1.44).
    ///     - UID is the federation ID of the actor.
    ///     - uniqueIdentifier is the [SessionId] of the actor.
    /// - MAY have "organizational unit" attributes
    /// - MAY have other attributes, which might be ignored by other home servers and other clients.
    fn validate(&self) -> Result<(), crate::ConstraintError> {
        // this code sucks. i couldn't think of a way to make it better though. sorry!
        let mut num_cn: u8 = 0;
        let mut num_dc: u8 = 0;
        let mut num_uid: u8 = 0;
        let mut num_unique_identifier: u8 = 0;

        let rdns = &self.0;
        for rdn in rdns.iter() {
            for item in rdn.0.iter() {
                match item.oid.to_string().as_str() {
                    "0.9.2342.19200300.100.1.1" => num_uid += 1,
                    "0.9.2342.19200300.100.1.44" => {
                        num_unique_identifier += 1;
                        if let Ok(value) = item.value.decode_as::<String>() {
                            SessionId::new_validated(value)?;
                        } else {
                            return Err(crate::ConstraintError::Malformed(Some(
                                "Tried to decode SessionID as String and failed".to_string(),
                            )));
                        }
                    }
                    "2.5.4.3" => {
                        num_cn += 1;
                        if num_cn > 1 {
                            return Err(crate::ConstraintError::OutOfBounds {
                                lower: 1,
                                upper: 1,
                                actual: num_cn.to_string(),
                                reason: Some("Distinguished Names must include exactly one common name attribute.".to_string())
                            });
                        }
                    }
                    "0.9.2342.19200300.100.1.25" => num_dc += 1,
                    _ => {}
                }
            }
        }
        if num_dc == 0 {
            return Err(crate::ConstraintError::OutOfBounds {
                lower: 1,
                upper: u8::MAX as i32,
                actual: "0".to_string(),
                reason: Some("Domain Component is missing".to_string()),
            });
        }
        if num_uid > 1 {
            return Err(crate::ConstraintError::OutOfBounds {
                lower: 0,
                upper: 1,
                actual: num_uid.to_string(),
                reason: Some("Too many UID components supplied".to_string()),
            });
        }
        if num_unique_identifier > 1 {
            return Err(crate::ConstraintError::OutOfBounds {
                lower: 0,
                upper: 1,
                actual: num_unique_identifier.to_string(),
                reason: Some("Too many uniqueIdentifier components supplied".to_string()),
            });
        }
        if num_unique_identifier > 0 && num_uid == 0 {
            return Err(crate::ConstraintError::OutOfBounds {
                lower: 1,
                upper: 1,
                actual: num_uid.to_string(),
                reason: Some(
                    "Actors must have uniqueIdentifier AND UID, only uniqueIdentifier found"
                        .to_string(),
                ),
            });
        }
        if num_uid > 0 && num_unique_identifier == 0 {
            return Err(crate::ConstraintError::OutOfBounds {
                lower: 1,
                upper: 1,
                actual: num_unique_identifier.to_string(),
                reason: Some(
                    "Actors must have uniqueIdentifier AND UID, only UID found".to_string(),
                ),
            });
        }
        Ok(())
    }
}

impl Constrained for SessionId {
    /// [SessionId] must be longer than 0 and not longer than 32 characters to be deemed valid.
    fn validate(&self) -> Result<(), crate::ConstraintError> {
        if self.len() > Length::new(32) || self.len() == Length::ZERO {
            return Err(crate::ConstraintError::OutOfBounds {
                lower: 1,
                upper: 32,
                actual: self.len().to_string(),
                reason: Some("SessionId too long".to_string()),
            });
        }
        Ok(())
    }
}

impl Constrained for Capabilities {
    fn validate(&self) -> Result<(), crate::ConstraintError> {
        let is_ca = self.basic_constraints.ca;

        // Define the flags to check
        let mut can_commit_content = false;
        let mut can_sign = false;
        let mut key_cert_sign = false;
        let mut has_only_encipher = false;
        let mut has_only_decipher = false;
        let mut has_key_agreement = false;

        // Iterate over all the entries in the KeyUsage vector, check if they exist/are true
        for item in self.key_usage.iter() {
            if !has_only_encipher && item == &KeyUsage::EncipherOnly(true) {
                has_only_encipher = true;
            }
            if !has_only_decipher && item == &KeyUsage::DecipherOnly(true) {
                has_only_decipher = true;
            }
            if !has_key_agreement && item == &KeyUsage::KeyAgreement(true) {
                has_key_agreement = true;
            }
            if !has_key_agreement && item == &KeyUsage::ContentCommitment(true) {
                can_commit_content = true;
            }
            if !has_key_agreement && item == &KeyUsage::DigitalSignature(true) {
                can_sign = true;
            }
            if !has_key_agreement && item == &KeyUsage::KeyCertSign(true) {
                key_cert_sign = true;
            }
        }

        // Non-CAs must be able to sign their messages. Whether with or without non-repudiation
        // does not matter.
        if !is_ca && !can_sign && !can_commit_content {
            return Err(crate::ConstraintError::Malformed(Some(
                "Actors require signing capabilities, none found".to_string(),
            )));
        }

        // Certificates cannot be both non-repudiating and repudiating
        if can_sign && can_commit_content {
            return Err(crate::ConstraintError::Malformed(Some(
                "Cannot have both signing and non-repudiation signing capabilities".to_string(),
            )));
        }

        // If these Capabilities are for a CA, it also must have the KeyCertSign Capability set to
        // true. Also, non-CAs are not allowed to have the KeyCertSign flag set to true.
        if is_ca || key_cert_sign {
            if !is_ca {
                return Err(crate::ConstraintError::Malformed(Some(
                    "If KeyCertSign capability is wanted, CA flag must be true".to_string(),
                )));
            }
            if !key_cert_sign {
                return Err(crate::ConstraintError::Malformed(Some(
                    "CA must have KeyCertSign capability".to_string(),
                )));
            }
        }

        // has_key_agreement needs to be true if has_only_encipher or _decipher are true.
        // See: <https://cryptography.io/en/latest/x509/reference/#cryptography.x509.KeyUsage.encipher_only>
        // See: <https://cryptography.io/en/latest/x509/reference/#cryptography.x509.KeyUsage.decipher_only>
        if (has_only_encipher || has_only_decipher) && !has_key_agreement {
            Err(crate::ConstraintError::Malformed(Some(
                "KeyAgreement capability needs to be true to use OnlyEncipher or OnlyDecipher"
                    .to_string(),
            )))
        } else {
            Ok(())
        }
    }
}

impl<S: Signature> Constrained for IdCsr<S> {
    fn validate(&self) -> Result<(), crate::ConstraintError> {
        self.inner_csr.capabilities.validate()?;
        self.inner_csr.subject.validate()?;
        Ok(())
    }
}

#[cfg(test)]
mod name_constraints {
    use std::str::FromStr;

    use x509_cert::name::Name;

    use crate::Constrained;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn correct() {
        let name = Name::from_str(
            "cn=flori,dc=localhost,uid=flori@localhost,uniqueIdentifier=h3g2jt4dhfgj8hjs",
        )
        .unwrap();
        name.validate().unwrap();
        let name = Name::from_str("CN=flori,DC=www,DC=polyphony,DC=chat").unwrap();
        name.validate().unwrap();
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn no_domain_component() {
        let name = Name::from_str("CN=flori").unwrap();
        assert!(name.validate().is_err());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn two_cns() {
        let name = Name::from_str("CN=flori,CN=xenia,DC=localhost").unwrap();
        assert!(name.validate().is_err())
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn two_uid_or_uniqueid() {
        let name = Name::from_str("CN=flori,CN=xenia,uid=numbaone,uid=numbatwo").unwrap();
        assert!(name.validate().is_err());
        let name =
            Name::from_str("CN=flori,CN=xenia,uniqueIdentifier=numbaone,uniqueIdentifier=numbatwo")
                .unwrap();
        assert!(name.validate().is_err())
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn uid_and_no_uniqueid_or_uniqueid_and_no_uid() {
        let name = Name::from_str("CN=flori,CN=xenia,uid=numbaone").unwrap();
        assert!(name.validate().is_err());
        let name = Name::from_str("CN=flori,CN=xenia,uniqueIdentifier=numbaone").unwrap();
        assert!(name.validate().is_err())
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn malformed_session_id_failes() {
        let name =
            Name::from_str("cn=flori,dc=localhost,uid=flori@localhost,uniqueIdentifier=").unwrap();
        assert!(name.validate().is_err());
        let name =
            Name::from_str("cn=flori,dc=localhost,uid=flori@localhost,uniqueIdentifier=123456789012345678901234567890123").unwrap();
        assert!(name.validate().is_err());
    }
}

#[cfg(test)]
mod session_id_constraints {

    use crate::certs::SessionId;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn zero_long_session_id_fails() {
        assert!(SessionId::new_validated(String::from("")).is_err())
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn thirtytwo_length_session_id_is_ok() {
        assert!(SessionId::new_validated(String::from("11111111111111111111111111222222")).is_ok())
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn thirtythree_length_session_id_fails() {
        assert!(
            SessionId::new_validated(String::from("111111111111111111111111112222223")).is_err()
        )
    }
}
