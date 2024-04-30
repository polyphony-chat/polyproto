// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*!

# polyproto

(Generic) Rust types and traits to quickly get a
[polyproto](https://docs.polyphony.chat/Protocol%20Specifications/core/) implementation up and
running.

## Implementing polyproto

**The crate is currently in very early (alpha) development. A lot of functionality is missing, and
things may break or change at any point in time.**

This crate extends upon types offered by [der](https://crates.io/crates/der) and
[spki](https://crates.io/crates/spki). As such, these crates are required dependencies for
projects looking to implement polyproto.

Start by implementing the trait [crate::signature::Signature] for a signature algorithm of your
choice. Popular crates for cryptography and signature algorithms supply their own `PublicKey` and
`PrivateKey` types. You should extend upon these types with your own structs and implement the
[crate::key] traits for these new structs.

You can then use the [crate::certs] types to build certificates using your implementations of the
aforementioned traits.

## Cryptography

This crate provides no cryptographic functionality whatsoever; its sole purpose is to aid in
implementing polyproto by transforming the
[polyproto specification](https://docs.polyphony.chat/Protocol%20Specifications/core/) into
well-defined yet adaptable Rust types.

## WebAssembly

This crate is designed to work with the `wasm32-unknown-unknown` target. To compile for `wasm`, you
will have to use the `wasm` feature:

```toml
[dependencies]
polyproto = { version = "0", features = ["wasm"] }
```
*/

pub const OID_RDN_DOMAIN_COMPONENT: &str = "0.9.2342.19200300.100.1.25";
pub const OID_RDN_COMMON_NAME: &str = "2.5.4.3";
pub const OID_RDN_UNIQUE_IDENTIFIER: &str = "0.9.2342.19200300.100.1.44";
pub const OID_RDN_UID: &str = "0.9.2342.19200300.100.1.1";

use errors::base::ConstraintError;
#[cfg(feature = "wasm_bindgen")]
use wasm_bindgen::prelude::*;
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[cfg(feature = "reqwest")]
/// Ready-to-use API routes, implemented using `reqwest`
pub mod api;
/// Generic polyproto certificate types and traits.
pub mod certs;
/// Error types used in this crate
pub mod errors;
/// Generic polyproto public- and private key traits.
pub mod key;
/// Generic polyproto signature traits.
pub mod signature;
#[cfg(feature = "routes")]
/// Types used in polyproto and the polyproto HTTP/REST APIs
pub mod types;

pub(crate) mod constraints;

pub use der;
pub use spki;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
/// Traits implementing [Constrained] can be validated to be well-formed. This does not guarantee
/// that a validated type will always be *correct* in the context it is in.
///
/// ### Example
///
/// The password "123" might be well-formed, as in, it meets the validation criteria specified by
/// the system. However, this makes no implications about "123" being the correct password for a
/// given user account.
pub trait Constrained {
    fn validate(&self) -> Result<(), ConstraintError>;
}

#[cfg(test)]
mod test {
    use der::asn1::Uint;
    use x509_cert::certificate::Profile;
    use x509_cert::serial_number::SerialNumber;

    #[derive(Clone, PartialEq, Eq, Debug)]
    enum TestProfile {}

    impl Profile for TestProfile {}

    fn strip_leading_zeroes(bytes: &[u8]) -> &[u8] {
        if let Some(stripped) = bytes.strip_prefix(&[0u8]) {
            stripped
        } else {
            bytes
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_convert_serial_number() {
        let biguint = Uint::new(&[10u8, 240u8]).unwrap();
        assert_eq!(biguint.as_bytes(), &[10u8, 240u8]);
        let serial_number: SerialNumber<TestProfile> =
            SerialNumber::new(biguint.as_bytes()).unwrap();
        assert_eq!(
            strip_leading_zeroes(serial_number.as_bytes()),
            biguint.as_bytes()
        );

        let biguint = Uint::new(&[240u8, 10u8]).unwrap();
        assert_eq!(biguint.as_bytes(), &[240u8, 10u8]);
        let serial_number: SerialNumber<TestProfile> =
            SerialNumber::new(biguint.as_bytes()).unwrap();
        assert_eq!(
            strip_leading_zeroes(serial_number.as_bytes()),
            biguint.as_bytes()
        );
    }
}
