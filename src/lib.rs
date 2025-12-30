#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod authenticator;
pub mod erasure;
pub mod kdf;
pub mod states;
pub mod wrapped_inc_mlkem768;

pub const PROTOCOL_INFO: &str = "SPQR_RUST_MLKEM768_SHA-256";

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
