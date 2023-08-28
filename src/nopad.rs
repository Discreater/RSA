//! No padding

use alloc::vec::Vec;
use num_bigint::BigUint;
use rand_core::{RngCore, CryptoRng};
use zeroize::Zeroizing;

use crate::{traits::{PaddingScheme, PublicKeyParts}, key, algorithms::{pad::uint_to_be_pad, rsa::rsa_encrypt}};

/// padding zero into front of the message.
pub struct ZeroPadEncrypt;

impl PaddingScheme for ZeroPadEncrypt {
    fn decrypt<Rng: rand_core::CryptoRngCore>(
        self,
        _rng: Option<&mut Rng>,
        _priv_key: &crate::RsaPrivateKey,
        _ciphertext: &[u8],
    ) -> crate::Result<Vec<u8>> {
        unimplemented!()
    }

    fn encrypt<Rng: rand_core::CryptoRngCore>(
        self,
        _rng: &mut Rng,
        pub_key: &crate::RsaPublicKey,
        msg: &[u8],
    ) -> crate::Result<Vec<u8>> {
        let k = pub_key.size();
        key::check_public(pub_key)?;
        
        let mut em = Zeroizing::new(vec![0u8; k]) ;
        em[0..k-msg.len()].fill(0);
        em[k-msg.len()..].copy_from_slice(msg);
        let int = Zeroizing::new(BigUint::from_bytes_be(&em));
        uint_to_be_pad(rsa_encrypt(pub_key, &int)?, pub_key.size())
    }
}

/// Always return 1
pub struct NoRng;

impl RngCore for NoRng {
    fn next_u32(&mut self) -> u32 {
        65537
    }

    fn next_u64(&mut self) -> u64 {
        65537
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(1);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for NoRng {

}