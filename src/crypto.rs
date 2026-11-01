use aes::Aes128;
use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecrypt, BlockDecryptMut, BlockEncrypt, KeyInit, KeyIvInit};
use anyhow::{Result, anyhow};
use cbc::Decryptor as CbcDecryptor;
use hmac::{Hmac, Mac};
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPrivateKey};
use sha2::{Digest, Sha256};

use crate::keys::{FAKE_KEYSET, PKG_DERIVED_KEY3, RsaKey};

type Aes128CbcDec = CbcDecryptor<Aes128>;
type HmacSha256 = Hmac<Sha256>;

fn build_rsa_key(k: &RsaKey) -> Result<RsaPrivateKey> {
    let n = BigUint::from_bytes_be(k.modulus);
    let e = BigUint::from_bytes_be(k.public_exponent);
    let d = BigUint::from_bytes_be(k.private_exponent);
    let p = BigUint::from_bytes_be(k.prime1);
    let q = BigUint::from_bytes_be(k.prime2);
    let mut key = RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .map_err(|e| anyhow!("rsa key setup: {e}"))?;
    key.precompute().map_err(|e| anyhow!("rsa precompute: {e}"))?;
    Ok(key)
}

/// PKCS#1 v1.5 RSA decrypt. Writes the first 32 bytes of plaintext into `out`.
pub fn rsa2048_decrypt(out: &mut [u8; 32], ciphertext: &[u8; 256], use_dk3: bool) -> Result<()> {
    let key = build_rsa_key(if use_dk3 { &PKG_DERIVED_KEY3 } else { &FAKE_KEYSET })?;
    let plaintext = key
        .decrypt(Pkcs1v15Encrypt, ciphertext)
        .map_err(|e| anyhow!("rsa decrypt: {e}"))?;
    let take = plaintext.len().min(out.len());
    out[..take].copy_from_slice(&plaintext[..take]);
    Ok(())
}

/// SHA-256 of `input` into `out` (32 bytes).
pub fn iv_key_hash256(out: &mut [u8; 32], input: &[u8; 64]) {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    out.copy_from_slice(&digest);
}

/// AES-128-CBC decrypt. `ivkey` is iv (16) || key (16).
pub fn aes_cbc_decrypt(ivkey: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let (iv, key) = ivkey.split_at(16);
    let mut buf = ciphertext.to_vec();
    Aes128CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| anyhow!("cbc decrypt: {e}"))?;
    Ok(buf)
}

/// HMAC-SHA256(ekpfs, u32_le(1) || seed) → (data_key, tweak_key).
pub fn pfs_gen_crypto_key(ekpfs: &[u8; 32], seed: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(ekpfs).expect("hmac accepts any key length");
    let mut d = [0u8; 20];
    d[..4].copy_from_slice(&1u32.to_le_bytes());
    d[4..].copy_from_slice(seed);
    mac.update(&d);
    let digest = mac.finalize().into_bytes();

    let mut tweak_key = [0u8; 16];
    let mut data_key = [0u8; 16];
    tweak_key.copy_from_slice(&digest[..16]);
    data_key.copy_from_slice(&digest[16..]);
    (data_key, tweak_key)
}

fn xts_xor_block(dst: &mut [u8; 16], a: &[u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        dst[i] = a[i] ^ b[i];
    }
}

fn xts_mult(tweak: &mut [u8; 16]) {
    let mut feedback = 0u8;
    for b in tweak.iter_mut() {
        let next_feedback = (*b >> 7) & 1;
        *b = (*b << 1) | feedback;
        feedback = next_feedback;
    }
    if feedback != 0 {
        tweak[0] ^= 0x87;
    }
}

/// XEX-style PFS decrypt. The tweak input (sector number) advances every 0x1000 bytes;
/// the encrypted tweak is Galois-multiplied once per 16-byte block.
pub fn decrypt_pfs(
    data_key: &[u8; 16],
    tweak_key: &[u8; 16],
    src: &[u8],
    dst: &mut [u8],
    start_sector: u64,
) {
    assert_eq!(src.len(), dst.len());
    assert_eq!(src.len() % 0x1000, 0);

    let data_cipher = Aes128::new(data_key.into());
    let tweak_cipher = Aes128::new(tweak_key.into());

    for (sector_idx, (src_sector, dst_sector)) in src
        .chunks_exact(0x1000)
        .zip(dst.chunks_exact_mut(0x1000))
        .enumerate()
    {
        let current_sector = start_sector + sector_idx as u64;

        let mut tweak = [0u8; 16];
        tweak[..8].copy_from_slice(&current_sector.to_le_bytes());
        tweak_cipher.encrypt_block((&mut tweak).into());

        for (ct, pt) in src_sector
            .chunks_exact(16)
            .zip(dst_sector.chunks_exact_mut(16))
        {
            let ct_block: &[u8; 16] = ct.try_into().unwrap();
            let mut block = [0u8; 16];
            xts_xor_block(&mut block, ct_block, &tweak);
            data_cipher.decrypt_block((&mut block).into());
            let pt_block: &mut [u8; 16] = pt.try_into().unwrap();
            xts_xor_block(pt_block, &block, &tweak);
            xts_mult(&mut tweak);
        }
    }
}
