//! Cryptographic primitives for MimiRats.
//!
//! Cross-platform module providing hash functions, HMAC, symmetric ciphers,
//! key derivation, and Windows-compatible password hashing algorithms.

#![allow(dead_code)]

use digest::Digest;
use hmac::{Hmac, Mac};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, KeyInit};

// ---------------------------------------------------------------------------
// Type aliases for CBC mode ciphers
// ---------------------------------------------------------------------------

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

// HMAC type aliases
type HmacMd5 = Hmac<md5::Md5>;
type HmacSha1 = Hmac<sha1::Sha1>;
type HmacSha256 = Hmac<sha2::Sha256>;

// AES block size
const AES_BLOCK_SIZE: usize = 16;
// DES block size
const DES_BLOCK_SIZE: usize = 8;

// =========================================================================
// 1. Hash functions
// =========================================================================

/// Compute MD4 hash (16 bytes).
pub fn md4_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = md4::Md4::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute MD5 hash (16 bytes).
pub fn md5_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = md5::Md5::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA-1 hash (20 bytes).
pub fn sha1_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = sha1::Sha1::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA-256 hash (32 bytes).
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// =========================================================================
// 2. HMAC functions
// =========================================================================

/// HMAC-MD5.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacMd5 as Mac>::new_from_slice(key)
        .expect("HMAC-MD5 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// HMAC-SHA1.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(key)
        .expect("HMAC-SHA1 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// =========================================================================
// 3. Symmetric encryption / decryption
// =========================================================================

// ---- AES-CBC ----

/// Zero-pad `data` to a multiple of `block_size`.
fn pad_to_block_size(data: &[u8], block_size: usize) -> Vec<u8> {
    if data.is_empty() || block_size == 0 {
        return data.to_vec();
    }
    let remainder = data.len() % block_size;
    if remainder == 0 {
        data.to_vec()
    } else {
        let mut padded = data.to_vec();
        padded.resize(data.len() + (block_size - remainder), 0u8);
        padded
    }
}

/// AES-128 CBC decrypt. Accepts data that may not be block-aligned (pads with zeros).
/// Returns the decrypted buffer truncated to the original data length.
pub fn aes128_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 16 {
        return Err(format!("AES-128 requires 16-byte key, got {}", key.len()));
    }
    if iv.len() != AES_BLOCK_SIZE {
        return Err(format!("AES-CBC requires 16-byte IV, got {}", iv.len()));
    }
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let original_len = data.len();
    let mut buf = pad_to_block_size(data, AES_BLOCK_SIZE);

    let decryptor = Aes128CbcDec::new_from_slices(key, iv)
        .map_err(|e| format!("AES-128-CBC init error: {}", e))?;
    let result = decryptor
        .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|e| format!("AES-128-CBC decrypt error: {}", e))?;

    let mut out = result.to_vec();
    out.truncate(original_len);
    Ok(out)
}

/// AES-256 CBC decrypt.
pub fn aes256_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("AES-256 requires 32-byte key, got {}", key.len()));
    }
    if iv.len() != AES_BLOCK_SIZE {
        return Err(format!("AES-CBC requires 16-byte IV, got {}", iv.len()));
    }
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let original_len = data.len();
    let mut buf = pad_to_block_size(data, AES_BLOCK_SIZE);

    let decryptor = Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|e| format!("AES-256-CBC init error: {}", e))?;
    let result = decryptor
        .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|e| format!("AES-256-CBC decrypt error: {}", e))?;

    let mut out = result.to_vec();
    out.truncate(original_len);
    Ok(out)
}

/// AES-128 CBC encrypt.
pub fn aes128_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 16 {
        return Err(format!("AES-128 requires 16-byte key, got {}", key.len()));
    }
    if iv.len() != AES_BLOCK_SIZE {
        return Err(format!("AES-CBC requires 16-byte IV, got {}", iv.len()));
    }
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let padded = pad_to_block_size(data, AES_BLOCK_SIZE);
    let mut buf = vec![0u8; padded.len() + AES_BLOCK_SIZE]; // extra block for padding output space
    buf[..padded.len()].copy_from_slice(&padded);

    let encryptor = Aes128CbcEnc::new_from_slices(key, iv)
        .map_err(|e| format!("AES-128-CBC init error: {}", e))?;
    let result = encryptor
        .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buf, padded.len())
        .map_err(|e| format!("AES-128-CBC encrypt error: {}", e))?;

    Ok(result.to_vec())
}

/// AES-256 CBC encrypt.
pub fn aes256_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("AES-256 requires 32-byte key, got {}", key.len()));
    }
    if iv.len() != AES_BLOCK_SIZE {
        return Err(format!("AES-CBC requires 16-byte IV, got {}", iv.len()));
    }
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let padded = pad_to_block_size(data, AES_BLOCK_SIZE);
    let mut buf = vec![0u8; padded.len() + AES_BLOCK_SIZE];
    buf[..padded.len()].copy_from_slice(&padded);

    let encryptor = Aes256CbcEnc::new_from_slices(key, iv)
        .map_err(|e| format!("AES-256-CBC init error: {}", e))?;
    let result = encryptor
        .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buf, padded.len())
        .map_err(|e| format!("AES-256-CBC encrypt error: {}", e))?;

    Ok(result.to_vec())
}

// ---- RC4 (manual implementation) ----

/// RC4 Key Scheduling Algorithm (KSA) and Pseudo-Random Generation Algorithm (PRGA).
struct Rc4State {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4State {
    /// Initialize the RC4 state from a key (KSA).
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }

        if !key.is_empty() {
            let mut j: u8 = 0;
            for i in 0..256 {
                j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
                s.swap(i, j as usize);
            }
        }

        Rc4State { s, i: 0, j: 0 }
    }

    /// Generate the next keystream byte (PRGA).
    fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);
        self.s.swap(self.i as usize, self.j as usize);
        let idx = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
        self.s[idx as usize]
    }

    /// XOR the data with the keystream in-place.
    fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            *byte ^= self.next_byte();
        }
    }
}

/// RC4 encrypt (XOR with keystream). RC4 is symmetric: encrypt == decrypt.
pub fn rc4_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut output = data.to_vec();
    let mut state = Rc4State::new(key);
    state.apply(&mut output);
    output
}

/// RC4 decrypt (identical to encrypt for a stream cipher).
pub fn rc4_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    rc4_encrypt(key, data)
}

// ---- DES ECB ----

/// Single DES ECB encrypt. Data is zero-padded to a multiple of 8 bytes.
pub fn des_ecb_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != DES_BLOCK_SIZE {
        return Err(format!("DES requires 8-byte key, got {}", key.len()));
    }
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut des_cipher = des::Des::new_from_slice(key)
        .map_err(|e| format!("DES init error: {}", e))?;

    let padded = pad_to_block_size(data, DES_BLOCK_SIZE);
    let mut output = padded.clone();

    for chunk in output.chunks_exact_mut(DES_BLOCK_SIZE) {
        let block_ref = cipher::generic_array::GenericArray::from_mut_slice(chunk);
        des_cipher.encrypt_block_mut(block_ref);
    }

    Ok(output)
}

/// Single DES ECB decrypt. Data must be a multiple of 8 bytes.
pub fn des_ecb_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != DES_BLOCK_SIZE {
        return Err(format!("DES requires 8-byte key, got {}", key.len()));
    }
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data.len() % DES_BLOCK_SIZE != 0 {
        return Err(format!(
            "DES ECB decrypt requires data aligned to {} bytes, got {}",
            DES_BLOCK_SIZE,
            data.len()
        ));
    }

    let mut des_cipher = des::Des::new_from_slice(key)
        .map_err(|e| format!("DES init error: {}", e))?;

    let mut output = data.to_vec();

    for chunk in output.chunks_exact_mut(DES_BLOCK_SIZE) {
        let block_ref = cipher::generic_array::GenericArray::from_mut_slice(chunk);
        des_cipher.decrypt_block_mut(block_ref);
    }

    Ok(output)
}

// ---- DESX CBC (for NT5 LSA secrets) ----

/// DESX CBC mode decryption, as used in NT5-era LSA secret encryption.
///
/// DESX extends DES with pre- and post-whitening XOR keys.
/// The 24-byte key is split as: DES_key (8) | pre_whitening (8) | post_whitening (8).
/// CBC mode uses the provided IV.
pub fn desx_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() < 24 {
        return Err(format!("DESX requires 24-byte key (8 DES + 8 pre + 8 post), got {}", key.len()));
    }
    if iv.len() < DES_BLOCK_SIZE {
        return Err(format!("DESX CBC requires 8-byte IV, got {}", iv.len()));
    }
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data.len() % DES_BLOCK_SIZE != 0 {
        return Err(format!(
            "DESX CBC requires data aligned to {} bytes, got {}",
            DES_BLOCK_SIZE,
            data.len()
        ));
    }

    let des_key = &key[0..8];
    let pre_whitening = &key[8..16];
    let post_whitening = &key[16..24];

    let mut des_cipher = des::Des::new_from_slice(des_key)
        .map_err(|e| format!("DES init error: {}", e))?;

    let mut output = Vec::with_capacity(data.len());
    let mut prev_ct = [0u8; DES_BLOCK_SIZE];
    prev_ct.copy_from_slice(&iv[..DES_BLOCK_SIZE]);

    for chunk in data.chunks_exact(DES_BLOCK_SIZE) {
        // DESX decrypt: XOR with post_whitening, DES decrypt, XOR with pre_whitening, then CBC XOR with prev ciphertext
        let mut block = [0u8; DES_BLOCK_SIZE];
        for i in 0..DES_BLOCK_SIZE {
            block[i] = chunk[i] ^ post_whitening[i];
        }

        let block_ref = cipher::generic_array::GenericArray::from_mut_slice(&mut block);
        des_cipher.decrypt_block_mut(block_ref);

        for i in 0..DES_BLOCK_SIZE {
            block[i] ^= pre_whitening[i];
        }

        // CBC: XOR with previous ciphertext block
        for i in 0..DES_BLOCK_SIZE {
            block[i] ^= prev_ct[i];
        }

        prev_ct.copy_from_slice(chunk);
        output.extend_from_slice(&block);
    }

    Ok(output)
}

// =========================================================================
// 4. AES-CTS (Cipher Text Stealing) for Kerberos
// =========================================================================

/// AES-CTS encrypt (CTS mode as used in Kerberos AES encryption types).
///
/// For data <= 16 bytes: zero-pad to one block and do AES-CBC.
/// For data > 16 bytes:
///   1. AES-CBC encrypt all data zero-padded to block alignment.
///   2. Swap the last two ciphertext blocks.
///   3. Truncate output to original data length.
pub fn aes_cts_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 16 && key.len() != 32 {
        return Err(format!("AES-CTS requires 16 or 32-byte key, got {}", key.len()));
    }
    if iv.len() != AES_BLOCK_SIZE {
        return Err(format!("AES-CTS requires 16-byte IV, got {}", iv.len()));
    }
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let original_len = data.len();

    // For data that fits in one block or less, just do AES-CBC
    if original_len <= AES_BLOCK_SIZE {
        let padded = pad_to_block_size(data, AES_BLOCK_SIZE);
        return aes_cbc_encrypt_raw(key, iv, &padded);
    }

    // Pad data to full blocks for CBC encryption
    let padded = pad_to_block_size(data, AES_BLOCK_SIZE);
    let num_blocks = padded.len() / AES_BLOCK_SIZE;

    // AES-CBC encrypt all padded data
    let encrypted = aes_cbc_encrypt_raw(key, iv, &padded)?;

    // Swap the last two ciphertext blocks, then truncate
    let mut result = encrypted;
    if num_blocks >= 2 {
        let second_last_start = (num_blocks - 2) * AES_BLOCK_SIZE;
        let last_start = (num_blocks - 1) * AES_BLOCK_SIZE;

        // Swap the two blocks in place
        for i in 0..AES_BLOCK_SIZE {
            result.swap(second_last_start + i, last_start + i);
        }
    }

    result.truncate(original_len);
    Ok(result)
}

/// AES-CTS decrypt (CTS mode as used in Kerberos AES encryption types).
///
/// For data <= 16 bytes: zero-pad to one block and do AES-CBC decrypt.
/// For data > 16 bytes: reverse the CTS process.
pub fn aes_cts_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 16 && key.len() != 32 {
        return Err(format!("AES-CTS requires 16 or 32-byte key, got {}", key.len()));
    }
    if iv.len() != AES_BLOCK_SIZE {
        return Err(format!("AES-CTS requires 16-byte IV, got {}", iv.len()));
    }
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let original_len = data.len();

    // For data that fits in one block or less
    if original_len <= AES_BLOCK_SIZE {
        let padded = pad_to_block_size(data, AES_BLOCK_SIZE);
        let mut result = aes_cbc_decrypt_raw(key, iv, &padded)?;
        result.truncate(original_len);
        return Ok(result);
    }

    // Number of complete blocks and the tail length
    let num_full_blocks = original_len / AES_BLOCK_SIZE;
    let tail_len = original_len % AES_BLOCK_SIZE;

    if tail_len == 0 {
        // Data is block-aligned, but CTS still swaps the last two blocks
        let mut working = data.to_vec();
        let second_last_start = (num_full_blocks - 2) * AES_BLOCK_SIZE;
        let last_start = (num_full_blocks - 1) * AES_BLOCK_SIZE;

        // Swap back the last two blocks
        for i in 0..AES_BLOCK_SIZE {
            working.swap(second_last_start + i, last_start + i);
        }

        return aes_cbc_decrypt_raw(key, iv, &working);
    }

    // Non-block-aligned: CTS with partial last block
    // After encrypt's swap+truncate, the ciphertext layout is:
    //   [E[0]..E[n-3]] | E[n-1] (full 16-byte block) | E[n-2][0..tail_len] (partial)
    // To decrypt:
    // 1. ECB-decrypt E[n-1] to get intermediate I = P_pad[n-1] XOR E[n-2]
    // 2. Since padding bytes of P_pad[n-1] are zero: I[tail_len..] = E[n-2][tail_len..]
    // 3. Reconstruct full E[n-2] from partial + I[tail_len..]
    // 4. Reassemble original CBC order: E[0..n-3] | E[n-2] | E[n-1]
    // 5. CBC-decrypt and truncate to remove padding

    let n_minus_2_blocks = num_full_blocks - 1; // number of leading blocks before the CTS pair
    let cts_pair_start = n_minus_2_blocks * AES_BLOCK_SIZE;

    // E[n-1] is the full block (comes first in CTS output)
    let en_1_block = &data[cts_pair_start..cts_pair_start + AES_BLOCK_SIZE];
    // E[n-2] partial is the remaining tail_len bytes
    let en_2_partial = &data[cts_pair_start + AES_BLOCK_SIZE..];

    // ECB-decrypt E[n-1] to get intermediate
    let intermediate = aes_ecb_decrypt_block(key, en_1_block)?;

    // Reconstruct full E[n-2]: known partial bytes + padding from intermediate
    let mut en_2_full = [0u8; AES_BLOCK_SIZE];
    en_2_full[..tail_len].copy_from_slice(en_2_partial);
    en_2_full[tail_len..].copy_from_slice(&intermediate[tail_len..]);

    // Reassemble in original CBC order: E[0..n-3] | E[n-2] | E[n-1]
    let mut reconstructed = Vec::with_capacity((n_minus_2_blocks + 2) * AES_BLOCK_SIZE);
    reconstructed.extend_from_slice(&data[..cts_pair_start]); // leading blocks
    reconstructed.extend_from_slice(&en_2_full); // E[n-2] reconstructed
    reconstructed.extend_from_slice(en_1_block); // E[n-1]

    let mut decrypted = aes_cbc_decrypt_raw(key, iv, &reconstructed)?;
    decrypted.truncate(original_len);
    Ok(decrypted)
}

/// Raw AES-CBC encrypt with NoPadding (data must be block-aligned).
fn aes_cbc_encrypt_raw(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() == 16 {
        let mut buf = vec![0u8; data.len() + AES_BLOCK_SIZE];
        buf[..data.len()].copy_from_slice(data);
        let enc = Aes128CbcEnc::new_from_slices(key, iv)
            .map_err(|e| format!("AES-CBC init error: {}", e))?;
        let result = enc
            .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buf, data.len())
            .map_err(|e| format!("AES-CBC encrypt error: {}", e))?;
        Ok(result.to_vec())
    } else if key.len() == 32 {
        let mut buf = vec![0u8; data.len() + AES_BLOCK_SIZE];
        buf[..data.len()].copy_from_slice(data);
        let enc = Aes256CbcEnc::new_from_slices(key, iv)
            .map_err(|e| format!("AES-CBC init error: {}", e))?;
        let result = enc
            .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buf, data.len())
            .map_err(|e| format!("AES-CBC encrypt error: {}", e))?;
        Ok(result.to_vec())
    } else {
        Err(format!("AES requires 16 or 32-byte key, got {}", key.len()))
    }
}

/// Raw AES-CBC decrypt with NoPadding (data must be block-aligned).
fn aes_cbc_decrypt_raw(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() == 16 {
        let mut buf = data.to_vec();
        let dec = Aes128CbcDec::new_from_slices(key, iv)
            .map_err(|e| format!("AES-CBC init error: {}", e))?;
        let result = dec
            .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buf)
            .map_err(|e| format!("AES-CBC decrypt error: {}", e))?;
        Ok(result.to_vec())
    } else if key.len() == 32 {
        let mut buf = data.to_vec();
        let dec = Aes256CbcDec::new_from_slices(key, iv)
            .map_err(|e| format!("AES-CBC init error: {}", e))?;
        let result = dec
            .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buf)
            .map_err(|e| format!("AES-CBC decrypt error: {}", e))?;
        Ok(result.to_vec())
    } else {
        Err(format!("AES requires 16 or 32-byte key, got {}", key.len()))
    }
}

/// AES ECB decrypt a single block (for AES-CTS internal use).
fn aes_ecb_decrypt_block(key: &[u8], block: &[u8]) -> Result<[u8; AES_BLOCK_SIZE], String> {
    if block.len() != AES_BLOCK_SIZE {
        return Err(format!("ECB block must be {} bytes", AES_BLOCK_SIZE));
    }

    let mut out = [0u8; AES_BLOCK_SIZE];
    out.copy_from_slice(block);

    if key.len() == 16 {
        let mut aes_cipher = aes::Aes128::new_from_slice(key)
            .map_err(|e| format!("AES-128 init error: {}", e))?;
        let block_ref = cipher::generic_array::GenericArray::from_mut_slice(&mut out);
        aes_cipher.decrypt_block_mut(block_ref);
    } else if key.len() == 32 {
        let mut aes_cipher = aes::Aes256::new_from_slice(key)
            .map_err(|e| format!("AES-256 init error: {}", e))?;
        let block_ref = cipher::generic_array::GenericArray::from_mut_slice(&mut out);
        aes_cipher.decrypt_block_mut(block_ref);
    } else {
        return Err(format!("AES requires 16 or 32-byte key, got {}", key.len()));
    }

    Ok(out)
}

// =========================================================================
// 5. Key derivation
// =========================================================================

/// PBKDF2-HMAC-SHA1 key derivation.
pub fn pbkdf2_hmac_sha1(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Vec<u8> {
    let mut output = vec![0u8; output_len];
    pbkdf2::pbkdf2::<Hmac<sha1::Sha1>>(password, salt, iterations, &mut output)
        .expect("PBKDF2-HMAC-SHA1 output length should be valid");
    output
}

/// PBKDF2-HMAC-SHA256 key derivation.
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Vec<u8> {
    let mut output = vec![0u8; output_len];
    pbkdf2::pbkdf2::<Hmac<sha2::Sha256>>(password, salt, iterations, &mut output)
        .expect("PBKDF2-HMAC-SHA256 output length should be valid");
    output
}

// =========================================================================
// 6. Password hashing (Windows-specific algorithms, pure computation)
// =========================================================================

/// Convert a string to UTF-16LE byte representation.
pub fn str_to_utf16le(s: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(s.len() * 2);
    for code_unit in s.encode_utf16() {
        bytes.push((code_unit & 0xFF) as u8);
        bytes.push((code_unit >> 8) as u8);
    }
    bytes
}

/// Compute the NT hash (NTLM hash) of a password.
/// NT hash = MD4(UTF-16LE(password)).
pub fn nt_hash(password: &str) -> Vec<u8> {
    let utf16 = str_to_utf16le(password);
    md4_hash(&utf16)
}

/// Expand a 7-byte value into an 8-byte DES key with parity bits.
///
/// Each group of 7 bits from the input becomes 7 bits of a DES key byte,
/// with the 8th bit set to provide odd parity.
pub fn des_key_from_7(seven: &[u8]) -> [u8; 8] {
    assert!(seven.len() >= 7, "des_key_from_7 requires at least 7 bytes");

    let mut key = [0u8; 8];
    key[0] = seven[0] >> 1;
    key[1] = ((seven[0] & 0x01) << 6) | (seven[1] >> 2);
    key[2] = ((seven[1] & 0x03) << 5) | (seven[2] >> 3);
    key[3] = ((seven[2] & 0x07) << 4) | (seven[3] >> 4);
    key[4] = ((seven[3] & 0x0F) << 3) | (seven[4] >> 5);
    key[5] = ((seven[4] & 0x1F) << 2) | (seven[5] >> 6);
    key[6] = ((seven[5] & 0x3F) << 1) | (seven[6] >> 7);
    key[7] = seven[6] & 0x7F;

    // Set odd parity on each byte
    for byte in key.iter_mut() {
        *byte = (*byte << 1) | 1; // shift left and set low bit
        // Count set bits; if even number of 1s, flip the low bit to make it odd
        let bits = (*byte).count_ones();
        if bits % 2 == 0 {
            *byte ^= 1;
        }
    }

    key
}

/// Compute the LM hash of a password.
///
/// Algorithm:
/// 1. Convert password to uppercase ASCII.
/// 2. Pad or truncate to exactly 14 bytes.
/// 3. Split into two 7-byte halves.
/// 4. Expand each 7-byte half to an 8-byte DES key (with parity).
/// 5. DES-ECB encrypt the magic constant "KGS!@#$%" with each key.
/// 6. Concatenate the two 8-byte results.
pub fn lm_hash(password: &str) -> Vec<u8> {
    const LM_MAGIC: &[u8] = b"KGS!@#$%";

    // Uppercase and convert to bytes (ASCII only for LM)
    let upper: Vec<u8> = password
        .as_bytes()
        .iter()
        .map(|b| b.to_ascii_uppercase())
        .collect();

    // Pad or truncate to 14 bytes
    let mut padded = [0u8; 14];
    let copy_len = upper.len().min(14);
    padded[..copy_len].copy_from_slice(&upper[..copy_len]);

    // Split into two 7-byte halves
    let key1 = des_key_from_7(&padded[0..7]);
    let key2 = des_key_from_7(&padded[7..14]);

    // DES-ECB encrypt the magic constant with each key
    let part1 = des_ecb_encrypt(&key1, LM_MAGIC)
        .expect("DES encrypt of LM magic should not fail");
    let part2 = des_ecb_encrypt(&key2, LM_MAGIC)
        .expect("DES encrypt of LM magic should not fail");

    let mut result = Vec::with_capacity(16);
    result.extend_from_slice(&part1[..8]);
    result.extend_from_slice(&part2[..8]);
    result
}

// =========================================================================
// 7. Domain cached credentials
// =========================================================================

/// DCC v1 (Domain Cached Credentials version 1, aka "mscache").
/// DCC_v1 = MD4(NT_hash || lowercase_username_UTF16LE)
pub fn dcc_v1(nt_hash: &[u8], username: &str) -> Vec<u8> {
    let username_lower = username.to_lowercase();
    let username_utf16 = str_to_utf16le(&username_lower);

    let mut input = Vec::with_capacity(nt_hash.len() + username_utf16.len());
    input.extend_from_slice(nt_hash);
    input.extend_from_slice(&username_utf16);

    md4_hash(&input)
}

/// DCC v2 (Domain Cached Credentials version 2, aka "mscache2").
/// DCC_v2 = PBKDF2-HMAC-SHA1(DCC_v1, lowercase_username_UTF16LE, iterations, 16)
pub fn dcc_v2(nt_hash: &[u8], username: &str, iterations: u32) -> Vec<u8> {
    let v1 = dcc_v1(nt_hash, username);
    let username_lower = username.to_lowercase();
    let salt = str_to_utf16le(&username_lower);

    pbkdf2_hmac_sha1(&v1, &salt, iterations, 16)
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md4_hash() {
        // MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
        let empty_hash = md4_hash(b"");
        assert_eq!(hex::encode(&empty_hash), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn test_md5_hash() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let empty_hash = md5_hash(b"");
        assert_eq!(hex::encode(&empty_hash), "d41d8cd98f00b204e9800998ecf8427e");

        // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        let abc_hash = md5_hash(b"abc");
        assert_eq!(hex::encode(&abc_hash), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_sha1_hash() {
        // SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let hash = sha1_hash(b"abc");
        assert_eq!(hex::encode(&hash), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn test_sha256_hash() {
        // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let hash = sha256_hash(b"abc");
        assert_eq!(
            hex::encode(&hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_hmac_md5() {
        // RFC 2104 test vector
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = b"Hi There";
        let result = hmac_md5(&key, data);
        assert_eq!(hex::encode(&result), "9294727a3638bb1c13f48ef8158bfc9d");
    }

    #[test]
    fn test_hmac_sha256() {
        // RFC 4231 Test Case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let result = hmac_sha256(key, data);
        assert_eq!(
            hex::encode(&result),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn test_str_to_utf16le() {
        let result = str_to_utf16le("A");
        assert_eq!(result, vec![0x41, 0x00]);

        let result = str_to_utf16le("AB");
        assert_eq!(result, vec![0x41, 0x00, 0x42, 0x00]);
    }

    #[test]
    fn test_nt_hash() {
        // Empty password: MD4 of empty UTF-16LE = MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
        let hash = nt_hash("");
        assert_eq!(hex::encode(&hash), "31d6cfe0d16ae931b73c59d7e0c089c0");

        // "Password" -> known NTLM hash: a4f49c406510bdcab6824ee7c30fd852
        let hash = nt_hash("Password");
        assert_eq!(hex::encode(&hash), "a4f49c406510bdcab6824ee7c30fd852");
    }

    #[test]
    fn test_des_key_from_7() {
        // The expanded key should always have 8 bytes with parity bits
        let seven = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let key = des_key_from_7(&seven);
        assert_eq!(key.len(), 8);

        // All-zero input should produce keys with odd parity
        for &byte in key.iter() {
            assert_eq!(byte.count_ones() % 2, 1, "DES key byte should have odd parity");
        }
    }

    #[test]
    fn test_lm_hash() {
        // Empty password LM hash: aad3b435b51404eeaad3b435b51404ee
        let hash = lm_hash("");
        assert_eq!(hex::encode(&hash), "aad3b435b51404eeaad3b435b51404ee");
    }

    #[test]
    fn test_rc4_roundtrip() {
        let key = b"secret_key";
        let plaintext = b"Hello, World! This is a test of RC4 encryption.";

        let ciphertext = rc4_encrypt(key, plaintext);
        assert_ne!(&ciphertext[..], &plaintext[..]);

        let decrypted = rc4_decrypt(key, &ciphertext);
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_rc4_empty() {
        let key = b"key";
        let result = rc4_encrypt(key, b"");
        assert!(result.is_empty());
    }

    #[test]
    fn test_aes128_cbc_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x00u8; 16];
        let plaintext = [0xAAu8; 32]; // two blocks

        let encrypted = aes128_cbc_encrypt(&key, &iv, &plaintext).unwrap();
        let decrypted = aes128_cbc_decrypt(&key, &iv, &encrypted).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes256_cbc_roundtrip() {
        let key = [0x42u8; 32];
        let iv = [0x00u8; 16];
        let plaintext = [0xBBu8; 48]; // three blocks

        let encrypted = aes256_cbc_encrypt(&key, &iv, &plaintext).unwrap();
        let decrypted = aes256_cbc_decrypt(&key, &iv, &encrypted).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes_cbc_empty() {
        let key = [0u8; 16];
        let iv = [0u8; 16];

        let enc = aes128_cbc_encrypt(&key, &iv, b"").unwrap();
        assert!(enc.is_empty());
        let dec = aes128_cbc_decrypt(&key, &iv, b"").unwrap();
        assert!(dec.is_empty());
    }

    #[test]
    fn test_des_ecb_roundtrip() {
        let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        let plaintext = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

        let encrypted = des_ecb_encrypt(&key, &plaintext).unwrap();
        let decrypted = des_ecb_decrypt(&key, &encrypted).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes_cts_block_aligned() {
        let key = [0x42u8; 16];
        let iv = [0x00u8; 16];
        let plaintext = [0xAAu8; 32]; // exactly 2 blocks

        let encrypted = aes_cts_encrypt(&key, &iv, &plaintext).unwrap();
        let decrypted = aes_cts_decrypt(&key, &iv, &encrypted).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes_cts_non_aligned() {
        let key = [0x42u8; 16];
        let iv = [0x00u8; 16];
        let plaintext = [0xAAu8; 25]; // 1.5+ blocks

        let encrypted = aes_cts_encrypt(&key, &iv, &plaintext).unwrap();
        assert_eq!(encrypted.len(), plaintext.len());
        let decrypted = aes_cts_decrypt(&key, &iv, &encrypted).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes_cts_single_block() {
        let key = [0x42u8; 16];
        let iv = [0x00u8; 16];
        let plaintext = [0xCCu8; 16]; // exactly one block

        let encrypted = aes_cts_encrypt(&key, &iv, &plaintext).unwrap();
        let decrypted = aes_cts_decrypt(&key, &iv, &encrypted).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_pbkdf2_sha1() {
        // RFC 6070 test vector 1: P = "password", S = "salt", c = 1, dkLen = 20
        let dk = pbkdf2_hmac_sha1(b"password", b"salt", 1, 20);
        assert_eq!(
            hex::encode(&dk),
            "0c60c80f961f0e71f3a9b524af6012062fe037a6"
        );
    }

    #[test]
    fn test_dcc_v1() {
        // Compute with known NT hash of empty password
        let nt = nt_hash("");
        let result = dcc_v1(&nt, "administrator");
        // DCC v1 should return 16 bytes
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_dcc_v2() {
        // DCC v2 should return 16 bytes
        let nt = nt_hash("password");
        let result = dcc_v2(&nt, "testuser", 10240);
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_key_size_validation() {
        let iv = [0u8; 16];
        let data = [0u8; 16];

        // Wrong key sizes should return errors
        assert!(aes128_cbc_encrypt(&[0u8; 15], &iv, &data).is_err());
        assert!(aes128_cbc_decrypt(&[0u8; 17], &iv, &data).is_err());
        assert!(aes256_cbc_encrypt(&[0u8; 31], &iv, &data).is_err());
        assert!(aes256_cbc_decrypt(&[0u8; 33], &iv, &data).is_err());
        assert!(des_ecb_encrypt(&[0u8; 7], &data).is_err());
        assert!(des_ecb_decrypt(&[0u8; 9], &data).is_err());
    }
}
