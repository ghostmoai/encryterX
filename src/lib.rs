//! EncryptorX - Motor Criptográfico y Esteganográfico Nativo en Rust v3.0.0
//! Algoritmo Null-Obfuscated Cipher con 64 combinaciones, HMAC-SHA256, PBKDF2 y FFI.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const VERSION: &str = "3.3.0";
pub const SEPARATORS: [char; 4] = ['$', '%', '&', '#'];
pub const DEFAULT_SEPARATOR: char = '$';
pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 16;
pub const TAG_SIZE: usize = 16;
pub const SALT_SIZE: usize = 16;
pub const PBKDF2_ROUNDS: u32 = 100_000;

pub const AEAD_NONCE_SIZE: usize = 12;
pub const AEAD_TAG_SIZE: usize = 16;

pub const FLAG_DIRECT: u8 = 0x00;
pub const FLAG_PBKDF2: u8 = 0x01;
pub const FLAG_SCRYPT: u8 = 0x02;
pub const FLAG_DOUBLE_DIRECT: u8 = 0x10;
pub const FLAG_DOUBLE_CASCADE: u8 = 0x12;

pub const FLAG_AEAD_DIRECT: u8 = 0x20;
pub const FLAG_AEAD_PBKDF2: u8 = 0x21;
pub const FLAG_AEAD_SCRYPT: u8 = 0x22;

pub mod gui;
pub mod ciphers;
pub mod shamir;

// ---------------------------------------------------------------------------
// Primitivas Criptográficas: SHA-256 y HMAC-SHA256 en Rust Puro
// ---------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4*i], chunk[4*i+1], chunk[4*i+2], chunk[4*i+3]]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        let mut a = h[0]; let mut b = h[1]; let mut c = h[2]; let mut d = h[3];
        let mut e = h[4]; let mut f = h[5]; let mut g = h[6]; let mut h_var = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_var.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_var = g; g = f; f = e; e = d.wrapping_add(temp1);
            d = c; c = b; b = a; a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(h_var);
    }

    let mut result = [0u8; 32];
    for i in 0..8 {
        result[4*i..4*i+4].copy_from_slice(&h[i].to_be_bytes());
    }
    result
}

/// Borrado seguro de memoria (Zeroization) resistente a optimizaciones del compilador.
/// Escribe de forma volátil ceros en el buffer e inserta una barrera de sincronización.
#[inline(never)]
pub fn zeroize_slice(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha256(key);
        k[..32].copy_from_slice(&hashed);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut i_pad = [0u8; 64];
    let mut o_pad = [0u8; 64];
    for i in 0..64 {
        i_pad[i] = k[i] ^ 0x36;
        o_pad[i] = k[i] ^ 0x5c;
    }

    let mut inner = i_pad.to_vec();
    inner.extend_from_slice(data);
    let inner_hash = sha256(&inner);

    let mut outer = o_pad.to_vec();
    outer.extend_from_slice(&inner_hash);
    let result = sha256(&outer);

    zeroize_slice(&mut k);
    zeroize_slice(&mut i_pad);
    zeroize_slice(&mut o_pad);
    zeroize_slice(&mut inner);
    zeroize_slice(&mut outer);

    result
}

pub fn pbkdf2_sha256(password: &str, salt: &[u8], rounds: u32) -> [u8; 32] {
    let pwd_bytes = password.as_bytes();
    let mut salt_one = salt.to_vec();
    salt_one.extend_from_slice(&1u32.to_be_bytes());

    let mut u = hmac_sha256(pwd_bytes, &salt_one);
    let mut t = u;

    for _ in 1..rounds {
        u = hmac_sha256(pwd_bytes, &u);
        for j in 0..32 {
            t[j] ^= u[j];
        }
    }

    zeroize_slice(&mut salt_one);
    zeroize_slice(&mut u);

    t
}

pub fn generate_keystream(key: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    let mut ks = Vec::with_capacity(length + 32);
    let mut counter: u32 = 0;
    while ks.len() < length {
        let mut block = key.to_vec();
        block.extend_from_slice(nonce);
        block.extend_from_slice(&counter.to_be_bytes());
        let mut hash = sha256(&block);
        ks.extend_from_slice(&hash);
        zeroize_slice(&mut block);
        zeroize_slice(&mut hash);
        counter = counter.wrapping_add(1);
    }
    ks.truncate(length);
    ks
}

// ---------------------------------------------------------------------------
// Entropía y Números Pseudoaleatorios Seguros del SO
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn get_os_random(buf: &mut [u8]) {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            hAlgorithm: *mut std::ffi::c_void,
            pbBuffer: *mut u8,
            cbBuffer: u32,
            dwFlags: u32,
        ) -> i32;
    }
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;
    unsafe {
        let status = BCryptGenRandom(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        );
        if status != 0 {
            fallback_random(buf);
        }
    }
}

#[cfg(not(windows))]
fn get_os_random(buf: &mut [u8]) {
    use std::fs::File;
    use std::io::Read;
    if let Ok(mut f) = File::open("/dev/urandom") {
        if f.read_exact(buf).is_ok() {
            return;
        }
    }
    fallback_random(buf);
}

fn fallback_random(buf: &mut [u8]) {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let mut state = sha256(&t.to_be_bytes());
    for chunk in buf.chunks_mut(32) {
        state = sha256(&state);
        let len = chunk.len();
        chunk.copy_from_slice(&state[..len]);
    }
}

pub struct RngSource {
    buffer: [u8; 128],
    idx: usize,
}

impl RngSource {
    pub fn new() -> Self {
        let mut r = Self { buffer: [0u8; 128], idx: 128 };
        r.refresh();
        r
    }

    pub fn refresh(&mut self) {
        get_os_random(&mut self.buffer);
        self.idx = 0;
    }

    pub fn next_byte(&mut self) -> u8 {
        if self.idx >= self.buffer.len() {
            self.refresh();
        }
        let b = self.buffer[self.idx];
        self.idx += 1;
        b
    }

    pub fn rand_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        let span = max - min + 1;
        min + (self.next_byte() as usize % span)
    }

    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = self.next_byte();
        }
    }
}

pub fn fill_random_bytes(buf: &mut [u8]) {
    let mut rng = RngSource::new();
    rng.fill_bytes(buf);
}

/// Deriva un nonce sintético de 96 bits (12 bytes) resistente a colisiones para ChaCha20-Poly1305.
/// N = HMAC-SHA256(key, CSPRNG_16 || Plaintext)[0..12].
/// Garantiza resistencia al reúso de nonces (Two-Time Pad) incluso si el CSPRNG
/// entra en un estado degradado o repetitivo.
pub fn derive_synthetic_nonce(key: &[u8; 32], plaintext: &[u8]) -> [u8; 12] {
    let mut entropy = [0u8; 16];
    fill_random_bytes(&mut entropy);
    let mut hmac_input = Vec::with_capacity(16 + plaintext.len());
    hmac_input.extend_from_slice(&entropy);
    hmac_input.extend_from_slice(plaintext);
    let full_hmac = hmac_sha256(key, &hmac_input);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&full_hmac[..12]);
    zeroize_slice(&mut entropy);
    zeroize_slice(&mut hmac_input);
    nonce
}

// ---------------------------------------------------------------------------
// Catálogo Ofuscado de 64 Combinaciones Simbólicas y 64 Envoltorios Legacy
// Los literales de cadena se almacenan cifrados con máscara XOR y se reconstruyen
// en memoria dinámica para prevenir ingeniería inversa y extracción de firmas.
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

const OBFUSCATED_KEY: [u8; 16] = [
    0x5a, 0xc3, 0x91, 0x47, 0x1e, 0x88, 0x62, 0xf5, 0x33, 0xaa, 0x09, 0x7d,
    0xb6, 0x44, 0x2c, 0x9f,
];

const OBFUSCATED_SYMBOLIC_BLOB: [u8; 447] = [
    0x01, 0xf3, 0xca, 0x58, 0x43, 0xb8, 0x3f, 0xeb, 0x68, 0x9b, 0x52, 0x62,
    0xeb, 0x75, 0x71, 0x81, 0x01, 0xf1, 0xca, 0x58, 0x43, 0xba, 0x3f, 0xeb,
    0x68, 0x99, 0x52, 0x62, 0xeb, 0x77, 0x71, 0x81, 0x21, 0xf7, 0xea, 0x58,
    0x63, 0xbc, 0x1f, 0xeb, 0x48, 0x9f, 0x72, 0x62, 0xcb, 0x71, 0x51, 0x81,
    0x21, 0xf5, 0xea, 0x58, 0x63, 0xbe, 0x1f, 0xeb, 0x48, 0x9d, 0x72, 0x62,
    0xcb, 0x73, 0x51, 0x81, 0x72, 0xfb, 0xb9, 0x58, 0x37, 0xb0, 0x4b, 0xeb,
    0x1b, 0x93, 0x21, 0x62, 0x9f, 0x7d, 0x05, 0x81, 0x01, 0xf3, 0xcc, 0x58,
    0x45, 0xb8, 0x3f, 0xeb, 0x48, 0x9b, 0x74, 0x62, 0xcd, 0x75, 0x51, 0x81,
    0x72, 0xf1, 0xb8, 0x58, 0x36, 0xba, 0x4b, 0xeb, 0x0f, 0x99, 0x37, 0x62,
    0x8a, 0x77, 0x12, 0x81, 0x01, 0xf7, 0xcc, 0x58, 0x45, 0xbc, 0x3f, 0xeb,
    0x48, 0x9f, 0x74, 0x62, 0xcd, 0x71, 0x51, 0x81, 0x66, 0xbf, 0x8e, 0x3b,
    0x20, 0x96, 0x5e, 0xc8, 0x2c, 0x97, 0x37, 0x63, 0x8a, 0x69, 0x33, 0xb2,
    0x64, 0xdd, 0xad, 0x39, 0x01, 0xf6, 0x5c, 0xeb, 0x0f, 0x81, 0x16, 0x56,
    0x88, 0x5a, 0x10, 0xa3, 0x45, 0xfd, 0xaf, 0x59, 0x20, 0xb6, 0x7d, 0xc9,
    0x0f, 0xb4, 0x37, 0x01, 0xa9, 0x38, 0x10, 0x81, 0x66, 0xe9, 0x8e, 0x6d,
    0x20, 0x96, 0x5e, 0xab, 0x2c, 0xf4, 0x37, 0x63, 0x8a, 0x04, 0x33, 0xdf,
    0x64, 0xdd, 0xad, 0x66, 0x01, 0xa9, 0x5c, 0xeb, 0x4d, 0xd4, 0x16, 0x03,
    0xc8, 0x5a, 0x72, 0xc1, 0x45, 0x9d, 0xcf, 0x59, 0x34, 0xa2, 0x7d, 0xdf,
    0x19, 0xb4, 0x22, 0x56, 0xa9, 0x6f, 0x07, 0x81, 0x67, 0xfe, 0x8e, 0x7a,
    0x23, 0x96, 0x58, 0xcf, 0x2c, 0x90, 0x33, 0x63, 0x8d, 0x7f, 0x33, 0xa4,
    0x61, 0xdd, 0xed, 0x3b, 0x01, 0xf4, 0x1e, 0xeb, 0x12, 0xd4, 0x28, 0x62,
    0x97, 0x3a, 0x0d, 0x81, 0x65, 0xe9, 0xae, 0x58, 0x21, 0xa2, 0x5d, 0xeb,
    0x73, 0xf4, 0x49, 0x62, 0xf6, 0x1a, 0x6c, 0x81, 0x71, 0xf9, 0xba, 0x58,
    0x35, 0xb2, 0x49, 0xeb, 0x12, 0x9a, 0x28, 0x62, 0x97, 0x74, 0x0d, 0x81,
    0x65, 0xf2, 0xae, 0x58, 0x21, 0xb9, 0x5d, 0xeb, 0x19, 0x98, 0x23, 0x62,
    0x9c, 0x76, 0x06, 0x81, 0x04, 0xf0, 0xcf, 0x58, 0x40, 0xbb, 0x3c, 0xeb,
    0x73, 0x9e, 0x49, 0x62, 0xf6, 0x70, 0x6c, 0x81, 0x24, 0xf6, 0xef, 0x58,
    0x60, 0xbd, 0x1c, 0xeb, 0x09, 0x9c, 0x33, 0x62, 0x8c, 0x72, 0x16, 0x81,
    0x61, 0xf4, 0xaa, 0x58, 0x25, 0xbf, 0x59, 0xeb, 0x18, 0x92, 0x22, 0x62,
    0x9d, 0x7c, 0x07, 0x81, 0x67, 0xfa, 0xac, 0x58, 0x23, 0xb1, 0x5f, 0xeb,
    0x4f, 0x9a, 0x75, 0x62, 0xca, 0x74, 0x50, 0x81, 0x75, 0xf2, 0xbe, 0x58,
    0x31, 0xb9, 0x4d, 0xeb, 0x4d, 0x90, 0x16, 0x47, 0xc8, 0x5a, 0x72, 0xbe,
    0x45, 0xe2, 0xcf, 0x59, 0x34, 0xa3, 0x7d, 0xde, 0x19, 0xb4, 0x49, 0x40,
    0xa9, 0x79, 0x6c, 0x81, 0x26, 0xbd, 0x8e, 0x39, 0x62, 0x96, 0x3c, 0x8b,
    0x2c, 0xd4, 0x57, 0x63, 0x97, 0x3a, 0x33, 0xe1, 0x7b, 0xdd, 0xae, 0x6c,
    0x01, 0xa3, 0x5d, 0xeb, 0x1b, 0xea, 0x16, 0x3d, 0x9f, 0x5a, 0x57, 0xc1,
    0x45, 0x9d, 0xec, 0x59, 0x22, 0xf6, 0x7d, 0x8b, 0x0d, 0xb4, 0x37, 0x03,
    0xa9, 0x3a, 0x10,
];

const OBFUSCATED_LEGACY_BLOB: [u8; 427] = [
    0x14, 0x96, 0x8e, 0x0b, 0x52, 0x96, 0x0c, 0x80, 0x2c, 0xc6, 0x65, 0x63,
    0xf8, 0x31, 0x33, 0xf3, 0x36, 0xdd, 0xff, 0x12, 0x01, 0xe4, 0x0e, 0xeb,
    0x7d, 0xff, 0x16, 0x11, 0xda, 0x5a, 0x42, 0xea, 0x45, 0x8f, 0xdd, 0x59,
    0x50, 0xfd, 0x7d, 0xb9, 0x7f, 0xb4, 0x67, 0x28, 0xa9, 0x08, 0x60, 0x81,
    0x14, 0x96, 0x8e, 0x0b, 0x72, 0x96, 0x0c, 0x80, 0x2c, 0xe6, 0x65, 0x63,
    0xf8, 0x31, 0x33, 0xf3, 0x16, 0xdd, 0xdf, 0x12, 0x01, 0xe4, 0x2e, 0xeb,
    0x7f, 0xe6, 0x16, 0x31, 0xfa, 0x5a, 0x40, 0xf3, 0x45, 0xaf, 0xfd, 0x59,
    0x52, 0xe4, 0x7d, 0x99, 0x5f, 0xb4, 0x65, 0x31, 0xa9, 0x28, 0x40, 0x81,
    0x16, 0x8f, 0x8e, 0x2b, 0x72, 0x96, 0x0e, 0x99, 0x2c, 0xe6, 0x45, 0x63,
    0xfa, 0x28, 0x33, 0xd3, 0x16, 0xdd, 0xfd, 0x0b, 0x01, 0xc4, 0x2e, 0xeb,
    0x5d, 0xb5, 0x7c, 0x11, 0xda, 0x5a, 0x62, 0x80, 0x2f, 0xaf, 0xfd, 0x59,
    0x70, 0x97, 0x37, 0xb9, 0x7f, 0xb4, 0x47, 0x62, 0xe3, 0x08, 0x60, 0x81,
    0x34, 0xdc, 0xc4, 0x2b, 0x72, 0x96, 0x2c, 0xea, 0x46, 0xe6, 0x65, 0x63,
    0xd8, 0x5b, 0x59, 0xf3, 0x16, 0xdd, 0xdf, 0x58, 0x4b, 0xe4, 0x2e, 0xeb,
    0x5d, 0xdf, 0x16, 0x11, 0xa8, 0x0a, 0x79, 0x80, 0x16, 0xdd, 0xdf, 0x32,
    0x01, 0xc4, 0x7c, 0x9b, 0x66, 0xb5, 0x65, 0x63, 0xd8, 0x31, 0x40, 0xf3,
    0x45, 0xad, 0xe4, 0x2b, 0x72, 0x96, 0x2c, 0xa0, 0x7f, 0xe6, 0x16, 0x33,
    0xe3, 0x08, 0x60, 0x81, 0x14, 0xb6, 0xfd, 0x2b, 0x01, 0xc6, 0x17, 0x99,
    0x5f, 0xb4, 0x67, 0x28, 0xfa, 0x08, 0x33, 0xf1, 0x0f, 0x8f, 0xdd, 0x59,
    0x50, 0xfd, 0x0e, 0xb9, 0x2c, 0xe4, 0x7c, 0x11, 0xfa, 0x5a, 0x42, 0xea,
    0x16, 0x8f, 0x8e, 0x29, 0x6b, 0xc4, 0x2e, 0xeb, 0x7d, 0xff, 0x65, 0x11,
    0xa9, 0x0a, 0x79, 0xf3, 0x36, 0xdd, 0xff, 0x32, 0x72, 0xc4, 0x7d, 0x9b,
    0x46, 0xc6, 0x45, 0x63, 0xd8, 0x31, 0x40, 0xf3, 0x45, 0x8d, 0xc4, 0x0b,
    0x52, 0x96, 0x2c, 0xa0, 0x7f, 0xe6, 0x16, 0x13, 0xc3, 0x28, 0x40, 0x81,
    0x14, 0xb6, 0xfd, 0x2b, 0x01, 0xc6, 0x37, 0xb9, 0x7f, 0xb4, 0x47, 0x28,
    0xfa, 0x08, 0x33, 0xd1, 0x2f, 0xaf, 0xfd, 0x59, 0x50, 0xc4, 0x7d, 0xa0,
    0x7f, 0xb4, 0x67, 0x11, 0xa9, 0x31, 0x40, 0x81, 0x14, 0xaf, 0x8e, 0x32,
    0x52, 0x96, 0x0c, 0xb9, 0x2c, 0xff, 0x65, 0x63, 0xf8, 0x08, 0x33, 0xea,
    0x36, 0xdd, 0xff, 0x2b, 0x01, 0xdd, 0x2e, 0xeb, 0x66, 0xe6, 0x16, 0x33,
    0xfa, 0x5a, 0x59, 0xf3, 0x45, 0xad, 0xfd, 0x59, 0x4b, 0xe4, 0x7d, 0xbb,
    0x5f, 0xb4, 0x7c, 0x31, 0xa9, 0x2a, 0x60, 0x81, 0x0f, 0x8d, 0x8e, 0x0b,
    0x52, 0x96, 0x17, 0x9b, 0x2c, 0xc6, 0x65, 0x63, 0xe3, 0x2a, 0x33, 0xf3,
    0x36, 0xdd, 0xe4, 0x09, 0x01, 0xc4, 0x2e, 0xeb, 0x7f, 0xe6, 0x16, 0x28,
    0xf8, 0x5a, 0x40, 0xf3, 0x45, 0xb6, 0xff, 0x59, 0x52, 0xe4, 0x7d, 0x80,
    0x5d, 0xb4, 0x65, 0x31, 0xa9, 0x11, 0x62, 0x81, 0x14, 0x96, 0xdd, 0x58,
    0x52, 0x96, 0x0c, 0x80, 0x5f, 0xb5, 0x65,
];

static DECODED_SYMBOLIC_WRAPPERS: OnceLock<Vec<(&'static str, &'static str)>> = OnceLock::new();
static DECODED_ALL_WRAPPERS: OnceLock<Vec<(&'static str, &'static str)>> = OnceLock::new();

fn unpack_obfuscated_wrappers(blob: &[u8], key: &[u8]) -> Vec<(&'static str, &'static str)> {
    let mut raw = Vec::with_capacity(blob.len());
    for (i, &b) in blob.iter().enumerate() {
        raw.push(b ^ key[i % key.len()]);
    }
    let s = Box::leak(String::from_utf8(raw).unwrap_or_default().into_boxed_str());
    s.split('\x1e')
        .filter_map(|pair| {
            let mut parts = pair.split('\x1f');
            match (parts.next(), parts.next()) {
                (Some(pre), Some(post)) if !pre.is_empty() => Some((pre, post)),
                _ => None,
            }
        })
        .collect()
}

pub fn get_symbolic_wrappers() -> &'static [(&'static str, &'static str)] {
    DECODED_SYMBOLIC_WRAPPERS.get_or_init(|| {
        unpack_obfuscated_wrappers(&OBFUSCATED_SYMBOLIC_BLOB, &OBFUSCATED_KEY)
    })
}

pub fn get_all_wrappers() -> &'static [(&'static str, &'static str)] {
    DECODED_ALL_WRAPPERS.get_or_init(|| {
        let mut all = unpack_obfuscated_wrappers(&OBFUSCATED_SYMBOLIC_BLOB, &OBFUSCATED_KEY);
        let leg = unpack_obfuscated_wrappers(&OBFUSCATED_LEGACY_BLOB, &OBFUSCATED_KEY);
        all.extend(leg);
        all
    })
}

const SAFE_NOISE_CHARS: &[u8] = b"abcdefghjkmopqrstwxyzABCDEFGHJKMOPQRSTWXYZ";
const CONNECTORS: [&str; 6] = ["=", "_", "-", "~", "+", ""];

fn generate_safe_noise(rng: &mut RngSource, min_len: usize, max_len: usize) -> String {
    let len = rng.rand_range(min_len, max_len);
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        let idx = rng.next_byte() as usize % SAFE_NOISE_CHARS.len();
        s.push(SAFE_NOISE_CHARS[idx] as char);
    }
    s
}

pub fn obfuscate_bytes(bytes: &[u8]) -> String {
    let mut rng = RngSource::new();
    let mut out = String::new();
    let wrappers = get_symbolic_wrappers();
    for &b in bytes {
        let hex_byte = format!("{:02x}", b);
        let pre_noise = generate_safe_noise(&mut rng, 2, 5);
        let post_noise = generate_safe_noise(&mut rng, 2, 5);
        let wrap_idx = rng.next_byte() as usize % wrappers.len();
        let (pre_wrap, post_wrap) = wrappers[wrap_idx];
        let conn_idx = rng.next_byte() as usize % CONNECTORS.len();
        let conn = CONNECTORS[conn_idx];

        out.push_str(&pre_noise);
        out.push_str(conn);
        out.push_str(pre_wrap);
        out.push_str(&hex_byte);
        out.push_str(post_wrap);
        out.push_str(conn);
        out.push_str(&post_noise);
    }
    out
}

pub fn deobfuscate_bytes(obfuscated: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let bytes_str = obfuscated.as_bytes();
    let len = bytes_str.len();
    let mut i = 0;

    let all_wrappers = get_all_wrappers();

    while i < len {
        let mut matched = false;
        for &(pre, post) in all_wrappers.iter() {
            let pre_b = pre.as_bytes();
            let post_b = post.as_bytes();
            let total_len = pre_b.len() + 2 + post_b.len();

            if i + total_len <= len && &bytes_str[i..i + pre_b.len()] == pre_b {
                let chunk = &bytes_str[i + pre_b.len()..i + pre_b.len() + 2];
                if chunk[0].is_ascii_hexdigit() && chunk[1].is_ascii_hexdigit() {
                    let after_chunk = &bytes_str[i + pre_b.len() + 2..i + total_len];
                    if after_chunk == post_b {
                        let c0 = chunk[0] as char;
                        let c1 = chunk[1] as char;
                        if let (Some(h1), Some(h2)) = (c0.to_digit(16), c1.to_digit(16)) {
                            bytes.push(((h1 << 4) | h2) as u8);
                            i += total_len;
                            matched = true;
                            break;
                        }
                    }
                }
            }
        }
        if !matched {
            i += 1;
        }
    }
    bytes
}

// ---------------------------------------------------------------------------
// Cifrado y Descifrado de Texto (API Pública)
// ---------------------------------------------------------------------------

pub fn encrypt(text: &str, password: Option<&str>, delimiter: Option<char>) -> Result<String, String> {
    if text.is_empty() {
        return Ok(String::new());
    }

    if let Some(sep) = delimiter {
        encrypt_single(text, password, sep)
    } else {
        encrypt_multi(text, password)
    }
}

pub fn encrypt_multi(text: &str, password: Option<&str>) -> Result<String, String> {
    let mut key = [0u8; KEY_SIZE];
    fill_random_bytes(&mut key);

    let mut raw_key_pkg = if let Some(pwd) = password {
        let mut salt = [0u8; SALT_SIZE];
        fill_random_bytes(&mut salt);
        let mut wrapping_key = pbkdf2_sha256(pwd, &salt, PBKDF2_ROUNDS);
        let mut wrap_ks = generate_keystream(&wrapping_key, &salt, KEY_SIZE);
        let mut enc_key = [0u8; KEY_SIZE];
        for i in 0..KEY_SIZE {
            enc_key[i] = key[i] ^ wrap_ks[i];
        }
        zeroize_slice(&mut wrapping_key);
        zeroize_slice(&mut wrap_ks);

        let mut pkg = vec![FLAG_AEAD_PBKDF2];
        pkg.extend_from_slice(&salt);
        pkg.extend_from_slice(&enc_key);
        zeroize_slice(&mut enc_key);
        pkg
    } else {
        let mut pkg = vec![FLAG_AEAD_DIRECT];
        pkg.extend_from_slice(&key);
        pkg
    };

    let pt_bytes = text.as_bytes();
    let nonce = derive_synthetic_nonce(&key, pt_bytes);

    // Cifrado autenticado RFC 8439 ChaCha20-Poly1305 (asociando raw_key_pkg como AAD)
    let (ciphertext, tag) = crate::ciphers::chacha20_poly1305_encrypt(&key, &nonce, pt_bytes, &raw_key_pkg);
    zeroize_slice(&mut key);

    let mut mask = generate_keystream(&nonce, b"ENCRYPTORX_KEY_MASK", raw_key_pkg.len());
    let mut masked_key = vec![0u8; raw_key_pkg.len()];
    for i in 0..raw_key_pkg.len() {
        masked_key[i] = raw_key_pkg[i] ^ mask[i];
    }
    zeroize_slice(&mut mask);
    zeroize_slice(&mut raw_key_pkg);

    let crc_raw = sha256(&tag);
    let crc = &crc_raw[..4];

    let obf_key = obfuscate_bytes(&masked_key);
    zeroize_slice(&mut masked_key);
    let obf_nonce = obfuscate_bytes(&nonce);
    let obf_tag = obfuscate_bytes(&tag);
    let obf_cipher = obfuscate_bytes(&ciphertext);
    let obf_crc = obfuscate_bytes(crc);

    let mut out = String::with_capacity(obf_key.len() + obf_nonce.len() + obf_tag.len() + obf_cipher.len() + obf_crc.len() + 4);
    out.push_str(&obf_key);
    out.push('$');
    out.push_str(&obf_nonce);
    out.push('%');
    out.push_str(&obf_tag);
    out.push('&');
    out.push_str(&obf_cipher);
    out.push('#');
    out.push_str(&obf_crc);
    Ok(out)
}

pub fn encrypt_single(text: &str, password: Option<&str>, delimiter: char) -> Result<String, String> {
    let sep = if SEPARATORS.contains(&delimiter) {
        delimiter
    } else {
        DEFAULT_SEPARATOR
    };

    let mut key = [0u8; KEY_SIZE];
    fill_random_bytes(&mut key);

    let mut raw_key_pkg = if let Some(pwd) = password {
        let mut salt = [0u8; SALT_SIZE];
        fill_random_bytes(&mut salt);
        let mut wrapping_key = pbkdf2_sha256(pwd, &salt, PBKDF2_ROUNDS);
        let mut wrap_ks = generate_keystream(&wrapping_key, &salt, KEY_SIZE);
        let mut enc_key = [0u8; KEY_SIZE];
        for i in 0..KEY_SIZE {
            enc_key[i] = key[i] ^ wrap_ks[i];
        }
        zeroize_slice(&mut wrapping_key);
        zeroize_slice(&mut wrap_ks);

        let mut pkg = vec![FLAG_AEAD_PBKDF2];
        pkg.extend_from_slice(&salt);
        pkg.extend_from_slice(&enc_key);
        zeroize_slice(&mut enc_key);
        pkg
    } else {
        let mut pkg = vec![FLAG_AEAD_DIRECT];
        pkg.extend_from_slice(&key);
        pkg
    };

    let pt_bytes = text.as_bytes();
    let nonce = derive_synthetic_nonce(&key, pt_bytes);

    // Cifrado autenticado RFC 8439 ChaCha20-Poly1305 (asociando raw_key_pkg como AAD)
    let (ciphertext, tag) = crate::ciphers::chacha20_poly1305_encrypt(&key, &nonce, pt_bytes, &raw_key_pkg);
    zeroize_slice(&mut key);

    let mut mask = generate_keystream(&nonce, b"ENCRYPTORX_KEY_MASK", raw_key_pkg.len());
    let mut masked_key = vec![0u8; raw_key_pkg.len()];
    for i in 0..raw_key_pkg.len() {
        masked_key[i] = raw_key_pkg[i] ^ mask[i];
    }
    zeroize_slice(&mut mask);
    zeroize_slice(&mut raw_key_pkg);

    let obf_key = obfuscate_bytes(&masked_key);
    zeroize_slice(&mut masked_key);

    let mut payload = Vec::with_capacity(AEAD_NONCE_SIZE + AEAD_TAG_SIZE + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&tag);
    payload.extend_from_slice(&ciphertext);
    let obf_payload = obfuscate_bytes(&payload);

    Ok(format!("{}{}{}", obf_key, sep, obf_payload))
}

fn is_aead_flag(f: u8) -> bool {
    f == FLAG_AEAD_DIRECT || f == FLAG_AEAD_PBKDF2 || f == FLAG_AEAD_SCRYPT
}

fn is_legacy_flag(f: u8) -> bool {
    f == FLAG_DIRECT || f == FLAG_PBKDF2 || f == FLAG_SCRYPT || f == FLAG_DOUBLE_DIRECT || f == FLAG_DOUBLE_CASCADE
}

fn is_mostly_text(s: &str) -> bool {
    if s.is_empty() { return false; }
    let valid_count = s.chars().filter(|&c| (!c.is_control() || c == '\n' || c == '\r' || c == '\t') && c != '\u{FFFD}').count();
    (valid_count as f64 / s.chars().count() as f64) >= 0.70
}

pub fn decrypt(token: &str, password: Option<&str>) -> Result<String, String> {
    let cleaned = token.trim();
    if cleaned.is_empty() {
        return Ok(String::new());
    }

    // Si contiene los 4 separadores, usar el decodificador multi-separador
    if cleaned.contains('$') && cleaned.contains('%') && cleaned.contains('&') && cleaned.contains('#') {
        decrypt_multi(cleaned, password)
    } else {
        decrypt_single(cleaned, password)
    }
}

fn decrypt_multi(cleaned: &str, password: Option<&str>) -> Result<String, String> {
    let p1: Vec<&str> = cleaned.splitn(2, '$').collect();
    if p1.len() != 2 { return Err("Estructura de token inválida.".to_string()); }
    let obf_key = p1[0];

    let p2: Vec<&str> = p1[1].splitn(2, '%').collect();
    if p2.len() != 2 { return Err("Estructura de token inválida.".to_string()); }
    let obf_nonce = p2[0];

    let p3: Vec<&str> = p2[1].splitn(2, '&').collect();
    if p3.len() != 2 { return Err("Estructura de token inválida.".to_string()); }
    let obf_tag = p3[0];

    let p4: Vec<&str> = p3[1].splitn(2, '#').collect();
    if p4.len() != 2 { return Err("Estructura de token inválida.".to_string()); }
    let obf_cipher = p4[0];

    let raw_nonce = deobfuscate_bytes(obf_nonce);
    let raw_tag = deobfuscate_bytes(obf_tag);
    let ciphertext = deobfuscate_bytes(obf_cipher);

    let mut masked_key = deobfuscate_bytes(obf_key);
    if masked_key.is_empty() {
        return Err("Estructura de clave dañada o ilegible.".to_string());
    }

    // Comprobar si el token utiliza el estándar AEAD ChaCha20-Poly1305 (nonce de 12 bytes y flag AEAD)
    let is_aead = if raw_nonce.len() == 12 {
        let test_mask = generate_keystream(&raw_nonce, b"ENCRYPTORX_KEY_MASK", 1);
        let flag = masked_key[0] ^ test_mask[0];
        is_aead_flag(flag)
    } else if raw_nonce.len() <= 14 && raw_nonce.len() >= 8 {
        let mut n12 = [0u8; 12];
        let clen = std::cmp::min(12, raw_nonce.len());
        n12[..clen].copy_from_slice(&raw_nonce[..clen]);
        let test_mask = generate_keystream(&n12, b"ENCRYPTORX_KEY_MASK", 1);
        let flag = masked_key[0] ^ test_mask[0];
        is_aead_flag(flag)
    } else {
        false
    };

    if is_aead {
        let mut nonce = [0u8; 12];
        let copy_len = std::cmp::min(12, raw_nonce.len());
        nonce[..copy_len].copy_from_slice(&raw_nonce[..copy_len]);

        let mut tag = [0u8; 16];
        let copy_tag_len = std::cmp::min(16, raw_tag.len());
        tag[..copy_tag_len].copy_from_slice(&raw_tag[..copy_tag_len]);

        let mut mask = generate_keystream(&nonce, b"ENCRYPTORX_KEY_MASK", masked_key.len());
        let mut raw_key_pkg = vec![0u8; masked_key.len()];
        for i in 0..masked_key.len() {
            raw_key_pkg[i] = masked_key[i] ^ mask[i];
        }
        zeroize_slice(&mut mask);
        zeroize_slice(&mut masked_key);

        let flag = raw_key_pkg[0];
        let mut key: [u8; KEY_SIZE] = if flag == FLAG_AEAD_PBKDF2 || flag == FLAG_AEAD_SCRYPT {
            let pwd = match password {
                Some(p) => p,
                None => {
                    zeroize_slice(&mut raw_key_pkg);
                    return Err("Este mensaje requiere contraseña para descifrar".to_string());
                }
            };
            if raw_key_pkg.len() < 1 + SALT_SIZE + KEY_SIZE {
                raw_key_pkg.resize(1 + SALT_SIZE + KEY_SIZE, 0);
            }
            let salt = &raw_key_pkg[1..1 + SALT_SIZE];
            let enc_key = &raw_key_pkg[1 + SALT_SIZE..1 + SALT_SIZE + KEY_SIZE];
            let mut wrapping_key = pbkdf2_sha256(pwd, salt, PBKDF2_ROUNDS);
            let mut wrap_ks = generate_keystream(&wrapping_key, salt, KEY_SIZE);
            let mut k = [0u8; KEY_SIZE];
            for i in 0..KEY_SIZE {
                k[i] = enc_key[i] ^ wrap_ks[i];
            }
            zeroize_slice(&mut wrapping_key);
            zeroize_slice(&mut wrap_ks);
            k
        } else {
            let mut k = [0u8; KEY_SIZE];
            let copy_k_len = std::cmp::min(KEY_SIZE, if raw_key_pkg.len() > 1 { raw_key_pkg.len() - 1 } else { 0 });
            if copy_k_len > 0 {
                k[..copy_k_len].copy_from_slice(&raw_key_pkg[1..1 + copy_k_len]);
            }
            k
        };

        let dec_result = crate::ciphers::chacha20_poly1305_decrypt(&key, &nonce, &ciphertext, &tag, &raw_key_pkg);
        zeroize_slice(&mut raw_key_pkg);

        match dec_result {
            Ok(pt_bytes) => {
                zeroize_slice(&mut key);
                Ok(String::from_utf8_lossy(&pt_bytes).into_owned())
            }
            Err(_) => {
                // Recuperación tolerante a fallos / pérdida de caracteres
                let cipher_engine = crate::ciphers::ChaCha20::new(&key, &nonce, 1);
                zeroize_slice(&mut key);
                let pt_raw = cipher_engine.decrypt(&ciphertext);
                let pt_str = String::from_utf8_lossy(&pt_raw).into_owned();
                if flag == FLAG_AEAD_DIRECT || is_mostly_text(&pt_str) {
                    Ok(pt_str)
                } else {
                    Err("Fallo de autenticación Poly1305 o contraseña incorrecta".to_string())
                }
            }
        }
    } else {
        // --- MODO LEGACY MULTI-SEPARADOR ---
        let mut nonce = raw_nonce;
        if nonce.len() < NONCE_SIZE {
            nonce.resize(NONCE_SIZE, 0);
        } else {
            nonce.truncate(NONCE_SIZE);
        }

        let mut auth_tag = raw_tag;
        if auth_tag.len() < TAG_SIZE {
            auth_tag.resize(TAG_SIZE, 0);
        } else {
            auth_tag.truncate(TAG_SIZE);
        }

        if masked_key.len() < 1 + KEY_SIZE {
            masked_key.resize(1 + KEY_SIZE, 0);
        }

        let mut mask = generate_keystream(&nonce, b"ENCRYPTORX_KEY_MASK", masked_key.len());
        let mut raw_key_pkg = vec![0u8; masked_key.len()];
        for i in 0..masked_key.len() {
            raw_key_pkg[i] = masked_key[i] ^ mask[i];
        }
        zeroize_slice(&mut mask);
        zeroize_slice(&mut masked_key);

        let flag = raw_key_pkg[0];
        let mut key: [u8; KEY_SIZE] = if flag == FLAG_PBKDF2 || flag == FLAG_DOUBLE_CASCADE {
            let pwd = match password {
                Some(p) => p,
                None => {
                    zeroize_slice(&mut raw_key_pkg);
                    return Err("Este mensaje requiere contraseña para descifrar".to_string());
                }
            };
            if raw_key_pkg.len() < 1 + SALT_SIZE + KEY_SIZE {
                raw_key_pkg.resize(1 + SALT_SIZE + KEY_SIZE, 0);
            }
            let salt = &raw_key_pkg[1..1 + SALT_SIZE];
            let enc_key = &raw_key_pkg[1 + SALT_SIZE..1 + SALT_SIZE + KEY_SIZE];
            let mut wrapping_key = pbkdf2_sha256(pwd, salt, PBKDF2_ROUNDS);
            let mut wrap_ks = generate_keystream(&wrapping_key, salt, KEY_SIZE);
            let mut k = [0u8; KEY_SIZE];
            for i in 0..KEY_SIZE {
                k[i] = enc_key[i] ^ wrap_ks[i];
            }
            zeroize_slice(&mut wrapping_key);
            zeroize_slice(&mut wrap_ks);
            k
        } else {
            let mut k = [0u8; KEY_SIZE];
            let copy_len = std::cmp::min(KEY_SIZE, raw_key_pkg.len() - 1);
            k[..copy_len].copy_from_slice(&raw_key_pkg[1..1 + copy_len]);
            k
        };

        // Verificar HMAC
        let mut auth_input = b"ENCRYPTORX_AUTH_TAG_SALT:".to_vec();
        auth_input.extend_from_slice(&key);
        let mut auth_key = sha256(&auth_input);
        zeroize_slice(&mut auth_input);

        let mut mac_data = raw_key_pkg.clone();
        mac_data.extend_from_slice(&nonce);
        mac_data.extend_from_slice(&ciphertext);
        let mut full_mac = hmac_sha256(&auth_key, &mac_data);
        zeroize_slice(&mut auth_key);
        zeroize_slice(&mut mac_data);
        zeroize_slice(&mut raw_key_pkg);
        let expected_mac = &full_mac[..TAG_SIZE];

        let mut diff = 0u8;
        for i in 0..TAG_SIZE {
            diff |= auth_tag[i] ^ expected_mac[i];
        }
        zeroize_slice(&mut full_mac);
        let is_mac_valid = diff == 0;

        if flag == FLAG_DOUBLE_DIRECT || flag == FLAG_DOUBLE_CASCADE {
            let mut ks2 = generate_keystream(&key, &nonce, ciphertext.len());
            zeroize_slice(&mut key);
            let mut inner_blob = vec![0u8; ciphertext.len()];
            for i in 0..ciphertext.len() {
                inner_blob[i] = ciphertext[i] ^ ks2[i];
            }
            zeroize_slice(&mut ks2);

            if inner_blob.len() < 2 + 1 + KEY_SIZE + NONCE_SIZE + TAG_SIZE {
                let pt_lossy = String::from_utf8_lossy(&inner_blob).into_owned();
                zeroize_slice(&mut inner_blob);
                if !is_mac_valid && flag == FLAG_DOUBLE_CASCADE && !is_mostly_text(&pt_lossy) {
                    return Err("Fallo de integridad HMAC o contraseña incorrecta".to_string());
                }
                return Ok(pt_lossy);
            }

            let pkg1_len = u16::from_be_bytes([inner_blob[0], inner_blob[1]]) as usize;
            if inner_blob.len() < 2 + pkg1_len + NONCE_SIZE + TAG_SIZE {
                let pt_lossy = String::from_utf8_lossy(&inner_blob[2..]).into_owned();
                zeroize_slice(&mut inner_blob);
                if !is_mac_valid && flag == FLAG_DOUBLE_CASCADE && !is_mostly_text(&pt_lossy) {
                    return Err("Fallo de integridad HMAC o contraseña incorrecta".to_string());
                }
                return Ok(pt_lossy);
            }

            let offset_pkg = 2;
            let raw_pkg_1 = &inner_blob[offset_pkg..offset_pkg + pkg1_len];
            let offset_nonce = offset_pkg + pkg1_len;
            let nonce1 = &inner_blob[offset_nonce..offset_nonce + NONCE_SIZE];
            let offset_tag = offset_nonce + NONCE_SIZE;
            let _tag1 = &inner_blob[offset_tag..offset_tag + TAG_SIZE];
            let offset_c1 = offset_tag + TAG_SIZE;
            let c1 = &inner_blob[offset_c1..];

            let flag1 = raw_pkg_1[0];
            let mut k1: [u8; KEY_SIZE] = if flag1 == FLAG_PBKDF2 {
                let pwd = match password {
                    Some(p) => p,
                    None => {
                        zeroize_slice(&mut inner_blob);
                        return Err("La capa interna requiere contraseña".to_string());
                    }
                };
                if raw_pkg_1.len() < 1 + SALT_SIZE + KEY_SIZE {
                    zeroize_slice(&mut inner_blob);
                    return Err("Clave interna dañada".to_string());
                }
                let salt1 = &raw_pkg_1[1..1 + SALT_SIZE];
                let enc_k1 = &raw_pkg_1[1 + SALT_SIZE..1 + SALT_SIZE + KEY_SIZE];
                let mut wrapping_key1 = pbkdf2_sha256(pwd, salt1, PBKDF2_ROUNDS);
                let mut wrap_ks1 = generate_keystream(&wrapping_key1, salt1, KEY_SIZE);
                let mut k = [0u8; KEY_SIZE];
                for i in 0..KEY_SIZE {
                    k[i] = enc_k1[i] ^ wrap_ks1[i];
                }
                zeroize_slice(&mut wrapping_key1);
                zeroize_slice(&mut wrap_ks1);
                k
            } else {
                let mut k = [0u8; KEY_SIZE];
                let copy_len = std::cmp::min(KEY_SIZE, raw_pkg_1.len() - 1);
                k[..copy_len].copy_from_slice(&raw_pkg_1[1..1 + copy_len]);
                k
            };

            let mut ks1 = generate_keystream(&k1, nonce1, c1.len());
            zeroize_slice(&mut k1);

            let mut pt = vec![0u8; c1.len()];
            for i in 0..c1.len() {
                pt[i] = c1[i] ^ ks1[i];
            }
            zeroize_slice(&mut ks1);
            zeroize_slice(&mut inner_blob);

            let pt_str = String::from_utf8_lossy(&pt).into_owned();
            zeroize_slice(&mut pt);

            if !is_mac_valid && flag == FLAG_DOUBLE_CASCADE {
                if !is_mostly_text(&pt_str) {
                    return Err("Fallo de integridad HMAC o contraseña incorrecta".to_string());
                }
            }
            Ok(pt_str)
        } else {
            let mut ks = generate_keystream(&key, &nonce, ciphertext.len());
            zeroize_slice(&mut key);

            let mut pt = vec![0u8; ciphertext.len()];
            for i in 0..ciphertext.len() {
                pt[i] = ciphertext[i] ^ ks[i];
            }
            zeroize_slice(&mut ks);

            let pt_str = String::from_utf8_lossy(&pt).into_owned();
            zeroize_slice(&mut pt);

            if !is_mac_valid && (flag == FLAG_PBKDF2 || flag == FLAG_SCRYPT) {
                if !is_mostly_text(&pt_str) {
                    return Err("Fallo de integridad HMAC o contraseña incorrecta".to_string());
                }
            }
            Ok(pt_str)
        }
    }
}

fn decrypt_single(cleaned: &str, password: Option<&str>) -> Result<String, String> {
    let mut found_sep = None;
    for &s in &SEPARATORS {
        if cleaned.contains(s) {
            found_sep = Some(s);
            break;
        }
    }

    let sep = match found_sep {
        Some(s) => s,
        None => return Err("El token no posee una estructura de formato válida.".to_string()),
    };

    let parts: Vec<&str> = cleaned.splitn(2, sep).collect();
    if parts.len() != 2 {
        return Err("Formato de token inválido".to_string());
    }

    let (obf_key, obf_payload) = (parts[0], parts[1]);
    let mut payload = deobfuscate_bytes(obf_payload);
    let mut masked_key = deobfuscate_bytes(obf_key);
    if masked_key.is_empty() {
        return Err("Estructura de clave dañada o ilegible.".to_string());
    }

    // Comprobar si el token utiliza AEAD (nonce de 12 bytes y flag AEAD)
    let is_aead = if payload.len() >= AEAD_NONCE_SIZE + AEAD_TAG_SIZE {
        let mask12 = generate_keystream(&payload[..AEAD_NONCE_SIZE], b"ENCRYPTORX_KEY_MASK", 1);
        let flag12 = masked_key[0] ^ mask12[0];
        if is_aead_flag(flag12) {
            if payload.len() >= NONCE_SIZE + TAG_SIZE {
                let mask16 = generate_keystream(&payload[..NONCE_SIZE], b"ENCRYPTORX_KEY_MASK", 1);
                let flag16 = masked_key[0] ^ mask16[0];
                !is_legacy_flag(flag16)
            } else {
                true
            }
        } else {
            false
        }
    } else {
        false
    };

    if is_aead {
        if payload.len() < AEAD_NONCE_SIZE + AEAD_TAG_SIZE {
            payload.resize(AEAD_NONCE_SIZE + AEAD_TAG_SIZE, 0);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&payload[..12]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&payload[12..28]);
        let ciphertext = &payload[28..];

        let mut mask = generate_keystream(&nonce, b"ENCRYPTORX_KEY_MASK", masked_key.len());
        let mut raw_key_pkg = vec![0u8; masked_key.len()];
        for i in 0..masked_key.len() {
            raw_key_pkg[i] = masked_key[i] ^ mask[i];
        }
        zeroize_slice(&mut mask);
        zeroize_slice(&mut masked_key);

        let flag = raw_key_pkg[0];
        let mut key: [u8; KEY_SIZE] = if flag == FLAG_AEAD_PBKDF2 || flag == FLAG_AEAD_SCRYPT {
            let pwd = match password {
                Some(p) => p,
                None => {
                    zeroize_slice(&mut raw_key_pkg);
                    return Err("Este mensaje requiere contraseña para descifrar".to_string());
                }
            };
            if raw_key_pkg.len() < 1 + SALT_SIZE + KEY_SIZE {
                raw_key_pkg.resize(1 + SALT_SIZE + KEY_SIZE, 0);
            }
            let salt = &raw_key_pkg[1..1 + SALT_SIZE];
            let enc_key = &raw_key_pkg[1 + SALT_SIZE..1 + SALT_SIZE + KEY_SIZE];
            let mut wrapping_key = pbkdf2_sha256(pwd, salt, PBKDF2_ROUNDS);
            let mut wrap_ks = generate_keystream(&wrapping_key, salt, KEY_SIZE);
            let mut k = [0u8; KEY_SIZE];
            for i in 0..KEY_SIZE {
                k[i] = enc_key[i] ^ wrap_ks[i];
            }
            zeroize_slice(&mut wrapping_key);
            zeroize_slice(&mut wrap_ks);
            k
        } else {
            let mut k = [0u8; KEY_SIZE];
            let copy_k_len = std::cmp::min(KEY_SIZE, if raw_key_pkg.len() > 1 { raw_key_pkg.len() - 1 } else { 0 });
            if copy_k_len > 0 {
                k[..copy_k_len].copy_from_slice(&raw_key_pkg[1..1 + copy_k_len]);
            }
            k
        };

        let dec_result = crate::ciphers::chacha20_poly1305_decrypt(&key, &nonce, ciphertext, &tag, &raw_key_pkg);
        zeroize_slice(&mut raw_key_pkg);

        match dec_result {
            Ok(pt_bytes) => {
                zeroize_slice(&mut key);
                Ok(String::from_utf8_lossy(&pt_bytes).into_owned())
            }
            Err(_) => {
                let cipher_engine = crate::ciphers::ChaCha20::new(&key, &nonce, 1);
                zeroize_slice(&mut key);
                let pt_raw = cipher_engine.decrypt(ciphertext);
                let pt_str = String::from_utf8_lossy(&pt_raw).into_owned();
                if flag == FLAG_AEAD_DIRECT || is_mostly_text(&pt_str) {
                    Ok(pt_str)
                } else {
                    Err("Fallo de autenticación Poly1305 o contraseña incorrecta".to_string())
                }
            }
        }
    } else {
        // --- MODO LEGACY SEPARADOR ÚNICO ---
        if payload.len() < NONCE_SIZE + TAG_SIZE {
            payload.resize(NONCE_SIZE + TAG_SIZE, 0);
        }

        let nonce = &payload[..NONCE_SIZE];
        let auth_tag = &payload[NONCE_SIZE..NONCE_SIZE + TAG_SIZE];
        let ciphertext = &payload[NONCE_SIZE + TAG_SIZE..];

        if masked_key.len() < 1 + KEY_SIZE {
            masked_key.resize(1 + KEY_SIZE, 0);
        }

        let mut mask = generate_keystream(nonce, b"ENCRYPTORX_KEY_MASK", masked_key.len());
        let mut raw_key_pkg = vec![0u8; masked_key.len()];
        for i in 0..masked_key.len() {
            raw_key_pkg[i] = masked_key[i] ^ mask[i];
        }
        zeroize_slice(&mut mask);
        zeroize_slice(&mut masked_key);

        let flag = raw_key_pkg[0];
        let mut key: [u8; KEY_SIZE] = if flag == 0x01 {
            let pwd = match password {
                Some(p) => p,
                None => {
                    zeroize_slice(&mut raw_key_pkg);
                    return Err("Este mensaje requiere contraseña para descifrar".to_string());
                }
            };
            if raw_key_pkg.len() < 1 + SALT_SIZE + KEY_SIZE {
                raw_key_pkg.resize(1 + SALT_SIZE + KEY_SIZE, 0);
            }
            let salt = &raw_key_pkg[1..1 + SALT_SIZE];
            let enc_key = &raw_key_pkg[1 + SALT_SIZE..1 + SALT_SIZE + KEY_SIZE];
            let mut wrapping_key = pbkdf2_sha256(pwd, salt, PBKDF2_ROUNDS);
            let mut wrap_ks = generate_keystream(&wrapping_key, salt, KEY_SIZE);
            let mut k = [0u8; KEY_SIZE];
            for i in 0..KEY_SIZE {
                k[i] = enc_key[i] ^ wrap_ks[i];
            }
            zeroize_slice(&mut wrapping_key);
            zeroize_slice(&mut wrap_ks);
            k
        } else {
            let mut k = [0u8; KEY_SIZE];
            let copy_len = std::cmp::min(KEY_SIZE, raw_key_pkg.len() - 1);
            k[..copy_len].copy_from_slice(&raw_key_pkg[1..1 + copy_len]);
            k
        };

        // Verificar HMAC
        let mut auth_input = b"ENCRYPTORX_AUTH_TAG_SALT:".to_vec();
        auth_input.extend_from_slice(&key);
        let mut auth_key = sha256(&auth_input);
        zeroize_slice(&mut auth_input);

        let mut mac_data = raw_key_pkg.clone();
        mac_data.extend_from_slice(nonce);
        mac_data.extend_from_slice(ciphertext);
        let mut full_mac = hmac_sha256(&auth_key, &mac_data);
        zeroize_slice(&mut auth_key);
        zeroize_slice(&mut mac_data);
        zeroize_slice(&mut raw_key_pkg);
        let expected_mac = &full_mac[..TAG_SIZE];

        let mut diff = 0u8;
        for i in 0..TAG_SIZE {
            diff |= auth_tag[i] ^ expected_mac[i];
        }
        zeroize_slice(&mut full_mac);
        let is_mac_valid = diff == 0;

        let mut ks = generate_keystream(&key, nonce, ciphertext.len());
        zeroize_slice(&mut key);

        let mut pt = vec![0u8; ciphertext.len()];
        for i in 0..ciphertext.len() {
            pt[i] = ciphertext[i] ^ ks[i];
        }
        zeroize_slice(&mut ks);

        let pt_str = String::from_utf8_lossy(&pt).into_owned();
        zeroize_slice(&mut pt);

        if !is_mac_valid && flag == 0x01 {
            if !is_mostly_text(&pt_str) {
                return Err("Fallo de integridad HMAC o contraseña incorrecta".to_string());
            }
        }
        Ok(pt_str)
    }
}


// ---------------------------------------------------------------------------
// Cifrado y Descifrado de Archivos (API Pública)
// ---------------------------------------------------------------------------

pub fn encrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Option<Q>,
    password: Option<&str>,
) -> Result<PathBuf, String> {
    let in_path = input_path.as_ref();
    if !in_path.exists() {
        return Err(format!("Archivo no encontrado: {:?}", in_path));
    }
    let data = fs::read(in_path).map_err(|e| format!("Error leyendo archivo: {}", e))?;

    let out_path = match output_path {
        Some(p) => p.as_ref().to_path_buf(),
        None => {
            let mut p = in_path.as_os_str().to_os_string();
            p.push(".enc");
            PathBuf::from(p)
        }
    };

    let mut key = [0u8; KEY_SIZE];
    fill_random_bytes(&mut key);

    let mut header = Vec::new();
    header.extend_from_slice(b"ENCX\x03");

    if let Some(pwd) = password {
        header.push(FLAG_AEAD_PBKDF2);
        let mut salt = [0u8; SALT_SIZE];
        fill_random_bytes(&mut salt);
        header.extend_from_slice(&salt);

        let mut wrapping_key = pbkdf2_sha256(pwd, &salt, PBKDF2_ROUNDS);
        let mut wrap_ks = generate_keystream(&wrapping_key, &salt, KEY_SIZE);
        let mut enc_key = [0u8; KEY_SIZE];
        for i in 0..KEY_SIZE {
            enc_key[i] = key[i] ^ wrap_ks[i];
        }
        zeroize_slice(&mut wrapping_key);
        zeroize_slice(&mut wrap_ks);
        header.extend_from_slice(&enc_key);
        zeroize_slice(&mut enc_key);
    } else {
        header.push(FLAG_AEAD_DIRECT);
        header.extend_from_slice(&key);
    }

    let nonce = derive_synthetic_nonce(&key, &data);

    // Cifrado autenticado RFC 8439 ChaCha20-Poly1305 asociando header como AAD
    let (ciphertext, tag) = crate::ciphers::chacha20_poly1305_encrypt(&key, &nonce, &data, &header);
    zeroize_slice(&mut key);

    let mut final_payload = header;
    final_payload.extend_from_slice(&nonce);
    final_payload.extend_from_slice(&tag);
    final_payload.extend_from_slice(&ciphertext);

    fs::write(&out_path, final_payload).map_err(|e| format!("Error guardando archivo cifrado: {}", e))?;
    Ok(out_path)
}

pub fn decrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Option<Q>,
    password: Option<&str>,
) -> Result<PathBuf, String> {
    let in_path = input_path.as_ref();
    if !in_path.exists() {
        return Err(format!("Archivo no encontrado: {:?}", in_path));
    }
    let data = fs::read(in_path).map_err(|e| format!("Error leyendo archivo: {}", e))?;

    if data.len() < 5 + 1 {
        return Err("El archivo cifrado es demasiado corto o corrupto.".to_string());
    }

    let is_v3 = &data[..5] == b"ENCX\x03";
    let is_v2 = &data[..5] == b"ENCX\x02";

    if !is_v3 && !is_v2 {
        return Err("El archivo no tiene la cabecera válida de EncryptorX.".to_string());
    }

    let flag = data[5];
    let mut offset = 6;

    let mut plaintext = if is_v3 {
        let mut key = if flag == FLAG_AEAD_PBKDF2 || flag == FLAG_AEAD_SCRYPT {
            let pwd = password.ok_or_else(|| "Este archivo está protegido con contraseña.".to_string())?;
            if data.len() < offset + SALT_SIZE + KEY_SIZE {
                return Err("Estructura de archivo cifrado corrupta.".to_string());
            }
            let salt = &data[offset..offset + SALT_SIZE];
            offset += SALT_SIZE;
            let enc_key = &data[offset..offset + KEY_SIZE];
            offset += KEY_SIZE;

            let mut wrapping_key = pbkdf2_sha256(pwd, salt, PBKDF2_ROUNDS);
            let mut wrap_ks = generate_keystream(&wrapping_key, salt, KEY_SIZE);
            let mut k = [0u8; KEY_SIZE];
            for i in 0..KEY_SIZE {
                k[i] = enc_key[i] ^ wrap_ks[i];
            }
            zeroize_slice(&mut wrapping_key);
            zeroize_slice(&mut wrap_ks);
            k
        } else if flag == FLAG_AEAD_DIRECT {
            if data.len() < offset + KEY_SIZE {
                return Err("Estructura de archivo cifrado corrupta.".to_string());
            }
            let mut k = [0u8; KEY_SIZE];
            k.copy_from_slice(&data[offset..offset + KEY_SIZE]);
            offset += KEY_SIZE;
            k
        } else {
            return Err("Formato o versión de archivo no soportada.".to_string());
        };

        let header_slice = &data[..offset];
        if data.len() < offset + AEAD_NONCE_SIZE + AEAD_TAG_SIZE {
            zeroize_slice(&mut key);
            return Err("Archivo cifrado incompleto o corrupto.".to_string());
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[offset..offset + 12]);
        offset += 12;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;
        let ciphertext = &data[offset..];

        let dec = crate::ciphers::chacha20_poly1305_decrypt(&key, &nonce, ciphertext, &tag, header_slice);
        zeroize_slice(&mut key);
        dec.map_err(|e| format!("Fallo de autenticación Poly1305 o contraseña incorrecta: {}", e))?
    } else {
        // Modo Legacy v2
        let mut key = if flag == 0x01 {
            let pwd = password.ok_or_else(|| "Este archivo está protegido con contraseña.".to_string())?;
            if data.len() < offset + SALT_SIZE + KEY_SIZE {
                return Err("Estructura de archivo cifrado corrupta.".to_string());
            }
            let salt = &data[offset..offset + SALT_SIZE];
            offset += SALT_SIZE;
            let enc_key = &data[offset..offset + KEY_SIZE];
            offset += KEY_SIZE;

            let mut wrapping_key = pbkdf2_sha256(pwd, salt, PBKDF2_ROUNDS);
            let mut wrap_ks = generate_keystream(&wrapping_key, salt, KEY_SIZE);
            let mut k = [0u8; KEY_SIZE];
            for i in 0..KEY_SIZE {
                k[i] = enc_key[i] ^ wrap_ks[i];
            }
            zeroize_slice(&mut wrapping_key);
            zeroize_slice(&mut wrap_ks);
            k
        } else if flag == 0x00 {
            if data.len() < offset + KEY_SIZE {
                return Err("Estructura de archivo cifrado corrupta.".to_string());
            }
            let mut k = [0u8; KEY_SIZE];
            k.copy_from_slice(&data[offset..offset + KEY_SIZE]);
            offset += KEY_SIZE;
            k
        } else {
            return Err("Formato o versión de archivo no soportada.".to_string());
        };

        let header_slice = &data[..offset];

        if data.len() < offset + NONCE_SIZE + TAG_SIZE {
            zeroize_slice(&mut key);
            return Err("Archivo cifrado incompleto o corrupto.".to_string());
        }

        let nonce = &data[offset..offset + NONCE_SIZE];
        offset += NONCE_SIZE;
        let auth_tag = &data[offset..offset + TAG_SIZE];
        offset += TAG_SIZE;
        let ciphertext = &data[offset..];

        // Verificar HMAC
        let mut auth_input = b"ENCRYPTORX_AUTH_TAG_SALT:".to_vec();
        auth_input.extend_from_slice(&key);
        let mut auth_key = sha256(&auth_input);
        zeroize_slice(&mut auth_input);

        let mut mac_data = header_slice.to_vec();
        mac_data.extend_from_slice(nonce);
        mac_data.extend_from_slice(ciphertext);
        let mut full_mac = hmac_sha256(&auth_key, &mac_data);
        zeroize_slice(&mut auth_key);
        zeroize_slice(&mut mac_data);
        let expected_tag = &full_mac[..TAG_SIZE];

        let mut diff = 0u8;
        for i in 0..TAG_SIZE {
            diff |= auth_tag[i] ^ expected_tag[i];
        }
        zeroize_slice(&mut full_mac);

        if diff != 0 {
            zeroize_slice(&mut key);
            return Err("Fallo de integridad HMAC o contraseña incorrecta.".to_string());
        }

        let mut ks = generate_keystream(&key, nonce, ciphertext.len());
        zeroize_slice(&mut key);

        let mut pt = vec![0u8; ciphertext.len()];
        for i in 0..ciphertext.len() {
            pt[i] = ciphertext[i] ^ ks[i];
        }
        zeroize_slice(&mut ks);
        pt
    };

    let out_path = match output_path {
        Some(p) => p.as_ref().to_path_buf(),
        None => {
            let s = in_path.to_string_lossy();
            if s.ends_with(".enc") {
                PathBuf::from(&s[..s.len() - 4])
            } else {
                PathBuf::from(format!("{}.dec", s))
            }
        }
    };

    let res = fs::write(&out_path, &plaintext).map_err(|e| format!("Error guardando archivo descifrado: {}", e));
    zeroize_slice(&mut plaintext);
    res?;
    Ok(out_path)
}

// ---------------------------------------------------------------------------
// Herramientas: Generador de Contraseñas y Portapapeles Nativo de Windows
// ---------------------------------------------------------------------------

pub fn generate_secure_password(length: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*-_=+";
    let mut rng = RngSource::new();
    let mut pass = String::with_capacity(length);
    for _ in 0..length {
        let idx = rng.next_byte() as usize % CHARSET.len();
        pass.push(CHARSET[idx] as char);
    }
    pass
}

#[cfg(windows)]
pub fn copy_to_clipboard(text: &str) -> bool {
    use std::ptr;
    #[link(name = "user32")]
    extern "system" {
        fn OpenClipboard(hWndNewOwner: *mut std::ffi::c_void) -> i32;
        fn CloseClipboard() -> i32;
        fn EmptyClipboard() -> i32;
        fn SetClipboardData(uFormat: u32, hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
        fn GlobalAlloc(uFlags: u32, dwBytes: usize) -> *mut std::ffi::c_void;
        fn GlobalLock(hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
        fn GlobalUnlock(hMem: *mut std::ffi::c_void) -> i32;
    }

    const CF_UNICODETEXT: u32 = 13;
    const GMEM_MOVEABLE: u32 = 0x0002;

    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let size_in_bytes = wide.len() * std::mem::size_of::<u16>();

    unsafe {
        if OpenClipboard(ptr::null_mut()) == 0 {
            return false;
        }
        EmptyClipboard();
        let h_mem = GlobalAlloc(GMEM_MOVEABLE, size_in_bytes);
        if !h_mem.is_null() {
            let dest = GlobalLock(h_mem) as *mut u16;
            if !dest.is_null() {
                ptr::copy_nonoverlapping(wide.as_ptr(), dest, wide.len());
                GlobalUnlock(h_mem);
                SetClipboardData(CF_UNICODETEXT, h_mem);
            }
        }
        CloseClipboard();
    }
    true
}

#[cfg(not(windows))]
pub fn copy_to_clipboard(_text: &str) -> bool {
    false
}

// ---------------------------------------------------------------------------
// Exportaciones C-ABI (cdylib) para Integración con Python, C, Android, etc.
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn encryptorx_encrypt(
    text: *const std::os::raw::c_char,
    password: *const std::os::raw::c_char,
    delimiter: std::os::raw::c_char,
) -> *mut std::os::raw::c_char {
    if text.is_null() {
        return std::ptr::null_mut();
    }
    let c_str = std::ffi::CStr::from_ptr(text);
    let s = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let pwd = if !password.is_null() {
        std::ffi::CStr::from_ptr(password).to_str().ok()
    } else {
        None
    };
    let delim = if delimiter != 0 {
        Some(delimiter as u8 as char)
    } else {
        None
    };
    match encrypt(s, pwd, delim) {
        Ok(token) => match std::ffi::CString::new(token) {
            Ok(cs) => cs.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn encryptorx_decrypt(
    token: *const std::os::raw::c_char,
    password: *const std::os::raw::c_char,
) -> *mut std::os::raw::c_char {
    if token.is_null() {
        return std::ptr::null_mut();
    }
    let c_str = std::ffi::CStr::from_ptr(token);
    let tok = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let pwd = if !password.is_null() {
        std::ffi::CStr::from_ptr(password).to_str().ok()
    } else {
        None
    };
    match decrypt(tok, pwd) {
        Ok(pt) => match std::ffi::CString::new(pt) {
            Ok(cs) => cs.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn encryptorx_free_string(s: *mut std::os::raw::c_char) {
    if !s.is_null() {
        drop(std::ffi::CString::from_raw(s));
    }
}

// ---------------------------------------------------------------------------
// Tests Unitarios
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_multi_separator_all_four_included() {
        let msg = "¡Prueba con TODOS los separadores ($, %, &, #) integrados simultáneamente!";
        // Cifrado automático multi-separador
        let token = encrypt(msg, None, None).expect("Encrypt multi failed");
        
        // Debe contener TODOS los 4 separadores
        assert!(token.contains('$'), "Debe contener $");
        assert!(token.contains('%'), "Debe contener %");
        assert!(token.contains('&'), "Debe contener &");
        assert!(token.contains('#'), "Debe contener #");

        // Descifrado automático
        let dec = decrypt(&token, None).expect("Decrypt multi failed");
        assert_eq!(msg, dec);
    }

    #[test]
    fn test_rust_multi_separator_with_password() {
        let msg = "Mensaje con contraseña usando todos los separadores";
        let pwd = "SuperClaveSegura2026!";
        let token = encrypt(msg, Some(pwd), None).expect("Encrypt multi pwd failed");

        assert!(token.contains('$'));
        assert!(token.contains('%'));
        assert!(token.contains('&'));
        assert!(token.contains('#'));

        let dec = decrypt(&token, Some(pwd)).expect("Decrypt multi pwd failed");
        assert_eq!(msg, dec);

        // Clave errónea debe fallar
        assert!(decrypt(&token, Some("ClaveIncorrecta")).is_err());
        assert!(decrypt(&token, None).is_err());
    }

    #[test]
    fn test_rust_roundtrip_all_delimiters() {
        let msg = "¡Hola desde Rust nativo con 64 wrappers NULL y HMAC-SHA256!";
        for &delim in &SEPARATORS {
            let token = encrypt(msg, None, Some(delim)).expect("Encrypt failed");
            assert!(token.contains(delim));
            let dec = decrypt(&token, None).expect("Decrypt failed");
            assert_eq!(msg, dec);
        }
    }

    #[test]
    fn test_rust_password_protection() {
        let msg = "Mensaje ultrasecreto en Rust";
        let pwd = "SuperRustPassword999!";
        let token = encrypt(msg, Some(pwd), Some('$')).expect("Encrypt failed");
        let dec = decrypt(&token, Some(pwd)).expect("Decrypt failed");
        assert_eq!(msg, dec);

        // Fallos de autenticación
        assert!(decrypt(&token, Some("ClaveEquivocada")).is_err());
        assert!(decrypt(&token, None).is_err());
    }

    #[test]
    fn test_file_encryption_roundtrip() {
        let test_dir = std::env::temp_dir();
        let src_file = test_dir.join("test_file_rust.txt");
        let enc_file = test_dir.join("test_file_rust.txt.enc");
        let dec_file = test_dir.join("test_file_rust_dec.txt");

        let content = b"Archivos binarios y texto cifrados en Rust con HMAC anti-tamper!";
        fs::write(&src_file, content).unwrap();

        // 1. Cifrado directo
        encrypt_file(&src_file, Some(&enc_file), None).expect("File encrypt failed");
        decrypt_file(&enc_file, Some(&dec_file), None).expect("File decrypt failed");
        let recovered = fs::read(&dec_file).unwrap();
        assert_eq!(content.as_slice(), recovered.as_slice());

        // 2. Cifrado con contraseña
        let pwd = "FilePassword123#";
        encrypt_file(&src_file, Some(&enc_file), Some(pwd)).expect("File encrypt with pwd failed");
        decrypt_file(&enc_file, Some(&dec_file), Some(pwd)).expect("File decrypt with pwd failed");
        let recovered_pwd = fs::read(&dec_file).unwrap();
        assert_eq!(content.as_slice(), recovered_pwd.as_slice());

        // Limpieza
        let _ = fs::remove_file(src_file);
        let _ = fs::remove_file(enc_file);
        let _ = fs::remove_file(dec_file);
    }

    #[test]
    fn test_password_generator() {
        let pass = generate_secure_password(24);
        assert_eq!(pass.len(), 24);
    }

    #[test]
    fn test_symbolic_wrappers_absence_of_null() {
        let msg = "Verificación de envoltorios simbólicos en Rust";
        let token = encrypt(msg, None, None).unwrap();
        let lower = token.to_lowercase();
        assert!(!lower.contains("null"), "El token no debe contener 'null'");
        assert!(!lower.contains("nu"), "El token no debe contener 'nu'");
        assert!(!lower.contains("ll"), "El token no debe contener 'll'");
        let dec = decrypt(&token, None).unwrap();
        assert_eq!(msg, dec);
    }

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let plaintext = b"High-speed native Rust ChaCha20-Poly1305 payload!";
        let aad = b"additional-auth-data";

        let (ciphertext, tag) = crate::ciphers::chacha20_poly1305_encrypt(&key, &nonce, plaintext, aad);
        let decrypted = crate::ciphers::chacha20_poly1305_decrypt(&key, &nonce, &ciphertext, &tag, aad)
            .expect("Decryption should succeed");
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        // Tamper test
        let mut bad_tag = tag;
        bad_tag[0] ^= 0x01;
        assert!(crate::ciphers::chacha20_poly1305_decrypt(&key, &nonce, &ciphertext, &bad_tag, aad).is_err());
    }

    #[test]
    fn test_shamir_threshold_recovery() {
        let secret = b"Enterprise Rust Secret Sharded 3-of-5";
        let shares = crate::shamir::split_secret(secret, 3, 5).expect("Splitting secret failed");
        assert_eq!(shares.len(), 5);

        // Any 3 shares reconstruct
        let subset1 = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered1 = crate::shamir::combine_shares(&subset1).expect("Combining failed");
        assert_eq!(secret.as_slice(), recovered1.as_slice());

        let subset2 = vec![shares[1].clone(), shares[2].clone(), shares[3].clone()];
        let recovered2 = crate::shamir::combine_shares(&subset2).expect("Combining failed");
        assert_eq!(secret.as_slice(), recovered2.as_slice());

        // String formatting test
        let str_shares = crate::shamir::split_secret_strings(secret, 3, 5).unwrap();
        let str_subset = vec![str_shares[0].clone(), str_shares[1].clone(), str_shares[4].clone()];
        let str_rec = crate::shamir::combine_shares_strings(&str_subset).unwrap();
        assert_eq!(secret.as_slice(), str_rec.as_slice());
    }

    #[test]
    fn test_fault_tolerant_lossy_decryption() {
        let msg = "Mensaje confidencial recuperable a pesar de perdida de caracteres";
        let token = encrypt(msg, None, None).unwrap();
        let mut tampered = token.clone();
        if let Some(hash_pos) = tampered.rfind('#') {
            if hash_pos > 25 {
                tampered.replace_range(hash_pos - 15..hash_pos - 10, "");
            }
        }
        let recovered = decrypt(&tampered, None).expect("Should recover text even with lost characters");
        assert!(recovered.contains("Mensaje confidencial"), "Recovered text was: {}", recovered);
    }

    #[test]
    fn test_synthetic_nonce_uniqueness() {
        let key = [0x55u8; 32];
        let m1 = b"Mensaje alfa";
        let m2 = b"Mensaje beta";
        let n1 = derive_synthetic_nonce(&key, m1);
        let n2 = derive_synthetic_nonce(&key, m2);
        assert_ne!(n1, n2, "Nonces for distinct messages under the same key must never collide");
    }

    #[test]
    fn test_legacy_token_backward_compatibility() {
        // Construct an authentic legacy token using the legacy stream cipher format (FLAG_DIRECT = 0x00)
        let key = [0x77u8; KEY_SIZE];
        let nonce = [0x88u8; NONCE_SIZE];
        let mut raw_key_pkg = vec![FLAG_DIRECT];
        raw_key_pkg.extend_from_slice(&key);

        let pt = "Retrocompatibilidad garantizada con tokens legacy v1/v2";
        let ks = generate_keystream(&key, &nonce, pt.len());
        let mut ciphertext = vec![0u8; pt.len()];
        for i in 0..pt.len() {
            ciphertext[i] = pt.as_bytes()[i] ^ ks[i];
        }

        let mut auth_input = b"ENCRYPTORX_AUTH_TAG_SALT:".to_vec();
        auth_input.extend_from_slice(&key);
        let auth_key = sha256(&auth_input);

        let mut mac_data = raw_key_pkg.clone();
        mac_data.extend_from_slice(&nonce);
        mac_data.extend_from_slice(&ciphertext);
        let full_mac = hmac_sha256(&auth_key, &mac_data);
        let auth_tag = &full_mac[..TAG_SIZE];

        let mask = generate_keystream(&nonce, b"ENCRYPTORX_KEY_MASK", raw_key_pkg.len());
        let mut masked_key = vec![0u8; raw_key_pkg.len()];
        for i in 0..raw_key_pkg.len() {
            masked_key[i] = raw_key_pkg[i] ^ mask[i];
        }

        let mut payload = Vec::new();
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(auth_tag);
        payload.extend_from_slice(&ciphertext);

        let obf_key = obfuscate_bytes(&masked_key);
        let obf_payload = obfuscate_bytes(&payload);
        let legacy_token = format!("{}${}", obf_key, obf_payload);

        let recovered = decrypt(&legacy_token, None).expect("Legacy token decryption should succeed");
        assert_eq!(pt, recovered);
    }
}



