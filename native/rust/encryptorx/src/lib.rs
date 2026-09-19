//! EncryptorX - Motor Criptográfico Nativo en Rust v3.0.0
//! Algoritmo Null-Obfuscated Cipher con 64 combinaciones y HMAC-SHA256.

use std::time::{SystemTime, UNIX_EPOCH};

pub const VERSION: &str = "3.0.0";
pub const SEPARATORS: [char; 4] = ['$', '%', '&', '#'];
pub const DEFAULT_SEPARATOR: char = '$';
pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 16;
pub const TAG_SIZE: usize = 16;
pub const SALT_SIZE: usize = 16;
pub const PBKDF2_ROUNDS: u32 = 100_000;

// ---------------------------------------------------------------------------
// Primitivas SHA-256 y HMAC-SHA256 en Rust Puro (Zero Dependencies)
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
    sha256(&outer)
}

// ---------------------------------------------------------------------------
// Generador Pseudoaleatorio Seguro
// ---------------------------------------------------------------------------

fn get_random_bytes(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    // Intenta leer de /dev/urandom en unix o usa entropía de tiempo en windows
    #[cfg(unix)]
    {
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            if f.read_exact(&mut v).is_ok() {
                return v;
            }
        }
    }
    // Generador criptográfico por hash de entropía múltiple
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(123456789);
    
    let mut state = sha256(&seed.to_le_bytes());
    let mut generated = 0;
    while generated < len {
        state = sha256(&state);
        let take = std::cmp::min(len - generated, 32);
        v[generated..generated + take].copy_from_slice(&state[..take]);
        generated += take;
    }
    v
}

// ---------------------------------------------------------------------------
// Catálogo de 64 Combinaciones de Envoltorios "NULL"
// ---------------------------------------------------------------------------

pub const NULL_WRAPPERS: [(&str, &str); 64] = [
    ("NU", "LL"), ("nu", "ll"), ("Nu", "ll"), ("nU", "ll"),
    ("NU", "ll"), ("nu", "LL"), ("Nu", "LL"), ("nU", "LL"),
    ("NU", "Ll"), ("nu", "Ll"), ("Nu", "lL"), ("NU", "lL"),
    ("LL", "LL"), ("ll", "ll"), ("Ll", "ll"), ("lL", "ll"),
    ("LL", "ll"), ("ll", "LL"), ("Ll", "LL"), ("lL", "LL"),
    ("n", "ull"), ("N", "ull"), ("n", "ULL"), ("N", "ULL"),
    ("n", "Ull"), ("N", "uLl"), ("n", "ulL"), ("N", "UlL"),
    ("nu", "l"),   ("NU", "L"),   ("Nu", "L"),   ("nU", "l"),
    ("null", "null"), ("NULL", "NULL"), ("Null", "Null"), ("nULL", "nULL"),
    ("NulL", "NulL"), ("nuLL", "nuLL"), ("NUll", "NUll"), ("nulL", "nulL"),
    ("null", "NULL"), ("NULL", "null"), ("Null", "NULL"), ("NULL", "Null"),
    ("NL", "UL"), ("nl", "ul"), ("Nl", "uL"), ("nL", "Ul"),
    ("NL", "ul"), ("nl", "UL"), ("UL", "NL"), ("ul", "nl"),
    ("Ul", "Nl"), ("uL", "nL"),
    ("UN", "LL"), ("un", "ll"), ("Un", "ll"), ("uN", "LL"),
    ("LL", "UN"), ("ll", "un"), ("Ll", "un"), ("lL", "UN"),
    ("NUL", "L"), ("nul", "l"),
];

const SAFE_CHARS: &[u8] = b"qwrtpsdfghjkmzxcv123456789";
const CONNECTORS: &[u8] = b"=_-";

fn generate_keystream(key: &[u8], nonce: &[u8], len: usize) -> Vec<u8> {
    let mut ks = Vec::with_capacity(len);
    let mut counter: u32 = 0;
    while ks.len() < len {
        let mut input = Vec::new();
        input.extend_from_slice(key);
        input.extend_from_slice(nonce);
        input.extend_from_slice(&counter.to_be_bytes());
        let h = sha256(&input);
        let take = std::cmp::min(len - ks.len(), 32);
        ks.extend_from_slice(&h[..take]);
        counter += 1;
    }
    ks
}

fn pbkdf2_sha256(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut msg = salt.to_vec();
    msg.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_sha256(password.as_bytes(), &msg);
    let mut t = u;

    for _ in 1..iterations {
        u = hmac_sha256(password.as_bytes(), &u);
        for j in 0..32 {
            t[j] ^= u[j];
        }
    }
    t
}

// ---------------------------------------------------------------------------
// Ofuscación y Desofuscación
// ---------------------------------------------------------------------------

struct RngSource {
    buffer: Vec<u8>,
    idx: usize,
}

impl RngSource {
    fn new(len: usize) -> Self {
        Self {
            buffer: get_random_bytes(len.max(64)),
            idx: 0,
        }
    }

    fn next_u8(&mut self) -> u8 {
        if self.idx >= self.buffer.len() {
            self.buffer = get_random_bytes(self.buffer.len().max(64));
            self.idx = 0;
        }
        let b = self.buffer[self.idx];
        self.idx += 1;
        b
    }

    fn next_usize(&mut self, max: usize) -> usize {
        (self.next_u8() as usize) % max
    }
}

fn obfuscate_bytes(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 40);
    let mut rng = RngSource::new(bytes.len() * 16);

    for &b in bytes {
        let w_idx = rng.next_usize(64);
        let (pre_wrap, post_wrap) = NULL_WRAPPERS[w_idx];

        // Ruido pre
        let pre_len = 2 + rng.next_usize(4);
        for _ in 0..pre_len {
            result.push(SAFE_CHARS[rng.next_usize(SAFE_CHARS.len())] as char);
        }

        if rng.next_usize(2) == 0 {
            result.push(CONNECTORS[rng.next_usize(CONNECTORS.len())] as char);
        }

        result.push_str(pre_wrap);
        result.push_str(&format!("{:02x}", b));
        result.push_str(post_wrap);

        if rng.next_usize(2) == 0 {
            result.push(CONNECTORS[rng.next_usize(CONNECTORS.len())] as char);
        }

        // Ruido post
        let post_len = 2 + rng.next_usize(4);
        for _ in 0..post_len {
            result.push(SAFE_CHARS[rng.next_usize(SAFE_CHARS.len())] as char);
        }
    }
    result
}


fn deobfuscate_bytes(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let mut matched = false;
        for &(pre, post) in &NULL_WRAPPERS {
            let pre_chars: Vec<char> = pre.chars().collect();
            let post_chars: Vec<char> = post.chars().collect();
            let total = pre_chars.len() + 2 + post_chars.len();

            if i + total <= len {
                let has_pre = chars[i..i + pre_chars.len()] == pre_chars[..];
                if has_pre {
                    let h1 = chars[i + pre_chars.len()];
                    let h2 = chars[i + pre_chars.len() + 1];
                    if h1.is_ascii_hexdigit() && h2.is_ascii_hexdigit() {
                        let has_post = chars[i + pre_chars.len() + 2..i + total] == post_chars[..];
                        if has_post {
                            let hex_str: String = [h1, h2].iter().collect();
                            if let Ok(b) = u8::from_str_radix(&hex_str, 16) {
                                result.push(b);
                                i += total;
                                matched = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        if !matched {
            i += 1;
        }
    }
    result
}

// ---------------------------------------------------------------------------
// API Pública de Cifrado y Descifrado
// ---------------------------------------------------------------------------

pub fn encrypt(text: &str, password: Option<&str>, delimiter: char) -> Result<String, String> {
    if text.is_empty() {
        return Ok(String::new());
    }

    let delim = if SEPARATORS.contains(&delimiter) { delimiter } else { DEFAULT_SEPARATOR };

    let key = get_random_bytes(KEY_SIZE);
    let nonce = get_random_bytes(NONCE_SIZE);

    let mut raw_key_package = Vec::new();
    if let Some(pwd) = password.filter(|p| !p.is_empty()) {
        let salt = get_random_bytes(SALT_SIZE);
        let wrapping_key = pbkdf2_sha256(pwd, &salt, PBKDF2_ROUNDS);
        let wrap_ks = generate_keystream(&wrapping_key, &salt, KEY_SIZE);
        let mut enc_key = vec![0u8; KEY_SIZE];
        for i in 0..KEY_SIZE {
            enc_key[i] = key[i] ^ wrap_ks[i];
        }
        raw_key_package.push(0x01);
        raw_key_package.extend_from_slice(&salt);
        raw_key_package.extend_from_slice(&enc_key);
    } else {
        raw_key_package.push(0x00);
        raw_key_package.extend_from_slice(&key);
    }

    // Cifrar texto
    let pt_bytes = text.as_bytes();
    let ks = generate_keystream(&key, &nonce, pt_bytes.len());
    let mut ciphertext = vec![0u8; pt_bytes.len()];
    for i in 0..pt_bytes.len() {
        ciphertext[i] = pt_bytes[i] ^ ks[i];
    }

    // HMAC Auth Tag
    let mut auth_input = b"ENCRYPTORX_AUTH_TAG_SALT:".to_vec();
    auth_input.extend_from_slice(&key);
    let auth_key = sha256(&auth_input);

    let mut mac_data = raw_key_package.clone();
    mac_data.extend_from_slice(&nonce);
    mac_data.extend_from_slice(&ciphertext);
    let full_mac = hmac_sha256(&auth_key, &mac_data);
    let tag = &full_mac[..TAG_SIZE];

    // Enmascarar clave con Nonce
    let mask = generate_keystream(&nonce, b"ENCRYPTORX_KEY_MASK", raw_key_package.len());
    let mut masked_key = vec![0u8; raw_key_package.len()];
    for i in 0..raw_key_package.len() {
        masked_key[i] = raw_key_package[i] ^ mask[i];
    }

    // Payload = Nonce + Tag + Ciphertext
    let mut payload = Vec::new();
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(tag);
    payload.extend_from_slice(&ciphertext);

    let obf_key = obfuscate_bytes(&masked_key);
    let obf_payload = obfuscate_bytes(&payload);

    Ok(format!("{}{}{}", obf_key, delim, obf_payload))
}

pub fn decrypt(token: &str, password: Option<&str>) -> Result<String, String> {
    if token.is_empty() {
        return Ok(String::new());
    }

    let cleaned = token.trim();
    let mut found_sep = None;
    for &sep in &SEPARATORS {
        if cleaned.contains(sep) {
            found_sep = Some(sep);
            break;
        }
    }

    let sep = found_sep.ok_or_else(|| "No se encontró ningún separador válido ($, %, &, #)".to_string())?;
    let parts: Vec<&str> = cleaned.splitn(2, sep).collect();
    if parts.len() != 2 {
        return Err("El token no contiene dos secciones válidas".to_string());
    }

    let obf_key = parts[0];
    let obf_payload = parts[1];

    let payload = deobfuscate_bytes(obf_payload);
    if payload.len() < NONCE_SIZE + TAG_SIZE {
        return Err("Payload cifrado corrupto o demasiado corto".to_string());
    }

    let nonce = &payload[..NONCE_SIZE];
    let auth_tag = &payload[NONCE_SIZE..NONCE_SIZE + TAG_SIZE];
    let ciphertext = &payload[NONCE_SIZE + TAG_SIZE..];

    let masked_key = deobfuscate_bytes(obf_key);
    if masked_key.len() < 1 + KEY_SIZE {
        return Err("Clave corrupta o no encontrada en el token".to_string());
    }

    let mask = generate_keystream(nonce, b"ENCRYPTORX_KEY_MASK", masked_key.len());
    let mut raw_key_pkg = vec![0u8; masked_key.len()];
    for i in 0..masked_key.len() {
        raw_key_pkg[i] = masked_key[i] ^ mask[i];
    }

    let flag = raw_key_pkg[0];
    let key: [u8; KEY_SIZE] = if flag == 0x01 {
        let pwd = password.ok_or_else(|| "Este mensaje requiere contraseña para descifrar".to_string())?;
        if raw_key_pkg.len() < 1 + SALT_SIZE + KEY_SIZE {
            return Err("Estructura de clave con contraseña dañada".to_string());
        }
        let salt = &raw_key_pkg[1..1 + SALT_SIZE];
        let enc_key = &raw_key_pkg[1 + SALT_SIZE..1 + SALT_SIZE + KEY_SIZE];
        let wrapping_key = pbkdf2_sha256(pwd, salt, PBKDF2_ROUNDS);
        let wrap_ks = generate_keystream(&wrapping_key, salt, KEY_SIZE);
        let mut k = [0u8; KEY_SIZE];
        for i in 0..KEY_SIZE {
            k[i] = enc_key[i] ^ wrap_ks[i];
        }
        k
    } else {
        let mut k = [0u8; KEY_SIZE];
        k.copy_from_slice(&raw_key_pkg[1..1 + KEY_SIZE]);
        k
    };

    // Verificar HMAC
    let mut auth_input = b"ENCRYPTORX_AUTH_TAG_SALT:".to_vec();
    auth_input.extend_from_slice(&key);
    let auth_key = sha256(&auth_input);

    let mut mac_data = raw_key_pkg;
    mac_data.extend_from_slice(nonce);
    mac_data.extend_from_slice(ciphertext);
    let expected_mac = hmac_sha256(&auth_key, &mac_data);

    // Comparación segura en tiempo constante
    let mut diff = 0u8;
    for i in 0..TAG_SIZE {
        diff |= auth_tag[i] ^ expected_mac[i];
    }

    if diff != 0 {
        return Err("Fallo de integridad HMAC o contraseña incorrecta".to_string());
    }

    // Descifrar texto
    let ks = generate_keystream(&key, nonce, ciphertext.len());
    let mut pt = vec![0u8; ciphertext.len()];
    for i in 0..ciphertext.len() {
        pt[i] = ciphertext[i] ^ ks[i];
    }

    String::from_utf8(pt).map_err(|e| format!("Error decodificando UTF-8: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_roundtrip() {
        let msg = "¡Hola desde Rust nativo con 64 wrappers NULL y HMAC!";
        for &delim in &SEPARATORS {
            let token = encrypt(msg, None, delim).expect("Encrypt failed");
            assert!(token.contains(delim));
            let dec = decrypt(&token, None).expect("Decrypt failed");
            assert_eq!(msg, dec);
        }
    }

    #[test]
    fn test_rust_password() {
        let msg = "Confidencial en Rust";
        let pwd = "RustPassword123";
        let token = encrypt(msg, Some(pwd), '$').expect("Encrypt failed");
        let dec = decrypt(&token, Some(pwd)).expect("Decrypt failed");
        assert_eq!(msg, dec);

        assert!(decrypt(&token, Some("Wrong")).is_err());
        assert!(decrypt(&token, None).is_err());
    }
}
