//! ChaCha20 Stream Cipher & Poly1305 Authenticator (RFC 8439)
//! Pure Rust implementation with zero external dependencies.

/// ChaCha20 Quarter Round operation on state array indices.
#[inline(always)]
fn qr(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]); x[d] ^= x[a]; x[d] = x[d].rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]); x[b] ^= x[c]; x[b] = x[b].rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]); x[d] ^= x[a]; x[d] = x[d].rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]); x[b] ^= x[c]; x[b] = x[b].rotate_left(7);
}

/// ChaCha20 stream cipher engine.
pub struct ChaCha20 {
    state: [u32; 16],
}

impl ChaCha20 {
    /// Initialize ChaCha20 with a 32-byte key, 12-byte nonce, and 32-bit initial counter.
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let mut state = [0u32; 16];
        // "expand 32-byte k" constants
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // 8 key words
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        }

        // Counter
        state[12] = counter;

        // 3 nonce words
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
        }

        Self { state }
    }

    /// Generate 64-byte block for current counter.
    fn block(&self, counter: u32) -> [u8; 64] {
        let mut x = self.state;
        x[12] = counter;

        // 10 double rounds (20 rounds total)
        for _ in 0..10 {
            // Column rounds
            qr(&mut x, 0, 4, 8,  12);
            qr(&mut x, 1, 5, 9,  13);
            qr(&mut x, 2, 6, 10, 14);
            qr(&mut x, 3, 7, 11, 15);

            // Diagonal rounds
            qr(&mut x, 0, 5, 10, 15);
            qr(&mut x, 1, 6, 11, 12);
            qr(&mut x, 2, 7, 8,  13);
            qr(&mut x, 3, 4, 9,  14);
        }

        let mut out = [0u8; 64];
        for i in 0..16 {
            let word = x[i].wrapping_add(if i == 12 { counter } else { self.state[i] });
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Encrypt or decrypt data in-place using XOR keystream.
    pub fn apply_keystream(&self, data: &mut [u8], mut counter: u32) {
        let mut offset = 0;
        while offset < data.len() {
            let keystream = self.block(counter);
            let chunk_len = std::cmp::min(64, data.len() - offset);
            for i in 0..chunk_len {
                data[offset + i] ^= keystream[i];
            }
            offset += chunk_len;
            counter = counter.wrapping_add(1);
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        self.apply_keystream(&mut buf, self.state[12]);
        buf
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        self.encrypt(ciphertext)
    }
}

/// Poly1305 One-Time Authenticator (RFC 8439).
pub struct Poly1305 {
    r0: u64,
    r1: u64,
    r2: u64,
    r3: u64,
    r4: u64,
    s1: u64,
    s2: u64,
    s3: u64,
    s4: u64,
    h0: u64,
    h1: u64,
    h2: u64,
    h3: u64,
    h4: u64,
    pad: [u8; 16],
    buffer: [u8; 16],
    buf_len: usize,
}

impl Poly1305 {
    /// Initialize with 32-byte key: r (first 16 bytes, clamped) and s (last 16 bytes).
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r = [0u8; 16];
        r.copy_from_slice(&key[0..16]);
        // Clamp r
        r[3] &= 15;
        r[7] &= 15;
        r[11] &= 15;
        r[15] &= 15;
        r[4] &= 252;
        r[8] &= 252;
        r[12] &= 252;

        let r0 = (u32::from_le_bytes(r[0..4].try_into().unwrap()) & 0x3ffffff) as u64;
        let r1 = ((u32::from_le_bytes(r[3..7].try_into().unwrap()) >> 2) & 0x3ffff03) as u64;
        let r2 = ((u32::from_le_bytes(r[6..10].try_into().unwrap()) >> 4) & 0x3ffc0ff) as u64;
        let r3 = ((u32::from_le_bytes(r[9..13].try_into().unwrap()) >> 6) & 0x3f03fff) as u64;
        let r4 = ((u32::from_le_bytes(r[12..16].try_into().unwrap()) >> 8) & 0x00fffff) as u64;

        let mut pad = [0u8; 16];
        pad.copy_from_slice(&key[16..32]);

        Self {
            r0,
            r1,
            r2,
            r3,
            r4,
            s1: r1 * 5,
            s2: r2 * 5,
            s3: r3 * 5,
            s4: r4 * 5,
            h0: 0,
            h1: 0,
            h2: 0,
            h3: 0,
            h4: 0,
            pad,
            buffer: [0u8; 16],
            buf_len: 0,
        }
    }

    fn process_block(&mut self, block: &[u8], is_final_partial: bool) {
        let hibit = if is_final_partial { 0 } else { 1u64 << 24 };

        let mut b = [0u8; 17];
        b[..block.len()].copy_from_slice(block);
        if is_final_partial {
            b[block.len()] = 1;
        }

        let c0 = (u32::from_le_bytes(b[0..4].try_into().unwrap()) & 0x3ffffff) as u64;
        let c1 = ((u32::from_le_bytes(b[3..7].try_into().unwrap()) >> 2) & 0x3ffffff) as u64;
        let c2 = ((u32::from_le_bytes(b[6..10].try_into().unwrap()) >> 4) & 0x3ffffff) as u64;
        let c3 = ((u32::from_le_bytes(b[9..13].try_into().unwrap()) >> 6) & 0x3ffffff) as u64;
        let c4 = ((u32::from_le_bytes(b[12..16].try_into().unwrap()) >> 8) as u64) | hibit;

        self.h0 += c0;
        self.h1 += c1;
        self.h2 += c2;
        self.h3 += c3;
        self.h4 += c4;

        let d0 = self.h0 * self.r0 + self.h1 * self.s4 + self.h2 * self.s3 + self.h3 * self.s2 + self.h4 * self.s1;
        let d1 = self.h0 * self.r1 + self.h1 * self.r0 + self.h2 * self.s4 + self.h3 * self.s3 + self.h4 * self.s2;
        let d2 = self.h0 * self.r2 + self.h1 * self.r1 + self.h2 * self.r0 + self.h3 * self.s4 + self.h4 * self.s3;
        let d3 = self.h0 * self.r3 + self.h1 * self.r2 + self.h2 * self.r1 + self.h3 * self.r0 + self.h4 * self.s4;
        let d4 = self.h0 * self.r4 + self.h1 * self.r3 + self.h2 * self.r2 + self.h3 * self.r1 + self.h4 * self.r0;

        let mut c = d0 >> 26; self.h0 = d0 & 0x3ffffff;
        let mut x = d1 + c; c = x >> 26; self.h1 = x & 0x3ffffff;
        x = d2 + c; c = x >> 26; self.h2 = x & 0x3ffffff;
        x = d3 + c; c = x >> 26; self.h3 = x & 0x3ffffff;
        x = d4 + c; c = x >> 26; self.h4 = x & 0x3ffffff;
        self.h0 += c * 5;
        c = self.h0 >> 26; self.h0 &= 0x3ffffff;
        self.h1 += c;
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        if self.buf_len > 0 {
            let want = 16 - self.buf_len;
            let take = std::cmp::min(want, data.len());
            self.buffer[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            offset += take;

            if self.buf_len == 16 {
                let blk = self.buffer;
                self.process_block(&blk, false);
                self.buf_len = 0;
            }
        }

        while offset + 16 <= data.len() {
            let blk = &data[offset..offset + 16];
            self.process_block(blk, false);
            offset += 16;
        }

        if offset < data.len() {
            let rem = &data[offset..];
            self.buffer[..rem.len()].copy_from_slice(rem);
            self.buf_len = rem.len();
        }
    }

    pub fn finish(mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            let len = self.buf_len;
            let mut blk = [0u8; 16];
            blk[..len].copy_from_slice(&self.buffer[..len]);
            self.process_block(&blk[..len], true);
        }

        let mut c = self.h1 >> 26; self.h1 &= 0x3ffffff;
        self.h2 += c; c = self.h2 >> 26; self.h2 &= 0x3ffffff;
        self.h3 += c; c = self.h3 >> 26; self.h3 &= 0x3ffffff;
        self.h4 += c; c = self.h4 >> 26; self.h4 &= 0x3ffffff;
        self.h0 += c * 5; c = self.h0 >> 26; self.h0 &= 0x3ffffff;
        self.h1 += c;

        // Compute h + -p to reduce if h >= p
        let mut g0 = self.h0.wrapping_add(5); c = g0 >> 26; g0 &= 0x3ffffff;
        let mut g1 = self.h1.wrapping_add(c); c = g1 >> 26; g1 &= 0x3ffffff;
        let mut g2 = self.h2.wrapping_add(c); c = g2 >> 26; g2 &= 0x3ffffff;
        let mut g3 = self.h3.wrapping_add(c); c = g3 >> 26; g3 &= 0x3ffffff;
        let g4 = self.h4.wrapping_add(c).wrapping_sub(1 << 26);

        let mask = (g4 >> 63).wrapping_sub(1);
        let nmask = !mask;
        self.h0 = (self.h0 & nmask) | (g0 & mask);
        self.h1 = (self.h1 & nmask) | (g1 & mask);
        self.h2 = (self.h2 & nmask) | (g2 & mask);
        self.h3 = (self.h3 & nmask) | (g3 & mask);
        self.h4 = (self.h4 & nmask) | (g4 & mask);

        let f0 = (self.h0 | (self.h1 << 26)) & 0xffffffff;
        let f1 = ((self.h1 >> 6) | (self.h2 << 20)) & 0xffffffff;
        let f2 = ((self.h2 >> 12) | (self.h3 << 14)) & 0xffffffff;
        let f3 = ((self.h3 >> 18) | (self.h4 << 8)) & 0xffffffff;

        let pad0 = u32::from_le_bytes(self.pad[0..4].try_into().unwrap()) as u64;
        let pad1 = u32::from_le_bytes(self.pad[4..8].try_into().unwrap()) as u64;
        let pad2 = u32::from_le_bytes(self.pad[8..12].try_into().unwrap()) as u64;
        let pad3 = u32::from_le_bytes(self.pad[12..16].try_into().unwrap()) as u64;

        let mut t = f0 + pad0; let o0 = (t & 0xffffffff) as u32; c = t >> 32;
        t = f1 + pad1 + c; let o1 = (t & 0xffffffff) as u32; c = t >> 32;
        t = f2 + pad2 + c; let o2 = (t & 0xffffffff) as u32; c = t >> 32;
        t = f3 + pad3 + c; let o3 = (t & 0xffffffff) as u32;

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&o0.to_le_bytes());
        tag[4..8].copy_from_slice(&o1.to_le_bytes());
        tag[8..12].copy_from_slice(&o2.to_le_bytes());
        tag[12..16].copy_from_slice(&o3.to_le_bytes());
        tag
    }
}

/// ChaCha20-Poly1305 AEAD authenticated encryption (RFC 8439).
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    // 1. Generate one-time Poly1305 subkey with counter = 0
    let engine = ChaCha20::new(key, nonce, 0);
    let poly_block = engine.block(0);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_block[0..32]);

    // 2. Encrypt plaintext starting with counter = 1
    let cipher_engine = ChaCha20::new(key, nonce, 1);
    let ciphertext = cipher_engine.encrypt(plaintext);

    // 3. Compute Poly1305 MAC tag over AAD || pad || Ciphertext || pad || len(AAD) || len(C)
    let mut poly = Poly1305::new(&poly_key);
    if !aad.is_empty() {
        poly.update(aad);
        if aad.len() % 16 != 0 {
            let pad = vec![0u8; 16 - (aad.len() % 16)];
            poly.update(&pad);
        }
    }

    if !ciphertext.is_empty() {
        poly.update(&ciphertext);
        if ciphertext.len() % 16 != 0 {
            let pad = vec![0u8; 16 - (ciphertext.len() % 16)];
            poly.update(&pad);
        }
    }

    let mut lengths = [0u8; 16];
    lengths[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly.update(&lengths);

    let tag = poly.finish();
    (ciphertext, tag)
}

/// ChaCha20-Poly1305 AEAD authenticated decryption (RFC 8439).
pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    tag: &[u8; 16],
    aad: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let engine = ChaCha20::new(key, nonce, 0);
    let poly_block = engine.block(0);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_block[0..32]);

    let mut poly = Poly1305::new(&poly_key);
    if !aad.is_empty() {
        poly.update(aad);
        if aad.len() % 16 != 0 {
            let pad = vec![0u8; 16 - (aad.len() % 16)];
            poly.update(&pad);
        }
    }

    if !ciphertext.is_empty() {
        poly.update(ciphertext);
        if ciphertext.len() % 16 != 0 {
            let pad = vec![0u8; 16 - (ciphertext.len() % 16)];
            poly.update(&pad);
        }
    }

    let mut lengths = [0u8; 16];
    lengths[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly.update(&lengths);

    let expected_tag = poly.finish();
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= tag[i] ^ expected_tag[i];
    }
    if diff != 0 {
        return Err("Authentication tag verification failed: corrupted data or wrong key.");
    }

    let cipher_engine = ChaCha20::new(key, nonce, 1);
    Ok(cipher_engine.decrypt(ciphertext))
}
