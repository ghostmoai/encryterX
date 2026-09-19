//! Shamir's Secret Sharing Scheme (k, n) over GF(256)
//! Pure Rust implementation with primitive generator 3.

const IRREDUCIBLE_POLY: u16 = 0x11B;

pub struct GF256Tables {
    exp: [u8; 512],
    log: [u8; 256],
}

impl GF256Tables {
    pub const fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        let mut i = 0;
        while i < 255 {
            exp[i] = x as u8;
            exp[i + 255] = x as u8;
            log[x as usize] = i as u8;

            let mut next = (x << 1) ^ x;
            if (next & 0x100) != 0 {
                next ^= IRREDUCIBLE_POLY;
            }
            x = next;
            i += 1;
        }
        exp[510] = exp[0];
        exp[511] = exp[1];
        Self { exp, log }
    }

    #[inline(always)]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let idx = (self.log[a as usize] as usize) + (self.log[b as usize] as usize);
            self.exp[idx]
        }
    }

    #[inline(always)]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        if b == 0 {
            panic!("Division by zero in GF(256)");
        }
        if a == 0 {
            0
        } else {
            let log_a = self.log[a as usize] as usize;
            let log_b = self.log[b as usize] as usize;
            let idx = (log_a + 255 - log_b) % 255;
            self.exp[idx]
        }
    }
}

pub static GF: GF256Tables = GF256Tables::new();

/// Pseudo-random byte generator for secret sharing coefficients when std RNG is used.
fn random_bytes(len: usize) -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut buf = vec![0u8; len];
    let mut seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    for i in 0..len {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        buf[i] = (seed >> 32) as u8 ^ ((seed >> 48) as u8);
    }
    buf
}

/// Split a secret into `n` shares requiring threshold `k` shares for reconstruction.
pub fn split_secret(secret: &[u8], k: u8, n: u8) -> Result<Vec<(u8, Vec<u8>)>, &'static str> {
    if k < 2 {
        return Err("Threshold k must be at least 2.");
    }
    if k > n {
        return Err("Threshold k cannot exceed total shares n.");
    }

    let secret_len = secret.len();
    let mut shares: Vec<(u8, Vec<u8>)> = (1..=n).map(|x| (x, vec![0u8; secret_len])).collect();

    let rand_pool = random_bytes(secret_len * (k as usize - 1) + 128);
    let mut rand_idx = 0;

    for (byte_idx, &s_byte) in secret.iter().enumerate() {
        let mut coeffs = Vec::with_capacity(k as usize);
        coeffs.push(s_byte);
        for _ in 1..k {
            let r = rand_pool[rand_idx % rand_pool.len()];
            rand_idx += 1;
            coeffs.push(r);
        }

        // Evaluate polynomial P(x) = s_byte + a_1*x + ... + a_{k-1}*x^{k-1}
        for (x, share_buf) in shares.iter_mut() {
            let mut y = 0u8;
            let mut x_pow = 1u8;
            for &coeff in coeffs.iter() {
                y ^= GF.mul(coeff, x_pow);
                x_pow = GF.mul(x_pow, *x);
            }
            share_buf[byte_idx] = y;
        }
    }

    Ok(shares)
}

/// Combine `k` or more shares to reconstruct the original secret.
pub fn combine_shares(shares: &[(u8, Vec<u8>)]) -> Result<Vec<u8>, &'static str> {
    if shares.is_empty() {
        return Err("No shares provided.");
    }
    let share_len = shares[0].1.len();
    for s in shares {
        if s.1.len() != share_len {
            return Err("Mismatched share lengths.");
        }
    }

    let k = shares.len();
    let mut secret = vec![0u8; share_len];

    for byte_idx in 0..share_len {
        let mut secret_byte = 0u8;
        for j in 0..k {
            let (x_j, ref y_j_buf) = shares[j];
            let y_j = y_j_buf[byte_idx];

            let mut num = 1u8;
            let mut den = 1u8;
            for m in 0..k {
                if m == j {
                    continue;
                }
                let (x_m, _) = shares[m];
                num = GF.mul(num, x_m);
                den = GF.mul(den, x_m ^ x_j);
            }

            let l_j_0 = GF.div(num, den);
            secret_byte ^= GF.mul(y_j, l_j_0);
        }
        secret[byte_idx] = secret_byte;
    }

    Ok(secret)
}

/// Helper: split secret into string shares '<x>-<hex>'
pub fn split_secret_strings(secret: &[u8], k: u8, n: u8) -> Result<Vec<String>, &'static str> {
    let raw_shares = split_secret(secret, k, n)?;
    let mut results = Vec::with_capacity(raw_shares.len());
    for (x, data) in raw_shares {
        let hex_str: String = data.iter().map(|b| format!("{:02x}", b)).collect();
        results.push(format!("{}-{}", x, hex_str));
    }
    Ok(results)
}

/// Helper: combine string shares into secret bytes
pub fn combine_shares_strings(share_strings: &[String]) -> Result<Vec<u8>, &'static str> {
    let mut raw_shares = Vec::with_capacity(share_strings.len());
    for s in share_strings {
        let parts: Vec<&str> = s.splitn(2, '-').collect();
        if parts.len() != 2 {
            return Err("Invalid share format, expected '<x>-<hex>'");
        }
        let x: u8 = parts[0].parse().map_err(|_| "Invalid share index")?;
        let hex_str = parts[1];
        if hex_str.len() % 2 != 0 {
            return Err("Invalid hex data length in share");
        }
        let mut bytes = Vec::with_capacity(hex_str.len() / 2);
        for i in (0..hex_str.len()).step_by(2) {
            let byte = u8::from_str_radix(&hex_str[i..i + 2], 16)
                .map_err(|_| "Invalid hex character in share")?;
            bytes.push(byte);
        }
        raw_shares.push((x, bytes));
    }
    combine_shares(&raw_shares)
}
