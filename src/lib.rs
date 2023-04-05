const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

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

/// SHA-256 hasher
pub struct Sha256 {
    state: [u32; 8],
    len: usize,

    buf: [u8; 64],
    buf_len: usize,
}

impl Sha256 {
    /// Create new Sha256 instance.
    pub fn new() -> Self {
        Default::default()
    }

    /// Process data, updating the internal state.
    pub fn update(&mut self, message: impl AsRef<[u8]>) {
        let mut message = message.as_ref();
        self.len += message.len();

        if self.buf_len > 0 {
            let n = (64 - self.buf_len).min(message.len());
            self.buf[self.buf_len..self.buf_len + n].copy_from_slice(&message[..n]);
            self.buf_len += n;
            if self.buf_len == 64 {
                process(&mut self.state, &self.buf);
                self.buf_len = 0
            }
            message = &message[n..];
        }

        if message.len() >= 64 {
            let n = message.len() & !(64 - 1);
            process(&mut self.state, &message[..n]);
            message = &message[n..];
        }

        if message.len() > 0 {
            self.buf[..message.len()].copy_from_slice(message);
            self.buf_len = message.len();
        }
    }

    /// Retrieve result and consume Sha256 instance.
    pub fn finalize(mut self) -> [u8; 32] {
        padding(&mut self.buf, self.buf_len);
        // Append the original message length at the end of the message block as a 64-bit big-endian integer.
        self.buf[64 - 8..].copy_from_slice(&((self.len as u64 * 8).to_be_bytes()));
        process(&mut self.state, &self.buf);
        // Produce the final hash value (big-endian):
        self.state.iter_mut().for_each(|x| *x = x.to_be());
        unsafe { std::mem::transmute(self.state) }
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self {
            state: H,
            len: 0,
            buf: [0; 64],
            buf_len: 0,
        }
    }
}

fn padding(block: &mut [u8; 64], block_len: usize) {
    // Append a single '1' bit to the buf.
    block[block_len] = 0x80;
    block[block_len + 1..].fill(0);
}

/// Process the message in successive 512-bit chunks:
fn process(state: &mut [u32; 8], block: &[u8]) {
    let (mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );

    // break message into 512-bit chunks
    for m in block.chunks_exact(64) {
        // create a 64-entry message schedule array w[0..63] of 32-bit words
        let mut w = [0u32; 64];
        // copy chunk into first 16 words w[0..15] of the message schedule array
        for (src, dest) in m.chunks_exact(4).zip(&mut w).take(16) {
            *dest = u32::from_be_bytes(src.try_into().unwrap());
        }
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        // Initialize working variables to current hash value:
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
            (h0, h1, h2, h3, h4, h5, h6, h7);
        //  Compression function main loop:
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        // Add the compressed chunk to the current hash value:
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }

    state[0] = h0;
    state[1] = h1;
    state[2] = h2;
    state[3] = h3;
    state[4] = h4;
    state[5] = h5;
    state[6] = h6;
    state[7] = h7;
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn test_sha256() {
        let cases = vec![
            (
                vec!["abcdefg"],
                "7d1a54127b222502f5b79b5fb0803061152a44f92b37e23c6527baf665d4da9a",
            ),
            (
                vec!["abc", "def", "g"],
                "7d1a54127b222502f5b79b5fb0803061152a44f92b37e23c6527baf665d4da9a",
            ),
            (
                vec!["hello world\n"],
                "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447",
            ),
            (
                vec![
                    "`1234567890-=",
                    "qwertyuiop[]\\",
                    "asdfghjkl;'",
                    "zxcvbnm,./",
                ],
                "757907b174a2168aa1ccdb4cb1115002d1bf2113212d0644de21b677288979b0",
            ),
            (
                // ax64
                vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
            ),
            (
                vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                "8af881bc88895bd9d8cea975a7d06dc0275d9db9d57f138216936b65e8b06489",
            ),
        ];
        for (messages, expect) in cases {
            let mut sha256 = Sha256::new();
            for chunk in &messages {
                sha256.update(chunk.as_bytes());
            }
            let actual = hex::encode(sha256.finalize());
            assert_eq!(actual, expect, "testing sha256 `{:?}`", messages);
        }
    }
}
