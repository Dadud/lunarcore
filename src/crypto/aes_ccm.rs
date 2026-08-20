use super::aes::{Aes128, Aes256};

const AES_BLOCK_SIZE: usize = 16;

fn put_be16(buf: &mut [u8], val: u16) {
    buf[0] = (val >> 8) as u8;
    buf[1] = val as u8;
}

fn xor_block(dst: &mut [u8; AES_BLOCK_SIZE], src: &[u8; AES_BLOCK_SIZE]) {
    for i in 0..AES_BLOCK_SIZE {
        dst[i] ^= src[i];
    }
}

fn encrypt_block(key: &[u8], block: &mut [u8; AES_BLOCK_SIZE]) {
    match key.len() {
        32 => {
            let cipher = Aes256::new(key.try_into().expect("32-byte key"));
            cipher.encrypt_block(block);
        }
        16 => {
            let cipher = Aes128::new(key.try_into().expect("16-byte key"));
            cipher.encrypt_block(block);
        }
        _ => return,
    }
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn auth_start(
    key: &[u8],
    m: usize,
    nonce: &[u8],
    aad: &[u8],
    plain_len: usize,
    x: &mut [u8; AES_BLOCK_SIZE],
) {
    const L: usize = 2;
    let aad_len = aad.len();

    let mut b = [0u8; AES_BLOCK_SIZE];
    b[0] = if aad_len > 0 { 0x40 } else { 0 };
    b[0] |= (((m - 2) / 2) << 3) as u8;
    b[0] |= (L - 1) as u8;
    let nonce_copy_len = (15 - L).min(nonce.len());
    b[1..1 + nonce_copy_len].copy_from_slice(&nonce[..nonce_copy_len]);
    put_be16(&mut b[AES_BLOCK_SIZE - L..AES_BLOCK_SIZE], plain_len as u16);
    encrypt_block(key, &mut b);
    *x = b;

    if aad_len == 0 {
        return;
    }

    let mut aad_buf = [0u8; AES_BLOCK_SIZE];
    put_be16(&mut aad_buf[..2], aad_len as u16);
    let copy_len = aad.len().min(AES_BLOCK_SIZE - 2);
    aad_buf[2..2 + copy_len].copy_from_slice(&aad[..copy_len]);
    xor_block(x, &aad_buf);
    encrypt_block(key, x);

    if aad_len > AES_BLOCK_SIZE - 2 {
        let mut second = [0u8; AES_BLOCK_SIZE];
        let remain = aad.len() - (AES_BLOCK_SIZE - 2);
        second[..remain].copy_from_slice(&aad[AES_BLOCK_SIZE - 2..]);
        xor_block(&mut second, x);
        encrypt_block(key, &mut second);
        *x = second;
    }
}

fn auth_data(key: &[u8], data: &[u8], x: &mut [u8; AES_BLOCK_SIZE]) {
    let full_blocks = data.len() / AES_BLOCK_SIZE;
    let last = data.len() % AES_BLOCK_SIZE;
    let mut offset = 0;

    for _ in 0..full_blocks {
        let mut block = [0u8; AES_BLOCK_SIZE];
        block.copy_from_slice(&data[offset..offset + AES_BLOCK_SIZE]);
        xor_block(x, &block);
        encrypt_block(key, x);
        offset += AES_BLOCK_SIZE;
    }

    if last > 0 {
        let mut block = [0u8; AES_BLOCK_SIZE];
        block[..last].copy_from_slice(&data[offset..offset + last]);
        xor_block(x, &block);
        encrypt_block(key, x);
    }
}

fn encr_start(nonce: &[u8], a: &mut [u8; AES_BLOCK_SIZE]) {
    const L: usize = 2;
    a[0] = (L - 1) as u8;
    let nonce_copy_len = (15 - L).min(nonce.len());
    a[1..1 + nonce_copy_len].copy_from_slice(&nonce[..nonce_copy_len]);
}

fn encr(key: &[u8], input: &[u8], output: &mut [u8], a: &mut [u8; AES_BLOCK_SIZE]) {
    const L: usize = 2;
    let full_blocks = input.len() / AES_BLOCK_SIZE;
    let last = input.len() % AES_BLOCK_SIZE;
    let mut in_off = 0;
    let mut out_off = 0;

    for i in 1..=full_blocks {
        put_be16(&mut a[AES_BLOCK_SIZE - 2..AES_BLOCK_SIZE], i as u16);
        let mut stream = [0u8; AES_BLOCK_SIZE];
        encrypt_block(key, &mut stream);
        for j in 0..AES_BLOCK_SIZE {
            output[out_off + j] = input[in_off + j] ^ stream[j];
        }
        in_off += AES_BLOCK_SIZE;
        out_off += AES_BLOCK_SIZE;
    }

    if last > 0 {
        let i = full_blocks + 1;
        put_be16(&mut a[AES_BLOCK_SIZE - 2..AES_BLOCK_SIZE], i as u16);
        let mut stream = [0u8; AES_BLOCK_SIZE];
        encrypt_block(key, &mut stream);
        for j in 0..last {
            output[out_off + j] = input[in_off + j] ^ stream[j];
        }
    }
}

fn encr_auth(key: &[u8], m: usize, x: &[u8; AES_BLOCK_SIZE], a: &mut [u8; AES_BLOCK_SIZE], auth: &mut [u8]) {
    put_be16(&mut a[AES_BLOCK_SIZE - 2..AES_BLOCK_SIZE], 0);
    let mut tmp = [0u8; AES_BLOCK_SIZE];
    encrypt_block(key, &mut tmp);
    for i in 0..m {
        auth[i] = x[i] ^ tmp[i];
    }
}

fn decr_auth(key: &[u8], m: usize, a: &mut [u8; AES_BLOCK_SIZE], auth: &[u8], t: &mut [u8; AES_BLOCK_SIZE]) {
    put_be16(&mut a[AES_BLOCK_SIZE - 2..AES_BLOCK_SIZE], 0);
    let mut tmp = [0u8; AES_BLOCK_SIZE];
    encrypt_block(key, &mut tmp);
    for i in 0..m {
        t[i] = auth[i] ^ tmp[i];
    }
}

pub fn aes_ccm_encrypt(
    key: &[u8],
    nonce: &[u8],
    tag_len: usize,
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8],
) -> bool {
    if nonce.len() < 13 || tag_len > AES_BLOCK_SIZE || ciphertext.len() < plaintext.len() {
        return false;
    }

    let mut x = [0u8; AES_BLOCK_SIZE];
    let mut a = [0u8; AES_BLOCK_SIZE];

    auth_start(key, tag_len, nonce, &[], plaintext.len(), &mut x);
    auth_data(key, plaintext, &mut x);

    encr_start(nonce, &mut a);
    encr(key, plaintext, &mut ciphertext[..plaintext.len()], &mut a);
    encr_auth(key, tag_len, &x, &mut a, tag);
    true
}

pub fn aes_ccm_decrypt(
    key: &[u8],
    nonce: &[u8],
    tag_len: usize,
    ciphertext: &[u8],
    plaintext: &mut [u8],
    tag: &[u8],
) -> bool {
    if nonce.len() < 13 || tag_len > AES_BLOCK_SIZE || plaintext.len() < ciphertext.len() || tag.len() < tag_len {
        return false;
    }

    let mut x = [0u8; AES_BLOCK_SIZE];
    let mut a = [0u8; AES_BLOCK_SIZE];
    let mut t = [0u8; AES_BLOCK_SIZE];

    encr_start(nonce, &mut a);
    decr_auth(key, tag_len, &mut a, tag, &mut t);
    encr(key, ciphertext, &mut plaintext[..ciphertext.len()], &mut a);

    auth_start(key, tag_len, nonce, &[], ciphertext.len(), &mut x);
    auth_data(key, &plaintext[..ciphertext.len()], &mut x);

    constant_time_compare(&x[..tag_len], &t[..tag_len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_ccm_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x00,
        ];
        let plaintext = b"Meshtastic PKI test payload";

        let mut ciphertext = [0u8; 64];
        let mut tag = [0u8; 8];
        assert!(aes_ccm_encrypt(
            &key,
            &nonce,
            8,
            plaintext,
            &mut ciphertext[..plaintext.len()],
            &mut tag,
        ));

        let mut decrypted = [0u8; 64];
        assert!(aes_ccm_decrypt(
            &key,
            &nonce,
            8,
            &ciphertext[..plaintext.len()],
            &mut decrypted,
            &tag,
        ));
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }
}
