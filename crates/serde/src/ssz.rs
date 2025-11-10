use thiserror::Error;

#[derive(Debug, Error)]
pub enum SszError {
    #[error("decode error")]
    Decode,
}

#[inline]
pub fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len() as u32;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

#[inline]
pub fn decode_bytes(input: &[u8], offset: &mut usize) -> Vec<u8> {
    if *offset + 4 > input.len() {
        return Vec::new();
    }
    let len = u32::from_le_bytes(input[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    if *offset + len > input.len() {
        return Vec::new();
    }
    let out = input[*offset..*offset + len].to_vec();
    *offset += len;
    out
}
