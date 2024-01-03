
pub fn encrypt(plaintext: u64, subkeys: [u32; 6]) -> u64 {
    let (k0, k1, k2, k3, k4, k5) =
        (subkeys[0], subkeys[1], subkeys[2], subkeys[3], subkeys[4], subkeys[5]);
    let k45 = concat(k4, k5);

    let p = plaintext ^ k45;
    let mut left = left(p);
    let mut right = right(p);

    right = right ^ left;

    (right, left) = f_round(left, right, k0);
    (right, left) = f_round(left, right, k1);
    (right, left) = f_round(left, right, k2);
    (left, right) = f_round(left, right, k3);

    right = right ^ left;

    concat(left, right)
}

pub fn decrypt(cipher: u64, subkeys: [u32; 6]) -> u64 {
    let (k0, k1, k2, k3, k4, k5) =
        (subkeys[0], subkeys[1], subkeys[2], subkeys[3], subkeys[4], subkeys[5]);
    let k45 = concat(k4, k5);

    let mut left = left(cipher);
    let mut right = right(cipher);

    right = right ^ left;

    (right, left) = f_round(left, right, k3);
    (right, left) = f_round(left, right, k2);
    (right, left) = f_round(left, right, k1);
    (left, right) = f_round(left, right, k0);

    right = right ^ left;

    concat(left, right) ^ k45
}

fn f_round(left: u32, right: u32, key: u32) -> (u32, u32) {
    let new_left = left ^ f(right ^ key);

    (new_left, right)
}

fn f(val: u32) -> u32 {
    let x: [u8; 4] = val.to_be_bytes();

    let y1 = g1(x[0] ^ x[1], x[2] ^ x[3]);
    let y0 = g0(x[0], y1);
    let y2 = g0(y1, x[2] & x[3]);
    let y3 = g1(y2, x[3]);

    u32::from_be_bytes([y0, y1, y2, y3])
}

fn g0(a: u8, b: u8) -> u8 {
    ((((a as u16) + (b as u16)) % 256) as u8) << 2
}

fn g1(a: u8, b: u8) -> u8 {
    ((((a as u16) + (b as u16) + 1) % 256) as u8) << 2
}

fn concat(a: u32, b: u32) -> u64 {
    ((a as u64) << 32) | (b as u64)
}

fn left(val: u64) -> u32 {
    (val >> 32) as u32
}

fn right(val: u64) -> u32 {
    val as u32
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_encrypts_and_decrypts() {
        let plaintext: u64 = 12323132;
        let subkeys: [u32; 6] = [1, 2, 3, 4, 5, 6];

        assert_eq!(plaintext, decrypt(encrypt(plaintext, subkeys), subkeys));
    }

    #[test]
    fn it_takes_right() {
        let val: u64 = 0b0000000000000000000000000000000100000000000000000000000000001111;
        let expected: u32 = 0b00000000000000000000000000001111;

        assert_eq!(expected, right(val));
    }

    #[test]
    fn it_takes_left() {
        let val: u64 = 0b0000000000000000000000000000000100000000000000000000000000000011;
        let expected: u32 = 0b00000000000000000000000000000001;

        assert_eq!(expected, left(val));
    }

    #[test]
    fn it_concat_binary() {
        let first: u32 = 0b00000000000000000000000000000001;
        let second: u32 = 0b00000000000000000000000000000011;

        let expected: u64 = 0b0000000000000000000000000000000100000000000000000000000000000011;
        let actual: u64 = concat(first, second);

        assert_eq!(expected, actual, "Expected: {}, got: {} instead.", expected, actual);
    }

    #[test]
    fn it_computes_g1() {
        assert_eq!(0b01011100, g1(0b10000010, 0b10010100));
        assert_eq!(0b11111100, g1(0b11111111, 0b11111111));
    }

    #[test]
    fn it_computes_g0() {
        assert_eq!(0b01011000, g0(0b10000010, 0b10010100));
        assert_eq!(0b11111000, g0(0b11111111, 0b11111111));
    }
}