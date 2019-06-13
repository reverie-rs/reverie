
#[macro_export]
macro_rules! libc_bit_field {
    ($flags:ident, $bit: ident) => {
        if $flags & libc::$bit == libc::$bit {
            Some(stringify!($bit))
        } else {
            None
        }
    }
}

#[macro_export]
macro_rules! libc_bit_sh {
    ($flags:ident, $bit: ident) => {
        if ($flags as u64) & (1u64.wrapping_shl(libc::$bit as u32)) == (1u64.wrapping_shl(libc::$bit as u32)) {
            Some(stringify!($bit))
        } else {
            None
        }
    }
}

#[macro_export]
macro_rules! libc_match_value {
    ($flag:ident, $value:ident) => {
        if $flag == libc::$value {
            Some(stringify!($value))
        } else {
            None
        }
    };
}
