/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 *
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#[macro_export]
macro_rules! libc_bit_field {
    ($flags:ident, $bit: ident) => {
        if $flags & libc::$bit == libc::$bit {
            Some(stringify!($bit))
        } else {
            None
        }
    };
}

#[macro_export]
macro_rules! libc_bit_sh {
    ($flags:ident, $bit: ident) => {
        if ($flags as u64) & (1u64.wrapping_shl(libc::$bit as u32))
            == (1u64.wrapping_shl(libc::$bit as u32))
        {
            Some(stringify!($bit))
        } else {
            None
        }
    };
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
