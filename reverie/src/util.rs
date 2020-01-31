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

use std::error::Error;
use std::str::FromStr;

/// Parses an environment variable command-line argument.
pub fn parse_env<T, U>(s: &str) -> Result<(T, U), Box<dyn Error>>
where
    T: FromStr,
    T::Err: Error + 'static,
    U: FromStr,
    U::Err: Error + 'static,
{
    let mut iter = s.splitn(2, '=');

    let key = iter.next().ok_or("Invalid KEY=VALUE: string is empty")?;

    let value = match iter.next() {
        Some(value) => value.parse()?,
        None => std::env::var(key)?.parse()?,
    };

    Ok((key.parse()?, value))
}
