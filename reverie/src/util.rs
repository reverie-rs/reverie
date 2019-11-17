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
