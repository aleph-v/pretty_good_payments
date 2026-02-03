//! Common utility functions for CLI commands.
//!
//! This module consolidates parsing functions and other utilities
//! shared across multiple command modules.

use alloy_primitives::{Address, B256, U256};
use eyre::{Result, WrapErr};

/// Parse a hex string as an Ethereum address.
///
/// Accepts both `0x`-prefixed and unprefixed hex strings.
///
/// # Errors
/// Returns an error if the input is not valid hex or is not exactly 20 bytes.
pub fn parse_address(s: &str) -> Result<Address> {
    let s = s.trim_start_matches("0x");
    let bytes = hex::decode(s)
        .wrap_err_with(|| format!("Invalid address format: '{s}' is not valid hex"))?;
    if bytes.len() != 20 {
        eyre::bail!(
            "Address must be 20 bytes, got {} bytes from '{}'",
            bytes.len(),
            s
        );
    }
    Ok(Address::from_slice(&bytes))
}

/// Parse a string as an amount (U256).
///
/// Supports:
/// - Decimal format: "1000"
/// - Hex format: "0x3e8"
///
/// # Errors
/// Returns an error if the input cannot be parsed as a number.
pub fn parse_amount(s: &str) -> Result<U256> {
    // Try parsing as decimal first
    if let Ok(n) = s.parse::<u128>() {
        return Ok(U256::from(n));
    }

    // Try parsing as hex
    if let Some(hex_str) = s.strip_prefix("0x") {
        let bytes = hex::decode(hex_str)
            .wrap_err_with(|| format!("Invalid hex amount: '{s}' is not valid hex"))?;
        return Ok(U256::from_be_slice(&bytes));
    }

    eyre::bail!(
        "Invalid amount format: '{}'. Expected decimal number or 0x-prefixed hex",
        s
    )
}

/// Parse a hex string as a 32-byte public key.
///
/// Accepts both `0x`-prefixed and unprefixed hex strings.
///
/// # Errors
/// Returns an error if the input is not valid hex or is not exactly 32 bytes.
pub fn parse_public_key(s: &str) -> Result<B256> {
    let s = s.trim_start_matches("0x");
    let bytes = hex::decode(s)
        .wrap_err_with(|| format!("Invalid public key format: '{s}' is not valid hex"))?;
    if bytes.len() != 32 {
        eyre::bail!(
            "Public key must be 32 bytes, got {} bytes from '{}'",
            bytes.len(),
            s
        );
    }
    Ok(B256::from_slice(&bytes))
}

/// Convert an Ethereum address to a B256 (left-padded with zeros).
///
/// This encoding is used by the Withdraw contract to store the recipient
/// address in the blinding factor field.
pub fn address_to_b256(addr: Address) -> B256 {
    let mut bytes = [0u8; 32];
    bytes[12..32].copy_from_slice(addr.as_slice());
    B256::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address_with_prefix() {
        let addr = parse_address("0x1234567890123456789012345678901234567890").unwrap();
        assert_eq!(
            addr,
            Address::from_slice(&hex::decode("1234567890123456789012345678901234567890").unwrap())
        );
    }

    #[test]
    fn test_parse_address_without_prefix() {
        let addr = parse_address("1234567890123456789012345678901234567890").unwrap();
        assert_eq!(
            addr,
            Address::from_slice(&hex::decode("1234567890123456789012345678901234567890").unwrap())
        );
    }

    #[test]
    fn test_parse_address_invalid_length() {
        let result = parse_address("0x1234");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("20 bytes"));
    }

    #[test]
    fn test_parse_address_invalid_hex() {
        let result = parse_address("0xGGGG");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not valid hex"));
    }

    #[test]
    fn test_parse_amount_decimal() {
        assert_eq!(parse_amount("1000").unwrap(), U256::from(1000));
        assert_eq!(parse_amount("0").unwrap(), U256::from(0));
        assert_eq!(
            parse_amount("340282366920938463463374607431768211455").unwrap(),
            U256::from(u128::MAX)
        );
    }

    #[test]
    fn test_parse_amount_hex() {
        assert_eq!(parse_amount("0x3e8").unwrap(), U256::from(1000));
        assert_eq!(parse_amount("0x0").unwrap(), U256::from(0));
    }

    #[test]
    fn test_parse_amount_invalid() {
        let result = parse_amount("not_a_number");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid amount format"));
    }

    #[test]
    fn test_parse_public_key() {
        let key =
            parse_public_key("0x0102030405060708091011121314151617181920212223242526272829303132")
                .unwrap();
        assert_eq!(key[0], 0x01);
        assert_eq!(key[31], 0x32);
    }

    #[test]
    fn test_parse_public_key_invalid_length() {
        let result = parse_public_key("0x1234");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_address_to_b256() {
        let addr = Address::from_slice(&[0x11u8; 20]);
        let b256 = address_to_b256(addr);

        // First 12 bytes should be zero
        for i in 0..12 {
            assert_eq!(b256[i], 0);
        }
        // Last 20 bytes should be the address
        for i in 12..32 {
            assert_eq!(b256[i], 0x11);
        }
    }
}
