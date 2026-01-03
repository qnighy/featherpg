use std::{fmt, str::FromStr};

use thiserror::Error;

/// Represents a protocol version with major and minor numbers.
///
/// PostgreSQL uses the versions 3.0 to 3.2 for the frontend/backend protocol.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion {
    value: u32,
}

impl ProtocolVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self {
            value: ((major as u32) << 16) | (minor as u32),
        }
    }

    pub const fn major(self) -> u16 {
        (self.value >> 16) as u16
    }

    pub const fn minor(self) -> u16 {
        (self.value & 0xFFFF) as u16
    }
}

impl fmt::Debug for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProtocolVersion")
            .field(&self.major())
            .field(&self.minor())
            .finish()
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major(), self.minor())
    }
}

impl FromStr for ProtocolVersion {
    type Err = ParseProtocolVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('.');
        let major_str = parts.next().ok_or(ParseProtocolVersionError(()))?;
        let minor_str = parts.next().ok_or(ParseProtocolVersionError(()))?;

        if parts.next().is_some() {
            return Err(ParseProtocolVersionError(()));
        }

        let major = major_str
            .parse::<u16>()
            .map_err(|_| ParseProtocolVersionError(()))?;
        let minor = minor_str
            .parse::<u16>()
            .map_err(|_| ParseProtocolVersionError(()))?;

        Ok(ProtocolVersion::new(major, minor))
    }
}

#[derive(Debug, Error)]
#[error("failed to parse protocol version")]
pub struct ParseProtocolVersionError(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version_get_major() {
        let version = ProtocolVersion::new(3, 1);
        assert_eq!(version.major(), 3);
    }

    #[test]
    fn test_protocol_version_get_minor() {
        let version = ProtocolVersion::new(3, 1);
        assert_eq!(version.minor(), 1);
    }

    #[test]
    fn test_protocol_version_display() {
        let version = ProtocolVersion::new(3, 2);
        assert_eq!(version.to_string(), "3.2");
    }

    #[test]
    fn test_protocol_version_from_str() {
        let version: ProtocolVersion = "3.1".parse().unwrap();
        assert_eq!(version.major(), 3);
        assert_eq!(version.minor(), 1);
    }

    #[test]
    fn test_protocol_version_from_str_invalid_one_segment() {
        let result: Result<ProtocolVersion, _> = "invalid".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_protocol_version_from_str_invalid_three_segments() {
        let result: Result<ProtocolVersion, _> = "3.1.4".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_protocol_version_from_str_invalid_non_numeric_major() {
        let result: Result<ProtocolVersion, _> = "x.1".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_protocol_version_from_str_invalid_non_numeric_minor() {
        let result: Result<ProtocolVersion, _> = "3.x".parse();
        assert!(result.is_err());
    }
}
