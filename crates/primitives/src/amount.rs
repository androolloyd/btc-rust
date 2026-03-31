use std::fmt;
use std::ops::{Add, Sub};

/// Amount in satoshis. Bitcoin amounts are always represented as satoshis internally.
/// 1 BTC = 100,000,000 satoshis
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Amount(i64);

impl Amount {
    pub const ZERO: Amount = Amount(0);
    pub const ONE_SAT: Amount = Amount(1);
    pub const ONE_BTC: Amount = Amount(100_000_000);
    pub const MAX_MONEY: Amount = Amount(21_000_000 * 100_000_000);

    pub const fn from_sat(satoshis: i64) -> Self {
        Amount(satoshis)
    }

    pub const fn from_btc(btc: i64) -> Self {
        Amount(btc * 100_000_000)
    }

    pub const fn as_sat(self) -> i64 {
        self.0
    }

    pub fn as_btc(self) -> f64 {
        self.0 as f64 / 100_000_000.0
    }

    pub fn is_valid(self) -> bool {
        self.0 >= 0 && self.0 <= Self::MAX_MONEY.0
    }
}

impl Add for Amount {
    type Output = Amount;
    fn add(self, rhs: Self) -> Self::Output {
        Amount(self.0 + rhs.0)
    }
}

impl Sub for Amount {
    type Output = Amount;
    fn sub(self, rhs: Self) -> Self::Output {
        Amount(self.0 - rhs.0)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let btc = self.0 / 100_000_000;
        let sat = (self.0 % 100_000_000).abs();
        if self.0 < 0 {
            write!(f, "-{}.{:08} BTC", btc.abs(), sat)
        } else {
            write!(f, "{}.{:08} BTC", btc, sat)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amount_basics() {
        assert_eq!(Amount::ONE_BTC.as_sat(), 100_000_000);
        assert_eq!(Amount::from_sat(50_000_000).as_btc(), 0.5);
        assert_eq!(Amount::MAX_MONEY.as_sat(), 2_100_000_000_000_000);
    }

    #[test]
    fn test_amount_arithmetic() {
        let a = Amount::from_sat(100);
        let b = Amount::from_sat(50);
        assert_eq!((a + b).as_sat(), 150);
        assert_eq!((a - b).as_sat(), 50);
    }

    #[test]
    fn test_amount_validity() {
        assert!(Amount::ZERO.is_valid());
        assert!(Amount::MAX_MONEY.is_valid());
        assert!(!Amount::from_sat(-1).is_valid());
        assert!(!Amount::from_sat(Amount::MAX_MONEY.as_sat() + 1).is_valid());
    }

    #[test]
    fn test_amount_display() {
        assert_eq!(Amount::ONE_BTC.to_string(), "1.00000000 BTC");
        assert_eq!(Amount::from_sat(123456789).to_string(), "1.23456789 BTC");
    }
}
