//! Network fields: an address compared against networks.
//!
//! `fd.net`, `fd.cnet`, `fd.snet`, `fd.lnet` and `fd.rnet` carry an address,
//! and `=`, `!=` and `in` ask whether it lies inside a network written as
//! `10.0.0.0/8` or `2001:db8::/32`. A plain address is a network of one.

use std::net::IpAddr;

use crate::lang::{Item, Op};

/// Whether `field` holds an address compared by network.
pub(super) fn is_network_field(field: &str) -> bool {
    matches!(
        field,
        "fd.net" | "fd.cnet" | "fd.snet" | "fd.lnet" | "fd.rnet"
    )
}

/// The comparison, or `None` for an operator that is not about networks.
pub(super) fn compare(address: &str, op: Op, items: &[Item]) -> Option<bool> {
    let inside_any = || {
        let Ok(address) = address.trim().parse::<IpAddr>() else {
            return false;
        };
        items.iter().any(|item| contains(item.text(), address))
    };
    match op {
        Op::Eq | Op::In => Some(inside_any()),
        Op::Ne => Some(!inside_any()),
        _ => None,
    }
}

/// Whether `network` (`a.b.c.d/n`, `x::/n`, or a plain address) holds `address`.
fn contains(network: &str, address: IpAddr) -> bool {
    let (base, bits) = match network.split_once('/') {
        Some((base, bits)) => match bits.parse::<u32>() {
            Ok(bits) => (base, Some(bits)),
            Err(_) => return false,
        },
        None => (network, None),
    };
    let Ok(base) = base.parse::<IpAddr>() else {
        return false;
    };
    match (base, address) {
        (IpAddr::V4(base), IpAddr::V4(address)) => {
            let bits = bits.unwrap_or(32);
            bits <= 32
                && prefix(
                    u128::from(base.to_bits()),
                    u128::from(address.to_bits()),
                    bits,
                    32,
                )
        }
        (IpAddr::V6(base), IpAddr::V6(address)) => {
            let bits = bits.unwrap_or(128);
            bits <= 128 && prefix(base.to_bits(), address.to_bits(), bits, 128)
        }
        _ => false,
    }
}

/// Whether the top `bits` of two `width`-bit numbers agree.
fn prefix(base: u128, address: u128, bits: u32, width: u32) -> bool {
    if bits == 0 {
        return true;
    }
    let shift = width - bits;
    base.checked_shr(shift).unwrap_or(0) == address.checked_shr(shift).unwrap_or(0)
}
