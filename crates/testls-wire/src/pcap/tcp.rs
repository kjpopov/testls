//! Borrow a TCP segment from an unfragmented IPv4/IPv6 packet (RFC 791,
//! RFC 8200 §3 and RFC 9293 §3.1). Never interpret Ethernet padding as data.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Directional addresses and sequence space of one observed TCP segment.
pub(super) struct Segment<'a> {
    pub endpoints: (SocketAddr, SocketAddr),
    pub sequence: u32,
    pub flags: u8,
    pub data: &'a [u8],
}

/// Extract a complete TCP segment from Ethernet II or raw IP (IANA PCAP link types).
pub(super) fn segment(link: u16, frame: &[u8]) -> Option<Segment<'_>> {
    let (version, ip) = match link {
        1 => {
            let (eth, ip) = frame.split_first_chunk::<14>()?;
            let version = match eth[12..] {
                [8, 0] => 4,
                [0x86, 0xdd] => 6,
                _ => return None,
            };
            (version, ip)
        }
        101 => (*frame.first()? >> 4, frame),
        _ => return None,
    };
    if *ip.first()? >> 4 != version {
        return None;
    }
    let (src, dst, tcp): (IpAddr, IpAddr, _) = match version {
        4 => {
            let (h, _) = ip.split_first_chunk::<20>()?;
            // Reject fragments, MF, and the reserved flag; DF is allowed.
            if h[0] & 15 < 5 || h[9] != 6 || u16::from_be_bytes([h[6], h[7]]) & !0x4000 != 0 {
                return None;
            }
            let end = usize::from(u16::from_be_bytes([h[2], h[3]]));
            (
                Ipv4Addr::new(h[12], h[13], h[14], h[15]).into(),
                Ipv4Addr::new(h[16], h[17], h[18], h[19]).into(),
                ip.get(usize::from(h[0] & 15) * 4..end)?,
            )
        }
        6 => {
            let (h, payload) = ip.split_first_chunk::<40>()?;
            if h[6] != 6 {
                return None;
            }
            let src: [u8; 16] = h[8..24].try_into().ok()?;
            let dst: [u8; 16] = h[24..40].try_into().ok()?;
            (
                Ipv6Addr::from(src).into(),
                Ipv6Addr::from(dst).into(),
                payload.get(..usize::from(u16::from_be_bytes([h[4], h[5]])))?,
            )
        }
        _ => return None,
    };
    let (h, _) = tcp.split_first_chunk::<20>()?;
    let offset = usize::from(h[12] >> 4) * 4;
    if offset < 20 {
        return None;
    }
    Some(Segment {
        endpoints: (
            SocketAddr::new(src, u16::from_be_bytes([h[0], h[1]])),
            SocketAddr::new(dst, u16::from_be_bytes([h[2], h[3]])),
        ),
        sequence: u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
        flags: h[13],
        data: tcp.get(offset..)?,
    })
}
