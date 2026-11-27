//! Zero-copy classic pcap 2.4 framing for offline packet analysis. File and
//! packet layouts: IETF OPSAWG pcap file format, sections 4 and 5.
//! No packet data is interpreted, copied, or padded to an alignment boundary.

use std::time::Duration;

use crate::DecodeError;

/// One packet record. A capture may contain only the first `data.len()`
/// bytes of an `original_len`-byte packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    /// Time since the Unix epoch as recorded by the capturing host.
    pub timestamp: Duration,
    /// Reported packet size before capture truncation. A rewritten capture
    /// can preserve an original length smaller than `data.len()` (§5).
    pub original_len: u32,
    /// Captured bytes, including the link-layer header and any captured FCS.
    pub data: &'a [u8],
}

/// Iterator over the records of one classic pcap file. A malformed record
/// yields one error and ends the iterator; earlier packets remain usable.
#[derive(Debug)]
pub struct Capture<'a> {
    remaining: &'a [u8],
    word: fn([u8; 4]) -> u32,
    nanos_per_tick: u32,
    snap_len: u32,
    link_type: u16,
    fcs_bytes: Option<u8>,
}

impl<'a> Capture<'a> {
    /// Opens an in-memory classic pcap, in either byte order and with either
    /// timestamp resolution. Packet headers are validated during iteration.
    ///
    /// # Errors
    /// Rejects incomplete headers, unknown formats (including pcapng), versions
    /// other than 2.4, zero snapshot length and reserved link-type flags.
    pub fn new(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let (header, remaining) =
            bytes
                .split_first_chunk::<24>()
                .ok_or(DecodeError::Truncated {
                    field: "pcap file header",
                })?;
        let (little, nanos_per_tick) = match header[..4] {
            [0xd4, 0xc3, 0xb2, 0xa1] => (true, 1000),
            [0xa1, 0xb2, 0xc3, 0xd4] => (false, 1000),
            [0x4d, 0x3c, 0xb2, 0xa1] => (true, 1),
            [0xa1, 0xb2, 0x3c, 0x4d] => (false, 1),
            _ => {
                return Err(DecodeError::Invalid {
                    field: "classic pcap magic",
                });
            }
        };
        let (version, word): (_, fn([u8; 4]) -> u32) = if little {
            ([2, 0, 4, 0], u32::from_le_bytes)
        } else {
            ([0, 2, 0, 4], u32::from_be_bytes)
        };
        if header[4..8] != version {
            return Err(DecodeError::Invalid {
                field: "pcap version (expected 2.4)",
            });
        }
        let snap_len = word([header[16], header[17], header[18], header[19]]);
        if snap_len == 0 {
            return Err(DecodeError::Invalid {
                field: "pcap snapshot length",
            });
        }
        let link = word([header[20], header[21], header[22], header[23]]);
        if link & 0x0bff_0000 != 0 {
            return Err(DecodeError::Invalid {
                field: "pcap reserved link-type bits",
            });
        }
        let [fcs, _, hi, lo] = link.to_be_bytes();
        Ok(Self {
            remaining,
            word,
            nanos_per_tick,
            snap_len,
            link_type: u16::from_be_bytes([hi, lo]),
            fcs_bytes: (fcs & 0x04 != 0).then_some((fcs >> 4) * 2),
        })
    }

    /// IANA PCAP `LinkType` shared by all packets in this capture.
    #[must_use]
    pub fn link_type(&self) -> u16 {
        self.link_type
    }

    /// Declared frame check sequence length in bytes, if present.
    #[must_use]
    pub fn fcs_bytes(&self) -> Option<u8> {
        self.fcs_bytes
    }

    /// Consumes one packet header and exactly its declared captured length.
    fn packet(&mut self) -> Result<Packet<'a>, DecodeError> {
        let (h, body) = self
            .remaining
            .split_first_chunk::<16>()
            .ok_or(DecodeError::Truncated {
                field: "pcap packet header",
            })?;
        let word = self.word;
        let secs = word([h[0], h[1], h[2], h[3]]);
        let fraction = word([h[4], h[5], h[6], h[7]]);
        if fraction >= 1_000_000_000 / self.nanos_per_tick {
            return Err(DecodeError::Invalid {
                field: "pcap timestamp fraction",
            });
        }
        let captured = word([h[8], h[9], h[10], h[11]]);
        let original_len = word([h[12], h[13], h[14], h[15]]);
        if captured > self.snap_len {
            return Err(DecodeError::Invalid {
                field: "pcap captured length",
            });
        }
        let (data, remaining) =
            body.split_at_checked(captured as usize)
                .ok_or(DecodeError::Truncated {
                    field: "pcap packet data",
                })?;
        self.remaining = remaining;
        Ok(Packet {
            timestamp: Duration::new(u64::from(secs), fraction * self.nanos_per_tick),
            original_len,
            data,
        })
    }
}

impl<'a> Iterator for Capture<'a> {
    type Item = Result<Packet<'a>, DecodeError>;

    /// Stops at EOF or after the first error. Even a zero-length packet consumes its header.
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let packet = self.packet();
        if packet.is_err() {
            self.remaining = &[];
        }
        Some(packet)
    }
}

impl std::iter::FusedIterator for Capture<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pair of unaligned records: one clipped three-byte packet and one empty packet.
    fn capture(magic: u32, little: bool) -> Vec<u8> {
        let word = if little {
            u32::to_le_bytes
        } else {
            u32::to_be_bytes
        };
        let version = if little { [2, 0, 4, 0] } else { [0, 2, 0, 4] };
        let mut bytes = word(magic).to_vec();
        bytes.extend(version);
        for value in [0, 0, 64, 0x2400_0001, 7, 37, 3, 17] {
            bytes.extend(word(value));
        }
        bytes.extend([1, 2, 3]);
        bytes.extend([0; 16]);
        bytes
    }

    /// Reads all four classic magics and advances over clipped/empty records without padding.
    #[test]
    fn byte_orders_and_resolutions() {
        for little in [true, false] {
            for (magic, nanos) in [(0xa1b2_c3d4, 37_000), (0xa1b2_3c4d, 37)] {
                let bytes = capture(magic, little);
                let mut file = Capture::new(&bytes).unwrap();
                assert_eq!((file.link_type(), file.fcs_bytes()), (1, Some(4)));
                assert_eq!(
                    file.next().unwrap().unwrap(),
                    Packet {
                        timestamp: Duration::new(7, nanos),
                        data: &[1, 2, 3],
                        original_len: 17
                    }
                );
                assert_eq!(file.next().unwrap().unwrap().data, []);
                assert!(file.next().is_none());
            }
        }
    }

    /// An incomplete record is an error, distinct from clean EOF at a record boundary.
    #[test]
    fn truncated_prefixes() {
        let bytes = capture(0xa1b2_c3d4, true);
        for n in 0..bytes.len() {
            if n < 24 {
                assert!(Capture::new(&bytes[..n]).is_err());
                continue;
            }
            let mut reader = Capture::new(&bytes[..n]).unwrap();
            assert_eq!(reader.by_ref().any(|r| r.is_err()), !matches!(n, 24 | 43));
            assert!(reader.next().is_none());
        }
    }

    /// A rewritten original length can be short without changing either record boundary.
    #[test]
    fn preserved_short_original_length() {
        let mut bytes = capture(0xa1b2_c3d4, false);
        bytes[36..40].copy_from_slice(&2u32.to_be_bytes());
        let mut records = Capture::new(&bytes).unwrap();
        let packet = records.next().unwrap().unwrap();
        assert_eq!(packet.original_len, 2);
        assert_eq!(packet.data, [1, 2, 3]);
        assert_eq!(records.next().unwrap().unwrap().data, []);
        assert!(records.next().is_none());
    }

    /// Reject incorrect magic, versions, bounds, reserved bits and invalid timestamps.
    #[test]
    fn rejects_invalid_fields() {
        for (offset, value) in [
            (0, 0x0a0d_0d0a),
            (4, 0),
            (16, 0),
            (20, 0x0800_0001),
            (28, 1_000_000),
            (32, u32::MAX),
        ] {
            let mut bytes = capture(0xa1b2_c3d4, false);
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            assert!(
                Capture::new(&bytes)
                    .and_then(Iterator::collect::<Result<Vec<_>, _>>)
                    .is_err()
            );
        }
    }
}
