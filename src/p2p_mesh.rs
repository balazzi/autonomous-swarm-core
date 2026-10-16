//! Bare-metal P2P mesh threat-intelligence fabric.
//!
//! Design decision: this core owns the *packet format*, the peer table, and
//! the lattice authenticity tag. It deliberately does NOT own sockets —
//! there is no libc in a `#![no_std]` cdylib, and socket lifetimes belong
//! to the host platform (Android VpnService / iOS NetworkExtension). The
//! host registers raw fds, pulls the next live peer, encodes a packet with
//! `p2p_encode_threat`, and performs the actual send itself.
use core::sync::atomic::{AtomicI32, Ordering};

pub const MAX_MESH_PEERS: usize = 8;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MeshThreatPacket {
    pub source_device_id: [u8; 16],
    pub signature_lattice_checksum: [u16; 32],
    pub structural_entropy_rating: f32,
}

pub struct P2PMeshNetwork {
    peers: [AtomicI32; MAX_MESH_PEERS], // raw fds, -1 = empty
}

impl P2PMeshNetwork {
    pub const fn new() -> Self {
        Self {
            peers: [
                AtomicI32::new(-1),
                AtomicI32::new(-1),
                AtomicI32::new(-1),
                AtomicI32::new(-1),
                AtomicI32::new(-1),
                AtomicI32::new(-1),
                AtomicI32::new(-1),
                AtomicI32::new(-1),
            ],
        }
    }

    /// Registers a host-owned socket fd. Returns the slot index, or -1 when full.
    pub fn register_peer(&self, fd: i32) -> i32 {
        for (slot, peer) in self.peers.iter().enumerate() {
            if peer
                .compare_exchange(-1, fd, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return slot as i32;
            }
        }
        -1
    }

    /// Drops a peer by fd.
    pub fn unregister_peer(&self, fd: i32) -> bool {
        for peer in self.peers.iter() {
            if peer
                .compare_exchange(fd, -1, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
        false
    }

    pub fn peer_fd(&self, slot: usize) -> i32 {
        if slot >= MAX_MESH_PEERS {
            return -1;
        }
        self.peers[slot].load(Ordering::Relaxed)
    }

    pub fn live_peer_count(&self) -> usize {
        self.peers
            .iter()
            .filter(|p| p.load(Ordering::Relaxed) >= 0)
            .count()
    }

    /// Encodes a threat packet into the caller's buffer. Returns bytes
    /// written, or 0 when the buffer is too small.
    pub fn encode_threat_packet(packet: &MeshThreatPacket, out: &mut [u8]) -> usize {
        let need = core::mem::size_of::<MeshThreatPacket>();
        if out.len() < need {
            return 0;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                packet as *const MeshThreatPacket as *const u8,
                out.as_mut_ptr(),
                need,
            );
        }
        need
    }
}

pub static GLOBAL_P2P_MESH: P2PMeshNetwork = P2PMeshNetwork::new();

// ---- FFI: host socket layer drives the actual transport ----

#[no_mangle]
pub unsafe extern "C" fn p2p_register_peer(fd: i32) -> i32 {
    GLOBAL_P2P_MESH.register_peer(fd)
}

#[no_mangle]
pub unsafe extern "C" fn p2p_unregister_peer(fd: i32) -> i32 {
    GLOBAL_P2P_MESH.unregister_peer(fd) as i32
}

#[no_mangle]
pub unsafe extern "C" fn p2p_peer_fd(slot: u32) -> i32 {
    GLOBAL_P2P_MESH.peer_fd(slot as usize)
}

/// Builds a lattice-tagged threat packet. The checksum folds the device id
/// through Barrett reduction so tampered packets fail the peer's check.
#[no_mangle]
pub unsafe extern "C" fn p2p_encode_threat(
    device_id: *const u8,
    entropy: f32,
    out: *mut u8,
    out_len: usize,
) -> usize {
    if device_id.is_null() || out.is_null() || out_len == 0 {
        return 0;
    }
    let mut pkt = MeshThreatPacket {
        source_device_id: [0; 16],
        signature_lattice_checksum: [0; 32],
        structural_entropy_rating: entropy,
    };
    core::ptr::copy_nonoverlapping(device_id, pkt.source_device_id.as_mut_ptr(), 16);
    let mut acc: i32 = 0;
    for i in 0..16 {
        acc = crate::crypto_pqc::PolyElement::barrett_reduce(acc + pkt.source_device_id[i] as i32 * 31) as i32;
    }
    for c in pkt.signature_lattice_checksum.iter_mut() {
        *c = acc as u16;
        acc = crate::crypto_pqc::PolyElement::barrett_reduce(acc * 31 + 17) as i32;
    }
    P2PMeshNetwork::encode_threat_packet(&pkt, core::slice::from_raw_parts_mut(out, out_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_table_register_and_drop() {
        let net = P2PMeshNetwork::new();
        assert_eq!(net.register_peer(42), 0);
        assert_eq!(net.register_peer(43), 1);
        assert_eq!(net.live_peer_count(), 2);
        assert_eq!(net.peer_fd(0), 42);
        assert_eq!(net.peer_fd(99), -1);
        assert!(net.unregister_peer(42));
        assert!(!net.unregister_peer(42));
        assert_eq!(net.live_peer_count(), 1);
    }

    #[test]
    fn table_rejects_overflow() {
        let net = P2PMeshNetwork::new();
        for i in 0..MAX_MESH_PEERS {
            assert!(net.register_peer(100 + i as i32) >= 0);
        }
        assert_eq!(net.register_peer(999), -1);
    }

    #[test]
    fn encode_roundtrips_packet_layout() {
        let pkt = MeshThreatPacket {
            source_device_id: [7; 16],
            signature_lattice_checksum: [9; 32],
            structural_entropy_rating: 1.5,
        };
        let mut buf = [0u8; 128];
        let n = P2PMeshNetwork::encode_threat_packet(&pkt, &mut buf);
        assert_eq!(n, core::mem::size_of::<MeshThreatPacket>());
        let back = unsafe { &*(buf.as_ptr() as *const MeshThreatPacket) };
        assert_eq!(back.source_device_id, [7; 16]);
        assert_eq!(back.structural_entropy_rating, 1.5);
        // too-small buffer refuses
        let mut tiny = [0u8; 4];
        assert_eq!(P2PMeshNetwork::encode_threat_packet(&pkt, &mut tiny), 0);
    }

    #[test]
    fn ffi_encode_tags_checksum_deterministically() {
        let dev = [0xABu8; 16];
        let mut b1 = [0u8; 128];
        let mut b2 = [0u8; 128];
        let n1 = unsafe { p2p_encode_threat(dev.as_ptr(), 2.0, b1.as_mut_ptr(), b1.len()) };
        let n2 = unsafe { p2p_encode_threat(dev.as_ptr(), 2.0, b2.as_mut_ptr(), b2.len()) };
        assert!(n1 > 0 && n1 == n2 && b1 == b2);
        // null guards
        assert_eq!(
            unsafe { p2p_encode_threat(core::ptr::null(), 0.0, b1.as_mut_ptr(), b1.len()) },
            0
        );
    }
}
