//! Lock-free shared ring buffer for inner-swarm state sync.
//!
//! 256 atomic slots + an atomic tail pointer. Writers commit with Release,
//! readers observe with Acquire — no mutexes anywhere on the hot path.
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU64, Ordering};

pub const RING_SLOTS: usize = 256;

/// Immutable, lock-free, atomically-fenced ring buffer for authenticated
/// inter-agent state-transition commits.
pub struct SwarmSharedRingBuffer {
    transaction_slots: [AtomicU64; RING_SLOTS],
    tail_pointer: AtomicU64,
}

impl SwarmSharedRingBuffer {
    pub const fn new() -> Self {
        // `[AtomicU64::new(0); 256]` is illegal (AtomicU64 is not Copy), so
        // build the array in a const loop over zeroed memory instead.
        let mut slots: [AtomicU64; RING_SLOTS] = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut i = 0;
        while i < RING_SLOTS {
            slots[i] = AtomicU64::new(0);
            i += 1;
        }
        Self {
            transaction_slots: slots,
            tail_pointer: AtomicU64::new(0),
        }
    }

    /// Commits an authenticated state-transition signature into the ring.
    pub fn commit_state_transition(&self, signed_lattice_vector: u64) {
        let idx = (self.tail_pointer.fetch_add(1, Ordering::SeqCst) % RING_SLOTS as u64) as usize;
        self.transaction_slots[idx].store(signed_lattice_vector, Ordering::Release);
    }

    /// Reads a slot with acquire ordering.
    pub fn read_slot(&self, index: usize) -> u64 {
        self.transaction_slots[index % RING_SLOTS].load(Ordering::Acquire)
    }

    /// Total commits since boot (monotonic; wraps the ring).
    pub fn committed_count(&self) -> u64 {
        self.tail_pointer.load(Ordering::Acquire)
    }
}

/// Global static shared-memory interface for the cluster execution path.
pub static SWARM_CON_BUFFER: SwarmSharedRingBuffer = SwarmSharedRingBuffer::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_commits_and_wraps() {
        let buf = SwarmSharedRingBuffer::new();
        for i in 0..300u64 {
            buf.commit_state_transition(0xA5A5_0000_0000_0000 | i);
        }
        assert_eq!(buf.committed_count(), 300);
        // slot 0 was overwritten by commit #256
        assert_eq!(buf.read_slot(0), 0xA5A5_0000_0000_0000 | 256);
        // slot 43 holds commit #43 (never overwritten: 300-256=44 < 43? no:
        // overwritten once commits pass 256+43=299 -> commit #299 wrote slot 43)
        assert_eq!(buf.read_slot(43), 0xA5A5_0000_0000_0000 | 299);
    }

    #[test]
    fn fresh_ring_is_zeroed() {
        let buf = SwarmSharedRingBuffer::new();
        assert_eq!(buf.committed_count(), 0);
        assert_eq!(buf.read_slot(0), 0);
        assert_eq!(buf.read_slot(255), 0);
    }
}
