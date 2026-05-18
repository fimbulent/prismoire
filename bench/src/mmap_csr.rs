//! mmap-backed CSR graph
//!
//! The idea: instead of holding the CSR's `offsets` and `targets` arrays
//! in heap `Vec<u32>`, write them to a tmpfs file and mmap it back. The
//! graph then lives in the OS page cache instead of process-resident
//! RSS, so:
//!
//! - **Steady-state RSS** is bounded by what BFS actually touches, not
//!   by total CSR bytes. The kernel evicts cold pages under pressure.
//! - **Rebuild peak** drops if the new CSR is *written* directly to a
//!   file (no `Vec<u32>` intermediate) and the swap is an mmap-pointer
//!   swap rather than two CSRs simultaneously in heap.
//! - **BFS warm perf** should match heap (same memory accesses, same
//!   cache behaviour once the page cache is warm).
//! - **BFS cold perf** pays a page-fault tax on first touch.
//!
//! This module implements only the read side + serialiser; the bench
//! mode in `main.rs` uses it for an A/B against the in-process
//! `CsrGraph`. The "stream the new CSR straight to a file" rebuild
//! path is **not** prototyped here — that's the production-side change
//! Option C would need, and we only do it if the bench validates the
//! cost model.
//!
//! ## File format (v1, host byte order, host alignment)
//!
//! ```text
//! [ 0 .. 8 ]   magic         = b"PMOIRECS"          (8 bytes)
//! [ 8 .. 12]   version       = 1u32                 (4 bytes)
//! [12 .. 16]   num_nodes     = N as u32             (4 bytes)
//! [16 .. 20]   offsets_count = N+1 as u32           (4 bytes)
//! [20 .. 24]   targets_count = E as u32             (4 bytes)
//! [24 .. ...]  offsets[N+1] : u32 array             (4·(N+1) bytes)
//! [   ...   ]  targets[E]   : u32 array             (4·E   bytes)
//! ```
//!
//! Host byte order + host alignment is fine because the file is
//! scratch space (tmpfs); we never read it on a different machine.
//! Page-aligned mmap base + 24 B header (multiple of 4) keeps both
//! arrays u32-aligned for safe `&[u32]` casts.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use memmap2::{Mmap, MmapOptions};

use crate::algo::{CsrAccess, CsrGraph};

const MAGIC: &[u8; 8] = b"PMOIRECS";
const VERSION: u32 = 1;
const HEADER_BYTES: usize = 24;

/// Serialise an in-memory `CsrGraph` to `path` in the format described
/// at the module level. Overwrites any existing file.
///
/// The write is a small fixed-size header followed by two contiguous
/// blits of `offsets` and `targets`. No intermediate buffer — we lean
/// on the kernel's write buffering.
pub fn serialize_csr_to_file(csr: &CsrGraph, path: &Path) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;

    let mut header = [0u8; HEADER_BYTES];
    header[0..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&VERSION.to_ne_bytes());
    header[12..16].copy_from_slice(&csr.num_nodes.to_ne_bytes());
    header[16..20].copy_from_slice(&(csr.offsets.len() as u32).to_ne_bytes());
    header[20..24].copy_from_slice(&(csr.targets.len() as u32).to_ne_bytes());
    f.write_all(&header)?;

    // Bit-blit u32 slices as bytes. Sound because u32 is `Copy` and
    // has no padding; the resulting file is host byte order, which is
    // exactly what `MmapCsrGraph::open` expects.
    let offsets_bytes = unsafe {
        std::slice::from_raw_parts(
            csr.offsets.as_ptr() as *const u8,
            std::mem::size_of_val(csr.offsets.as_slice()),
        )
    };
    f.write_all(offsets_bytes)?;

    let targets_bytes = unsafe {
        std::slice::from_raw_parts(
            csr.targets.as_ptr() as *const u8,
            std::mem::size_of_val(csr.targets.as_slice()),
        )
    };
    f.write_all(targets_bytes)?;

    f.sync_data()?;
    Ok(())
}

/// CSR graph whose `offsets`/`targets` arrays live in an `mmap`'d file
/// (typically tmpfs). The struct owns the `Mmap` handle; the slices
/// returned from [`Self::neighbors`] borrow from it.
///
/// Page cache management: under memory pressure the kernel can evict
/// pages from the mapped range. [`Self::madvise_dontneed`] forces
/// eviction explicitly (for the bench's cold-start measurement).
///
/// Safety: holding raw pointers + lengths into `_mmap` is the standard
/// pattern for a self-referential owner-of-mmap + slice-into-mmap
/// struct. The pointers are valid for as long as `_mmap` is alive
/// (i.e. for `'self`), so the `&[u32]` returned from `neighbors` is
/// sound under the inferred `'self` lifetime.
pub struct MmapCsrGraph {
    _mmap: Mmap,
    // Surfaced via `CsrAccess::num_nodes` for sanity checks; BFS itself
    // doesn't read it, hence the dead-code allow.
    #[allow(dead_code)]
    num_nodes: u32,
    offsets_ptr: *const u32,
    offsets_len: usize,
    targets_ptr: *const u32,
    targets_len: usize,
}

// The pointers are unique to this struct and the underlying mmap is
// read-only, so concurrent `&self` access is fine across threads.
unsafe impl Send for MmapCsrGraph {}
unsafe impl Sync for MmapCsrGraph {}

impl MmapCsrGraph {
    /// Mmap a CSR file written by [`serialize_csr_to_file`]. Validates
    /// the magic, version, and array bounds; everything else (e.g.
    /// dense-id range correctness) is trusted because the file came
    /// from a `CsrGraph` we just built.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let f = File::open(path)?;
        let mmap = unsafe { MmapOptions::new().map(&f)? };

        if mmap.len() < HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "csr file truncated (missing header)",
            ));
        }
        if &mmap[0..8] != MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "csr file magic mismatch",
            ));
        }
        let version = u32::from_ne_bytes(mmap[8..12].try_into().unwrap());
        if version != VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("csr file version {version} (expected {VERSION})"),
            ));
        }

        let num_nodes = u32::from_ne_bytes(mmap[12..16].try_into().unwrap());
        let offsets_count = u32::from_ne_bytes(mmap[16..20].try_into().unwrap()) as usize;
        let targets_count = u32::from_ne_bytes(mmap[20..24].try_into().unwrap()) as usize;

        let want_bytes = HEADER_BYTES + 4 * offsets_count + 4 * targets_count;
        if mmap.len() < want_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "csr file truncated: have {} bytes, want {} ({} offsets + {} targets)",
                    mmap.len(),
                    want_bytes,
                    offsets_count,
                    targets_count
                ),
            ));
        }

        // Page-aligned mmap base + 24 B (mul of 4) header → both arrays
        // start u32-aligned. Casting `*const u8` to `*const u32` is
        // sound under that alignment invariant.
        let base = mmap.as_ptr();
        // SAFETY: HEADER_BYTES and offsets_count·4 are within `mmap.len()`
        // by the bounds check above; alignment is guaranteed by the
        // page-aligned mmap base + multiple-of-4 header.
        let offsets_ptr = unsafe { base.add(HEADER_BYTES) as *const u32 };
        let targets_ptr = unsafe { base.add(HEADER_BYTES + 4 * offsets_count) as *const u32 };

        Ok(Self {
            _mmap: mmap,
            num_nodes,
            offsets_ptr,
            offsets_len: offsets_count,
            targets_ptr,
            targets_len: targets_count,
        })
    }

    /// Tell the kernel to evict the mmap range from the page cache.
    /// Subsequent `neighbors()` calls fault pages back in from the
    /// backing file (tmpfs → near-instant; real disk → slow). Used by
    /// the bench's cold-start measurement.
    pub fn madvise_dontneed(&self) -> std::io::Result<()> {
        // SAFETY: `_mmap.as_ptr()` + `_mmap.len()` describe a valid mapped
        // region. `MADV_DONTNEED` on a read-only file mapping discards
        // page-cache copies; the next access faults them back in from
        // the file. No aliasing concerns: we own the mapping.
        let ret = unsafe {
            libc_madvise(
                self._mmap.as_ptr() as *mut std::ffi::c_void,
                self._mmap.len(),
                MADV_DONTNEED,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Total bytes in the mapped region (header + offsets + targets).
    /// Surfaced for the bench's "what does the file weigh" line.
    pub fn mapped_bytes(&self) -> usize {
        self._mmap.len()
    }
}

impl CsrAccess for MmapCsrGraph {
    #[inline]
    fn neighbors(&self, i: u32) -> &[u32] {
        // SAFETY: `offsets_ptr` is valid for `offsets_len` u32s for
        // `'self` (tied to `_mmap`). `i < num_nodes` is the caller's
        // invariant — BFS only ever passes IDs it discovered via the
        // graph itself, so any out-of-range `i` is a bug, not data.
        let offsets = unsafe { std::slice::from_raw_parts(self.offsets_ptr, self.offsets_len) };
        let start = offsets[i as usize] as usize;
        let end = offsets[i as usize + 1] as usize;
        debug_assert!(end <= self.targets_len);
        unsafe { std::slice::from_raw_parts(self.targets_ptr.add(start), end - start) }
    }

    #[inline]
    fn num_nodes(&self) -> u32 {
        self.num_nodes
    }
}

// ---------------------------------------------------------------------------
// libc bindings for madvise (avoid adding a `libc` crate dep just for this)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const MADV_DONTNEED: std::ffi::c_int = 4;

#[cfg(not(target_os = "linux"))]
const MADV_DONTNEED: std::ffi::c_int = 4; // same value on most Unix; non-Linux not tested

unsafe extern "C" {
    /// `int madvise(void *addr, size_t length, int advice);` — POSIX
    /// memory advice. We use it only for `MADV_DONTNEED` to drop pages
    /// from the cache in the cold-start bench. Direct extern to avoid
    /// pulling in the `libc` crate for one symbol.
    #[link_name = "madvise"]
    fn libc_madvise(
        addr: *mut std::ffi::c_void,
        length: usize,
        advice: std::ffi::c_int,
    ) -> std::ffi::c_int;
}
