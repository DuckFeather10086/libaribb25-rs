//! MULTI2 block cipher implementation.
//!
//! MULTI2 is a symmetric block cipher used in ARIB STD-B25 for scrambling
//! transport stream packets. It operates on 64-bit blocks with a 256-bit
//! system key and uses CBC mode.
//!
//! Decryption can be accelerated by SIMD.  The available level is detected at
//! runtime via OS-provided CPU feature flags (AT_HWCAP / HWCAP2 on Linux,
//! CommPage on macOS).  The `Multi2` struct stores the selected `SimdLevel` so
//! that every `unsafe` SIMD call site is guarded by an explicit prior check.

use crate::error::{Multi2Error, Multi2Result};

// ---------------------------------------------------------------------------
// Public SIMD level type
// ---------------------------------------------------------------------------

/// SIMD acceleration level used for MULTI2 decryption.
///
/// The variant set describes what is **actually available on the current CPU**;
/// it is never constructed from user input without first verifying against the
/// detected capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SimdLevel {
    /// Pure Rust scalar implementation – always available.
    Scalar,
    /// ARM NEON (AArch64): 4 blocks decrypted in parallel per iteration.
    #[cfg(target_arch = "aarch64")]
    Neon,
}

impl SimdLevel {
    /// Detect the best SIMD level supported by the current CPU.
    ///
    /// Uses the OS-provided CPU feature flags (via `std::arch` macros).
    /// Always succeeds: returns `Scalar` when no SIMD is detected.
    pub fn detect() -> Self {
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("neon") {
            return SimdLevel::Neon;
        }
        SimdLevel::Scalar
    }

    /// Return a human-readable name suitable for log output.
    pub fn name(self) -> &'static str {
        match self {
            SimdLevel::Scalar => "scalar",
            #[cfg(target_arch = "aarch64")]
            SimdLevel::Neon => "NEON",
        }
    }

    /// Parse a user-supplied string into a `SimdLevel`.
    ///
    /// Accepts `"auto"`, `"scalar"`, and `"neon"` (case-insensitive).
    /// `"auto"` resolves to `SimdLevel::detect()`.
    ///
    /// Returns `None` for unrecognised values.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Some(SimdLevel::detect()),
            "scalar" => Some(SimdLevel::Scalar),
            #[cfg(target_arch = "aarch64")]
            "neon" => Some(SimdLevel::Neon),
            _ => None,
        }
    }

    /// Return the list of levels supported by this build target (not the CPU).
    pub fn build_levels() -> &'static [&'static str] {
        #[cfg(target_arch = "aarch64")]
        return &["auto", "scalar", "neon"];
        #[cfg(not(target_arch = "aarch64"))]
        return &["auto", "scalar"];
    }
}

impl std::fmt::Display for SimdLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// Internal state types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct CoreData {
    l: u32,
    r: u32,
}

#[derive(Clone, Copy)]
struct CoreParam {
    key: [u32; 8],
}

impl CoreParam {
    const fn zero() -> Self {
        Self { key: [0u32; 8] }
    }
}

// ---------------------------------------------------------------------------
// Multi2 public API
// ---------------------------------------------------------------------------

/// MULTI2 cipher state.
pub struct Multi2 {
    cbc_init: CoreData,
    sys: CoreParam,
    scr: [CoreData; 2],  // 0: odd, 1: even
    wrk: [CoreParam; 2], // 0: odd, 1: even
    round: u32,
    state: u32,
    /// The SIMD level used by `decrypt`.  Only levels that have been verified
    /// against the current CPU via `SimdLevel::detect()` are accepted.
    simd: SimdLevel,
}

const STATE_CBC_INIT_SET: u32 = 0x0001;
const STATE_SYSTEM_KEY_SET: u32 = 0x0002;
const STATE_SCRAMBLE_KEY_SET: u32 = 0x0004;
const STATE_ALL_SET: u32 = STATE_CBC_INIT_SET | STATE_SYSTEM_KEY_SET | STATE_SCRAMBLE_KEY_SET;

impl Multi2 {
    /// Create a new cipher instance with the best SIMD level detected
    /// automatically.
    pub fn new() -> Self {
        Self::with_simd(SimdLevel::detect())
    }

    /// Create a new cipher instance with an explicitly chosen SIMD level.
    ///
    /// # Panics
    /// Panics if `level` is higher than what `SimdLevel::detect()` reports for
    /// this CPU (prevents calling SIMD code on hardware that lacks the feature).
    pub fn with_simd(level: SimdLevel) -> Self {
        let detected = SimdLevel::detect();
        assert!(
            level <= detected,
            "requested SIMD level '{}' exceeds CPU capability '{}' — \
             use SimdLevel::detect() to obtain a safe level",
            level.name(),
            detected.name(),
        );
        Self {
            cbc_init: CoreData { l: 0, r: 0 },
            sys: CoreParam::zero(),
            scr: [CoreData { l: 0, r: 0 }; 2],
            wrk: [CoreParam::zero(); 2],
            round: 4,
            state: 0,
            simd: level,
        }
    }

    /// Return the SIMD level currently active for this instance.
    pub fn simd_level(&self) -> SimdLevel {
        self.simd
    }

    pub fn set_round(&mut self, val: u32) {
        self.round = val;
    }

    pub fn set_system_key(&mut self, val: &[u8; 32]) -> Multi2Result<()> {
        for i in 0..8 {
            self.sys.key[i] = load_be_u32(&val[i * 4..]);
        }
        self.state |= STATE_SYSTEM_KEY_SET;
        Ok(())
    }

    pub fn set_init_cbc(&mut self, val: &[u8; 8]) -> Multi2Result<()> {
        self.cbc_init.l = load_be_u32(&val[0..]);
        self.cbc_init.r = load_be_u32(&val[4..]);
        self.state |= STATE_CBC_INIT_SET;
        Ok(())
    }

    pub fn set_scramble_key(&mut self, val: &[u8; 16]) -> Multi2Result<()> {
        self.scr[0].l = load_be_u32(&val[0..]);
        self.scr[0].r = load_be_u32(&val[4..]);
        self.scr[1].l = load_be_u32(&val[8..]);
        self.scr[1].r = load_be_u32(&val[12..]);

        core_schedule(&mut self.wrk[0], &self.sys, self.scr[0]);
        core_schedule(&mut self.wrk[1], &self.sys, self.scr[1]);

        self.state |= STATE_SCRAMBLE_KEY_SET;
        Ok(())
    }

    pub fn clear_scramble_key(&mut self) {
        self.scr = [CoreData { l: 0, r: 0 }; 2];
        self.wrk = [CoreParam::zero(); 2];
        self.state &= !STATE_SCRAMBLE_KEY_SET;
    }

    fn check_state(&self) -> Multi2Result<()> {
        if self.state != STATE_ALL_SET {
            if self.state & STATE_CBC_INIT_SET == 0 {
                return Err(Multi2Error::UnsetCbcInit);
            }
            if self.state & STATE_SYSTEM_KEY_SET == 0 {
                return Err(Multi2Error::UnsetSystemKey);
            }
            if self.state & STATE_SCRAMBLE_KEY_SET == 0 {
                return Err(Multi2Error::UnsetScrambleKey);
            }
        }
        Ok(())
    }

    /// Encrypt buffer in CBC mode.
    /// `key_type`: 0x02 for even key, any other value for odd key.
    pub fn encrypt(&self, key_type: u32, buf: &mut [u8]) -> Multi2Result<()> {
        self.check_state()?;

        let prm = if key_type == 0x02 { &self.wrk[1] } else { &self.wrk[0] };
        let mut cbc = self.cbc_init;
        let mut p = 0;

        while p + 8 <= buf.len() {
            let src = CoreData {
                l: load_be_u32(&buf[p..]) ^ cbc.l,
                r: load_be_u32(&buf[p + 4..]) ^ cbc.r,
            };
            cbc = core_encrypt(src, prm, self.round);
            save_be_u32(&mut buf[p..], cbc.l);
            save_be_u32(&mut buf[p + 4..], cbc.r);
            p += 8;
        }

        if p < buf.len() {
            let dst = core_encrypt(cbc, prm, self.round);
            let mut tmp = [0u8; 8];
            save_be_u32(&mut tmp[0..], dst.l);
            save_be_u32(&mut tmp[4..], dst.r);
            let rem = buf.len() - p;
            for i in 0..rem {
                buf[p + i] ^= tmp[i];
            }
        }

        Ok(())
    }

    /// Decrypt buffer in CBC mode.
    /// `key_type`: 0x02 for even key, any other value for odd key.
    ///
    /// The SIMD path (if any) was selected and validated at construction time.
    /// Every `unsafe` SIMD call site is therefore preceded by a prior explicit
    /// capability check; we do NOT rely solely on `#[cfg(target_arch)]`.
    pub fn decrypt(&self, key_type: u32, buf: &mut [u8]) -> Multi2Result<()> {
        self.check_state()?;

        let prm = if key_type == 0x02 { &self.wrk[1] } else { &self.wrk[0] };
        let mut cbc = self.cbc_init;
        let mut p = 0;

        // --- NEON fast path: 4 blocks (32 bytes) at a time ---
        //
        // SAFETY: `self.simd == SimdLevel::Neon` is only true if `with_simd()`
        // verified that `is_aarch64_feature_detected!("neon")` returned `true`
        // for this process.  The slice pointer is valid for exactly 32 bytes.
        #[cfg(target_arch = "aarch64")]
        if self.simd == SimdLevel::Neon {
            while p + 32 <= buf.len() {
                let (new_l, new_r) = unsafe {
                    neon::decrypt_4blocks(
                        buf[p..].as_mut_ptr(),
                        &prm.key,
                        self.round,
                        cbc.l,
                        cbc.r,
                    )
                };
                cbc = CoreData { l: new_l, r: new_r };
                p += 32;
            }
        }

        // --- Scalar path: remaining full 8-byte blocks ---
        while p + 8 <= buf.len() {
            let src = CoreData {
                l: load_be_u32(&buf[p..]),
                r: load_be_u32(&buf[p + 4..]),
            };
            let mut dst = core_decrypt(src, prm, self.round);
            dst.l ^= cbc.l;
            dst.r ^= cbc.r;
            cbc = src;
            save_be_u32(&mut buf[p..], dst.l);
            save_be_u32(&mut buf[p + 4..], dst.r);
            p += 8;
        }

        // --- Partial trailing block (OFB-like padding) ---
        if p < buf.len() {
            let dst = core_encrypt(cbc, prm, self.round);
            let mut tmp = [0u8; 8];
            save_be_u32(&mut tmp[0..], dst.l);
            save_be_u32(&mut tmp[4..], dst.r);
            let rem = buf.len() - p;
            for i in 0..rem {
                buf[p + i] ^= tmp[i];
            }
        }

        Ok(())
    }
}

impl Default for Multi2 {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Core scalar cipher functions
// ---------------------------------------------------------------------------

#[inline(always)]
fn load_be_u32(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[0], p[1], p[2], p[3]])
}

#[inline(always)]
fn save_be_u32(p: &mut [u8], v: u32) {
    let b = v.to_be_bytes();
    p[0] = b[0]; p[1] = b[1]; p[2] = b[2]; p[3] = b[3];
}

#[inline(always)]
fn rot32(val: u32, count: u32) -> u32 {
    val.rotate_left(count)
}

fn core_pi1(src: CoreData) -> CoreData {
    CoreData { l: src.l, r: src.r ^ src.l }
}

fn core_pi2(src: CoreData, a: u32) -> CoreData {
    let t0 = src.r.wrapping_add(a);
    let t1 = rot32(t0, 1).wrapping_add(t0).wrapping_sub(1);
    let t2 = rot32(t1, 4) ^ t1;
    CoreData { l: src.l ^ t2, r: src.r }
}

fn core_pi3(src: CoreData, a: u32, b: u32) -> CoreData {
    let t0 = src.l.wrapping_add(a);
    let t1 = rot32(t0, 2).wrapping_add(t0).wrapping_add(1);
    let t2 = rot32(t1, 8) ^ t1;
    let t3 = t2.wrapping_add(b);
    let t4 = rot32(t3, 1).wrapping_sub(t3);
    let t5 = rot32(t4, 16) ^ (t4 | src.l);
    CoreData { l: src.l, r: src.r ^ t5 }
}

fn core_pi4(src: CoreData, a: u32) -> CoreData {
    let t0 = src.r.wrapping_add(a);
    let t1 = rot32(t0, 2).wrapping_add(t0).wrapping_add(1);
    CoreData { l: src.l ^ t1, r: src.r }
}

fn core_schedule(work: &mut CoreParam, skey: &CoreParam, dkey: CoreData) {
    let b1 = core_pi1(dkey);
    let b2 = core_pi2(b1, skey.key[0]);
    work.key[0] = b2.l;
    let b3 = core_pi3(b2, skey.key[1], skey.key[2]);
    work.key[1] = b3.r;
    let b4 = core_pi4(b3, skey.key[3]);
    work.key[2] = b4.l;
    let b5 = core_pi1(b4);
    work.key[3] = b5.r;
    let b6 = core_pi2(b5, skey.key[4]);
    work.key[4] = b6.l;
    let b7 = core_pi3(b6, skey.key[5], skey.key[6]);
    work.key[5] = b7.r;
    let b8 = core_pi4(b7, skey.key[7]);
    work.key[6] = b8.l;
    let b9 = core_pi1(b8);
    work.key[7] = b9.r;
}

fn core_encrypt(src: CoreData, w: &CoreParam, round: u32) -> CoreData {
    let mut d = src;
    for _ in 0..round {
        let t = core_pi1(d);
        let t = core_pi2(t, w.key[0]);
        let t = core_pi3(t, w.key[1], w.key[2]);
        let t = core_pi4(t, w.key[3]);
        let t = core_pi1(t);
        let t = core_pi2(t, w.key[4]);
        let t = core_pi3(t, w.key[5], w.key[6]);
        d = core_pi4(t, w.key[7]);
    }
    d
}

fn core_decrypt(src: CoreData, w: &CoreParam, round: u32) -> CoreData {
    let mut d = src;
    for _ in 0..round {
        let t = core_pi4(d, w.key[7]);
        let t = core_pi3(t, w.key[5], w.key[6]);
        let t = core_pi2(t, w.key[4]);
        let t = core_pi1(t);
        let t = core_pi4(t, w.key[3]);
        let t = core_pi3(t, w.key[1], w.key[2]);
        let t = core_pi2(t, w.key[0]);
        d = core_pi1(t);
    }
    d
}

// ---------------------------------------------------------------------------
// AArch64 NEON SIMD — 4-block-parallel decryption
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
mod neon {
    use std::arch::aarch64::*;

    #[inline(always)]
    unsafe fn rot1(v: uint32x4_t) -> uint32x4_t {
        vorrq_u32(vshlq_n_u32::<1>(v), vshrq_n_u32::<31>(v))
    }
    #[inline(always)]
    unsafe fn rot2(v: uint32x4_t) -> uint32x4_t {
        vorrq_u32(vshlq_n_u32::<2>(v), vshrq_n_u32::<30>(v))
    }
    #[inline(always)]
    unsafe fn rot4(v: uint32x4_t) -> uint32x4_t {
        vorrq_u32(vshlq_n_u32::<4>(v), vshrq_n_u32::<28>(v))
    }
    #[inline(always)]
    unsafe fn rot8(v: uint32x4_t) -> uint32x4_t {
        vorrq_u32(vshlq_n_u32::<8>(v), vshrq_n_u32::<24>(v))
    }
    #[inline(always)]
    unsafe fn rot16(v: uint32x4_t) -> uint32x4_t {
        vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(v)))
    }

    #[inline(always)]
    unsafe fn pi1(l: uint32x4_t, r: uint32x4_t) -> (uint32x4_t, uint32x4_t) {
        (l, veorq_u32(r, l))
    }

    #[inline(always)]
    unsafe fn pi2(l: uint32x4_t, r: uint32x4_t, a: uint32x4_t) -> (uint32x4_t, uint32x4_t) {
        let t0 = vaddq_u32(r, a);
        let t1 = vsubq_u32(vaddq_u32(rot1(t0), t0), vdupq_n_u32(1));
        let t2 = veorq_u32(rot4(t1), t1);
        (veorq_u32(l, t2), r)
    }

    #[inline(always)]
    unsafe fn pi3(l: uint32x4_t, r: uint32x4_t, a: uint32x4_t, b: uint32x4_t) -> (uint32x4_t, uint32x4_t) {
        let t0 = vaddq_u32(l, a);
        let t1 = vaddq_u32(vaddq_u32(rot2(t0), t0), vdupq_n_u32(1));
        let t2 = veorq_u32(rot8(t1), t1);
        let t3 = vaddq_u32(t2, b);
        // rot1(t3) - t3  ==  t3 + (t3 >> 31)
        let t4 = vaddq_u32(t3, vshrq_n_u32::<31>(t3));
        let t5 = veorq_u32(rot16(t4), vorrq_u32(t4, l));
        (l, veorq_u32(r, t5))
    }

    #[inline(always)]
    unsafe fn pi4(l: uint32x4_t, r: uint32x4_t, a: uint32x4_t) -> (uint32x4_t, uint32x4_t) {
        let t0 = vaddq_u32(r, a);
        let t1 = vaddq_u32(vaddq_u32(rot2(t0), t0), vdupq_n_u32(1));
        (veorq_u32(l, t1), r)
    }

    /// Decrypt 4 consecutive MULTI2 blocks (32 bytes) in-place using NEON.
    ///
    /// Returns the new CBC state `(l, r)` for the next call.
    ///
    /// # Safety
    /// The caller **must** have confirmed `is_aarch64_feature_detected!("neon")`
    /// before reaching this call site (enforced by `Multi2::with_simd`).
    /// `data` must be valid for exactly 32 bytes of read + write.
    #[target_feature(enable = "neon")]
    pub unsafe fn decrypt_4blocks(
        data: *mut u8,
        key: &[u32; 8],
        round: u32,
        cbc_l: u32,
        cbc_r: u32,
    ) -> (u32, u32) {
        let k0 = vdupq_n_u32(key[0]);
        let k1 = vdupq_n_u32(key[1]);
        let k2 = vdupq_n_u32(key[2]);
        let k3 = vdupq_n_u32(key[3]);
        let k4 = vdupq_n_u32(key[4]);
        let k5 = vdupq_n_u32(key[5]);
        let k6 = vdupq_n_u32(key[6]);
        let k7 = vdupq_n_u32(key[7]);

        // vld2q_u32 deinterleaves: raw.0 = [L0,L1,L2,L3], raw.1 = [R0,R1,R2,R3]
        // (native LE u32); vrev32q_u8 converts each word to the BE value MULTI2
        // operates on.
        let raw = vld2q_u32(data as *const u32);
        let bswap = |v: uint32x4_t| -> uint32x4_t {
            vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v)))
        };
        let c_l = bswap(raw.0);
        let c_r = bswap(raw.1);

        let (mut l, mut r) = (c_l, c_r);
        for _ in 0..round {
            let (l1, r1) = pi4(l,  r,  k7);
            let (l2, r2) = pi3(l1, r1, k5, k6);
            let (l3, r3) = pi2(l2, r2, k4);
            let (l4, r4) = pi1(l3, r3);
            let (l5, r5) = pi4(l4, r4, k3);
            let (l6, r6) = pi3(l5, r5, k1, k2);
            let (l7, r7) = pi2(l6, r6, k0);
            let (l8, r8) = pi1(l7, r7);
            l = l8; r = r8;
        }

        // CBC XOR: P[i] = D[i] ^ C[i-1], where P[0] uses the incoming state.
        // Build [cbc_l, C0L, C1L, C2L] using extract + lane-insert.
        // vextq_u32::<3>(c_l, c_l) = [C3L, C0L, C1L, C2L]
        let prev_l = vsetq_lane_u32::<0>(cbc_l, vextq_u32::<3>(c_l, c_l));
        let prev_r = vsetq_lane_u32::<0>(cbc_r, vextq_u32::<3>(c_r, c_r));

        let p_l = veorq_u32(l, prev_l);
        let p_r = veorq_u32(r, prev_r);

        let new_cbc_l = vgetq_lane_u32::<3>(c_l);
        let new_cbc_r = vgetq_lane_u32::<3>(c_r);

        // Convert back to BE and reinterleave into memory.
        vst2q_u32(data as *mut u32, uint32x4x2_t(bswap(p_l), bswap(p_r)));

        (new_cbc_l, new_cbc_r)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cipher() -> Multi2 {
        let sys_key = [0u8; 32];
        let init_cbc = [0u8; 8];
        let scramble_key = [1u8; 16];
        let mut m = Multi2::new();
        m.set_system_key(&sys_key).unwrap();
        m.set_init_cbc(&init_cbc).unwrap();
        m.set_scramble_key(&scramble_key).unwrap();
        m
    }

    fn make_cipher_with(level: SimdLevel) -> Multi2 {
        let sys_key = [0u8; 32];
        let init_cbc = [0u8; 8];
        let scramble_key = [1u8; 16];
        let mut m = Multi2::with_simd(level);
        m.set_system_key(&sys_key).unwrap();
        m.set_init_cbc(&init_cbc).unwrap();
        m.set_scramble_key(&scramble_key).unwrap();
        m
    }

    #[test]
    fn detect_returns_valid_level() {
        let level = SimdLevel::detect();
        // Must be parse-able back to itself.
        assert_eq!(SimdLevel::from_str(level.name()), Some(level));
    }

    #[test]
    fn with_simd_rejects_higher_than_detected() {
        // Requesting anything above the detected level must panic.
        // This test is skipped if NEON is available (all levels are reachable).
        #[cfg(target_arch = "aarch64")]
        if !std::arch::is_aarch64_feature_detected!("neon") {
            let result = std::panic::catch_unwind(|| {
                Multi2::with_simd(SimdLevel::Neon)
            });
            assert!(result.is_err(), "must panic when NEON is unavailable");
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let m = make_cipher();
        let original = [0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78,
                        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];
        let mut buf = original;
        m.encrypt(0x03, &mut buf).unwrap();
        assert_ne!(buf, original);
        m.decrypt(0x03, &mut buf).unwrap();
        assert_eq!(buf, original);
    }

    #[test]
    fn neon_matches_scalar_decrypt() {
        let detected = SimdLevel::detect();
        let m_auto   = make_cipher();
        let m_scalar = make_cipher_with(SimdLevel::Scalar);

        // 4 full NEON batches (128 bytes) + partial tail.
        let original: Vec<u8> = (0u8..=167u8).collect();
        let mut encrypted = original.clone();
        m_auto.encrypt(0x03, &mut encrypted).unwrap();

        let mut got_auto = encrypted.clone();
        m_auto.decrypt(0x03, &mut got_auto).unwrap();
        assert_eq!(got_auto, original, "auto-SIMD decrypt must recover plaintext");

        let mut got_scalar = encrypted.clone();
        m_scalar.decrypt(0x03, &mut got_scalar).unwrap();
        assert_eq!(got_scalar, original, "scalar decrypt must recover plaintext");

        assert_eq!(got_auto, got_scalar,
            "auto ({}) and scalar results must be identical", detected.name());
    }

    #[test]
    fn neon_cbc_continuity() {
        let m = make_cipher();
        let n = 200; // 200 × 8 = 1600 bytes = 50 NEON batches
        let original: Vec<u8> = (0..n * 8).map(|i| (i ^ (i >> 3)) as u8).collect();
        let mut buf = original.clone();
        m.encrypt(0x03, &mut buf).unwrap();
        m.decrypt(0x03, &mut buf).unwrap();
        assert_eq!(buf, original);
    }
}
