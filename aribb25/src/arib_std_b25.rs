//! ARIB STD-B25 TS Descrambler.
//!
//! Decrypts scrambled MPEG-TS streams using a B-CAS or A-CAS smart card.
//!
//! # Usage
//! ```no_run
//! use aribb25::b_cas_card::BCasCard;
//! use aribb25::arib_std_b25::AribStdB25;
//!
//! let mut bcas = BCasCard::new();
//! bcas.init().unwrap();
//!
//! let mut b25 = AribStdB25::new();
//! b25.set_b_cas_card(bcas).unwrap();
//!
//! let ts_bytes: Vec<u8> = std::fs::read("input.m2t").unwrap();
//!
//! // Feed TS data in chunks
//! b25.put(&ts_bytes).unwrap();
//!
//! // Retrieve decrypted data
//! let decrypted = b25.get().unwrap();
//! ```

use crate::b_cas_card::{BCasCard, BCasInitStatus};
use crate::error::{B25Error, B25Result, B25Warn};
use crate::multi2::{Multi2, SimdLevel};
use crate::ts_common_types::{extract_ts_header, TsHeader, TsSection};
use crate::ts_section_parser::TsSectionParser;

// ---------------------------------------------------------------------------
// Table/descriptor constants
// ---------------------------------------------------------------------------

const TS_SECTION_ID_PROGRAM_ASSOCIATION: u8 = 0x00;
const TS_SECTION_ID_CONDITIONAL_ACCESS: u8  = 0x01;
const TS_SECTION_ID_PROGRAM_MAP: u8         = 0x02;
const TS_SECTION_ID_ECM_S: u8               = 0x82;
const TS_SECTION_ID_EMM_S: u8               = 0x84;
const TS_SECTION_ID_EMM_MESSAGE: u8         = 0x85;
const TS_DESCRIPTOR_TAG_CA: u8              = 0x09;

const PID_PAT: u16 = 0x0000;
const PID_CAT: u16 = 0x0001;
const PID_NULL: u16 = 0x1fff;

// How much data to probe before giving up on finding PAT / PMT / ECM.
const PAT_SEARCH_LIMIT: usize = 16 * 1024 * 1024;
const PMT_SEARCH_LIMIT: usize = 32 * 1024 * 1024;
const ECM_SEARCH_LIMIT: usize = 32 * 1024 * 1024;

/// Minimum and maximum TS packet unit sizes.
const TS_PACKET_SIZE: usize = 188;
const UNIT_SIZE_MAX: usize  = 320;

// ---------------------------------------------------------------------------
// Internal data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum PidMapType {
    Unknown,
    Pat,
    Cat,
    Pmt,
    Nit,
    Pcr,
    Ecm,
    Emm,
    Eit,
    Other,
}

#[derive(Clone)]
struct PidMap {
    map_type: PidMapType,
    /// Reference count (number of streams using this PID).
    ref_count: u32,
    /// Index into `programs` for PMT PIDs, or into `decryptors` for ECM PIDs.
    target_idx: Option<usize>,
    normal_packet: i64,
    undecrypted: i64,
}

impl Default for PidMap {
    fn default() -> Self {
        Self {
            map_type: PidMapType::Unknown,
            ref_count: 0,
            target_idx: None,
            normal_packet: 0,
            undecrypted: 0,
        }
    }
}

#[allow(dead_code)]
struct StreamEntry {
    pid: u16,
    stream_type: u8,
}

struct TsProgram {
    program_number: u16,
    pmt_pid: u16,
    pmt: TsSectionParser,
    pcr_pid: u16,
    /// Phase: 0=not yet received, 1=received once, 2=received again.
    phase: u8,
    streams: Vec<StreamEntry>,
    old_streams: Vec<StreamEntry>,
}

struct Decryptor {
    ecm_pid: u16,
    ecm: TsSectionParser,
    m2: Option<Multi2>,
    unpurchased: i32,
    last_error: u16,
    /// When non-zero the previous ECM was unpurchased; skip sends to reduce load.
    locked: u32,
    /// Phase: 0=not yet received, 1=received once, 2=received again.
    phase: u8,
    /// Number of streams referencing this decryptor.
    ref_count: u32,
}

impl Decryptor {
    fn new(ecm_pid: u16) -> Self {
        Self {
            ecm_pid,
            ecm: TsSectionParser::new(),
            m2: None,
            unpurchased: 0,
            last_error: 0,
            locked: 0,
            phase: 0,
            ref_count: 0,
        }
    }
}

/// Per-program statistics exposed to the caller.
#[derive(Debug, Default, Clone)]
pub struct ProgramInfo {
    pub program_number: u16,
    pub ecm_unpurchased_count: i32,
    pub last_ecm_error_code: u16,
    pub total_packet_count: i64,
    pub undecrypted_packet_count: i64,
}

// ---------------------------------------------------------------------------
// Main decoder
// ---------------------------------------------------------------------------

/// ARIB STD-B25 descrambler.
pub struct AribStdB25 {
    // Configuration
    multi2_round: u32,
    multi2_simd: SimdLevel,
    strip_null: bool,
    emm_proc_on: bool,
    unit_size: usize,

    // B-CAS card
    bcas: Option<BCasCard>,
    ca_system_id: u16,
    card_ids: Vec<i64>,

    // Stream parsing state
    pat: TsSectionParser,
    cat: Option<TsSectionParser>,
    emm: Option<TsSectionParser>,
    emm_pid: u16,

    programs: Vec<TsProgram>,
    decryptors: Vec<Decryptor>, // pooled; free slots have ref_count==0

    pid_map: Box<[PidMap; 0x2000]>,

    // Byte offset into sbuf up to which we've already scanned.
    sbuf_offset: usize,

    // Input source buffer
    sbuf: Vec<u8>,
    // Output (decrypted) buffer
    dbuf: Vec<u8>,
}

impl AribStdB25 {
    /// Create a descrambler with the best SIMD level auto-detected.
    pub fn new() -> Self {
        Self::new_with_simd(SimdLevel::detect())
    }

    /// Create a descrambler with an explicitly chosen SIMD level.
    ///
    /// `level` must not exceed `SimdLevel::detect()` for this CPU; the
    /// underlying `Multi2::with_simd` will panic otherwise.
    pub fn new_with_simd(level: SimdLevel) -> Self {
        Self {
            multi2_round: 4,
            multi2_simd: level,
            strip_null: false,
            emm_proc_on: false,
            unit_size: 0,
            bcas: None,
            ca_system_id: 0,
            card_ids: Vec::new(),
            pat: TsSectionParser::new(),
            cat: None,
            emm: None,
            emm_pid: 0,
            programs: Vec::new(),
            decryptors: Vec::new(),
            pid_map: Box::new(std::array::from_fn(|_| PidMap::default())),
            sbuf_offset: 0,
            sbuf: Vec::new(),
            dbuf: Vec::new(),
        }
    }

    /// Set the number of MULTI2 cipher rounds (default: 4).
    pub fn set_multi2_round(&mut self, round: u32) {
        self.multi2_round = round;
    }

    /// When true, null (padding) TS packets (PID 0x1FFF) are stripped.
    pub fn set_strip(&mut self, strip: bool) {
        self.strip_null = strip;
    }

    /// When true, EMM messages are forwarded to the smart card.
    pub fn set_emm_proc(&mut self, on: bool) {
        self.emm_proc_on = on;
    }

    /// Override the automatic unit-size detection.
    pub fn set_unit_size(&mut self, size: usize) -> B25Result<()> {
        if size < TS_PACKET_SIZE || size > UNIT_SIZE_MAX {
            return Err(B25Error::InvalidParam);
        }
        self.unit_size = size;
        Ok(())
    }

    /// Attach the smart card.  Must be called before `put()`.
    pub fn set_b_cas_card(&mut self, mut bcas: BCasCard) -> B25Result<()> {
        let stat = bcas.get_init_status().map_err(B25Error::BCasCard)?;
        self.ca_system_id = stat.ca_system_id;
        let ids = bcas.get_id().map_err(B25Error::BCasCard)?;
        self.card_ids = ids;
        self.bcas = Some(bcas);
        Ok(())
    }

    /// Reset all state (keeps card and configuration).
    pub fn reset(&mut self) {
        self.teardown();
    }

    /// Flush remaining buffered data through the decoder.
    pub fn flush(&mut self) -> B25Result<()> {
        if self.unit_size < TS_PACKET_SIZE {
            self.select_unit_size()?;
            if self.unit_size < TS_PACKET_SIZE {
                return Err(B25Error::NonTsInputStream);
            }
        }
        self.proc_arib_std_b25()
    }

    /// Feed raw TS bytes into the decoder.
    pub fn put(&mut self, data: &[u8]) -> B25Result<Option<B25Warn>> {
        self.sbuf.extend_from_slice(data);

        if self.unit_size < TS_PACKET_SIZE {
            self.select_unit_size()?;
            if self.unit_size < TS_PACKET_SIZE {
                return Ok(Some(B25Warn::PatNotComplete));
            }
        }

        if self.programs.is_empty() {
            self.find_pat()?;
            if self.programs.is_empty() {
                if self.sbuf_offset < PAT_SEARCH_LIMIT {
                    return Ok(Some(B25Warn::PatNotComplete));
                } else {
                    return Err(B25Error::NoPat);
                }
            }
            self.sbuf_offset = 0;
        }

        if !self.check_pmt_complete() {
            self.find_pmt()?;
            if !self.check_pmt_complete() {
                if self.sbuf_offset < PMT_SEARCH_LIMIT {
                    return Ok(Some(B25Warn::PmtNotComplete));
                } else {
                    return Err(B25Error::NoPmt);
                }
            }
            self.sbuf_offset = 0;
        }

        if !self.check_ecm_complete() {
            self.find_ecm()?;
            if !self.check_ecm_complete() {
                if self.sbuf_offset < ECM_SEARCH_LIMIT {
                    return Ok(Some(B25Warn::EcmNotComplete));
                } else {
                    return Err(B25Error::NoEcm);
                }
            }
            self.sbuf_offset = 0;
        }

        self.proc_arib_std_b25()?;
        Ok(None)
    }

    /// Return the decrypted output buffer and clear it.
    pub fn get(&mut self) -> B25Result<Vec<u8>> {
        Ok(std::mem::take(&mut self.dbuf))
    }

    /// Withdraw the unconsumed input buffer and clear it.
    pub fn withdraw(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.sbuf)
    }

    /// Returns per-program statistics.
    pub fn get_program_info(&self) -> Vec<ProgramInfo> {
        let mut result = Vec::with_capacity(self.programs.len());
        for pgrm in &self.programs {
            let mut info = ProgramInfo { program_number: pgrm.program_number, ..Default::default() };

            // PMT PID
            let pmt_map = &self.pid_map[pgrm.pmt_pid as usize];
            info.total_packet_count += pmt_map.normal_packet + pmt_map.undecrypted;
            info.undecrypted_packet_count += pmt_map.undecrypted;

            // PCR PID
            if pgrm.pcr_pid != 0 && pgrm.pcr_pid != PID_NULL {
                let pcr_map = &self.pid_map[pgrm.pcr_pid as usize];
                info.total_packet_count += pcr_map.normal_packet + pcr_map.undecrypted;
                info.undecrypted_packet_count += pcr_map.undecrypted;
            }

            // Elementary stream PIDs
            for strm in &pgrm.streams {
                let sm = &self.pid_map[strm.pid as usize];
                if sm.map_type == PidMapType::Ecm {
                    if let Some(idx) = sm.target_idx {
                        let dec = &self.decryptors[idx];
                        info.ecm_unpurchased_count += dec.unpurchased;
                        info.last_ecm_error_code = dec.last_error;
                    }
                }
                info.total_packet_count += sm.normal_packet + sm.undecrypted;
                info.undecrypted_packet_count += sm.undecrypted;
            }

            result.push(info);
        }
        result
    }

    // -----------------------------------------------------------------------
    // Internal: state management
    // -----------------------------------------------------------------------

    fn teardown(&mut self) {
        self.unit_size = 0;
        self.sbuf_offset = 0;
        self.pat.reset();
        self.cat = None;
        self.emm = None;
        self.emm_pid = 0;
        self.programs.clear();
        self.decryptors.clear();
        *self.pid_map = std::array::from_fn(|_| PidMap::default());
        self.sbuf.clear();
        self.dbuf.clear();
    }

    // -----------------------------------------------------------------------
    // Internal: unit-size detection
    // -----------------------------------------------------------------------

    fn select_unit_size(&mut self) -> B25Result<()> {
        let data = &self.sbuf;
        if data.len() < TS_PACKET_SIZE * 16 {
            return Ok(());
        }
        let scan_end = (data.len()).min(TS_PACKET_SIZE * 32);
        let slice = &data[..scan_end];

        let mut count = [0u32; UNIT_SIZE_MAX - TS_PACKET_SIZE];
        let mut i = 0;
        while i + TS_PACKET_SIZE < slice.len() {
            if slice[i] == 0x47 {
                let limit = UNIT_SIZE_MAX.min(slice.len() - i);
                for j in TS_PACKET_SIZE..limit {
                    if slice[i + j] == 0x47 {
                        count[j - TS_PACKET_SIZE] += 1;
                    }
                }
            }
            i += 1;
        }

        let (best_n, best_count) = count
            .iter()
            .enumerate()
            .max_by_key(|&(_, &c)| c)
            .map(|(i, &c)| (i + TS_PACKET_SIZE, c))
            .unwrap_or((0, 0));

        if best_count < 8 || ((best_count as usize) * best_n + 3 * best_n) < scan_end {
            if !data.is_empty() {
                return Err(B25Error::NonTsInputStream);
            }
            return Ok(());
        }

        self.unit_size = best_n;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: PAT scanning
    // -----------------------------------------------------------------------

    fn find_pat(&mut self) -> B25Result<()> {
        let unit = self.unit_size;
        let mut offset = self.sbuf_offset;

        loop {
            if offset + unit >= self.sbuf.len() {
                break;
            }
            // Check two consecutive sync bytes for robustness.
            if self.sbuf[offset] != 0x47 || self.sbuf[offset + unit] != 0x47 {
                if let Some(new_off) = self.resync(offset) {
                    offset = new_off;
                } else {
                    break;
                }
                continue;
            }

            let hdr = extract_ts_header(&self.sbuf[offset..]);
            if hdr.pid == PID_PAT {
                let payload_bytes = {
                    let (payload, _n) = self.packet_payload(&hdr, offset);
                    payload.to_vec()
                };
                if !payload_bytes.is_empty() {
                    if self.pat.put(&hdr, &payload_bytes).is_err() {
                        self.sbuf_offset = offset + unit;
                        return Err(B25Error::PatParseFailure);
                    }
                    if self.pat.get_count() > 0 {
                        offset += unit;
                        break;
                    }
                }
            }

            offset += unit;
        }

        self.sbuf_offset = offset;

        if self.pat.get_count() > 0 {
            self.proc_pat()?;
        }

        Ok(())
    }

    fn proc_pat(&mut self) -> B25Result<()> {
        let sect = self.pat.get().ok_or(B25Error::PatParseFailure)?;

        if sect.hdr.table_id != TS_SECTION_ID_PROGRAM_ASSOCIATION {
            return Ok(());
        }

        let data = sect.data();
        let len = data.len().saturating_sub(4); // strip CRC
        let count = len / 4;

        // Clear old programs.
        self.programs.clear();
        self.decryptors.clear();
        *self.pid_map = std::array::from_fn(|_| PidMap::default());

        let mut programs = Vec::with_capacity(count);
        let mut i = 0;
        while i + 4 <= len {
            let program_number = ((data[i] as u16) << 8) | (data[i + 1] as u16);
            let pid = (((data[i + 2] & 0x1f) as u16) << 8) | (data[i + 3] as u16);
            if program_number != 0 {
                let pgrm_idx = programs.len();
                programs.push(TsProgram {
                    program_number,
                    pmt_pid: pid,
                    pmt: TsSectionParser::new(),
                    pcr_pid: 0,
                    phase: 0,
                    streams: Vec::new(),
                    old_streams: Vec::new(),
                });
                self.pid_map[pid as usize].map_type = PidMapType::Pmt;
                self.pid_map[pid as usize].target_idx = Some(pgrm_idx);
            }
            i += 4;
        }

        self.programs = programs;
        self.pid_map[PID_PAT as usize].map_type = PidMapType::Pat;
        self.pid_map[PID_PAT as usize].ref_count = 1;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: PMT
    // -----------------------------------------------------------------------

    fn check_pmt_complete(&self) -> bool {
        if self.programs.is_empty() {
            return true;
        }
        let all_phase_0 = self.programs.iter().all(|p| p.phase == 0);
        let any_phase_2 = self.programs.iter().any(|p| p.phase >= 2);
        if any_phase_2 { return true; }
        if all_phase_0 { return false; }
        true
    }

    fn find_pmt(&mut self) -> B25Result<()> {
        let unit = self.unit_size;
        let mut offset = self.sbuf_offset;

        loop {
            if offset + unit >= self.sbuf.len() {
                break;
            }
            if self.sbuf[offset] != 0x47 || self.sbuf[offset + unit] != 0x47 {
                if let Some(new_off) = self.resync(offset) {
                    offset = new_off;
                } else {
                    break;
                }
                continue;
            }

            let hdr = extract_ts_header(&self.sbuf[offset..]);

            if hdr.pid == PID_PAT {
                let payload_bytes = {
                    let (payload, _) = self.packet_payload(&hdr, offset);
                    payload.to_vec()
                };
                if !payload_bytes.is_empty() {
                    if self.pat.put(&hdr, &payload_bytes).is_err() {
                        self.sbuf_offset = offset + unit;
                        return Err(B25Error::PatParseFailure);
                    }
                    if self.pat.get_count() > 0 {
                        self.proc_pat()?;
                        // Reset sbuf head to current packet and restart.
                        let keep = self.sbuf.split_off(offset);
                        self.sbuf = keep;
                        self.sbuf_offset = 0;
                        return Ok(());
                    }
                }
                offset += unit;
                continue;
            }

            if self.pid_map[hdr.pid as usize].map_type == PidMapType::Pmt {
                let pgrm_idx = match self.pid_map[hdr.pid as usize].target_idx {
                    Some(i) => i,
                    None => { offset += unit; continue; }
                };

                if self.programs[pgrm_idx].phase == 0 {
                    let payload_bytes = {
                        let (payload, _) = self.packet_payload(&hdr, offset);
                        payload.to_vec()
                    };
                    if !payload_bytes.is_empty() {
                        if self.programs[pgrm_idx].pmt.put(&hdr, &payload_bytes).is_err() {
                            self.sbuf_offset = offset + unit;
                            return Err(B25Error::PmtParseFailure);
                        }
                        if self.programs[pgrm_idx].pmt.get_count() > 0 {
                            let warn = self.proc_pmt(pgrm_idx)?;
                            if warn.is_none() {
                                self.programs[pgrm_idx].phase = 1;
                                if self.check_pmt_complete() {
                                    offset += unit;
                                    break;
                                }
                            }
                        }
                    }
                } else {
                    self.programs[pgrm_idx].phase = 2;
                    offset += unit;
                    break;
                }
            }

            offset += unit;
        }

        self.sbuf_offset = offset;
        Ok(())
    }

    fn proc_pmt(&mut self, pgrm_idx: usize) -> B25Result<Option<B25Warn>> {
        let sect = self.programs[pgrm_idx].pmt.get().ok_or(B25Error::PmtParseFailure)?;

        if sect.hdr.table_id != TS_SECTION_ID_PROGRAM_MAP {
            return Ok(Some(B25Warn::TsSectionIdMismatch));
        }

        let data = sect.data();
        if data.len() < 4 {
            return Ok(Some(B25Warn::BrokenTsSection));
        }

        let pcr_pid = (((data[0] & 0x1f) as u16) << 8) | (data[1] as u16);
        self.programs[pgrm_idx].pcr_pid = pcr_pid;

        let prog_info_len = (((data[2] & 0x0f) as usize) << 8) | (data[3] as usize);
        let mut head = 4;
        let tail = data.len().saturating_sub(4); // strip CRC

        if head + prog_info_len > tail {
            return Ok(Some(B25Warn::BrokenTsSection));
        }

        // Find program-level ECM PID.
        let prog_ecm_pid = find_ca_descriptor_pid(&data[head..head + prog_info_len], self.ca_system_id);
        head += prog_info_len;

        // Register program-level decryptor if we found one.
        let primary_dec_idx = if let Some(ecm_pid) = prog_ecm_pid {
            let idx = self.ensure_decryptor(ecm_pid);
            self.decryptors[idx].ref_count += 1;
            Some(idx)
        } else if self.decryptors.len() == 1 {
            self.decryptors[0].ref_count += 1;
            Some(0)
        } else {
            None
        };

        // Clear old stream entries, unref their PIDs.
        let old_streams = std::mem::take(&mut self.programs[pgrm_idx].old_streams);
        let new_old = std::mem::take(&mut self.programs[pgrm_idx].streams);
        for s in &old_streams {
            self.unref_pid(s.pid);
        }
        self.programs[pgrm_idx].old_streams = new_old;

        // Register ECM stream.
        let mut new_streams: Vec<StreamEntry> = Vec::new();
        if let Some(ecm_pid) = prog_ecm_pid {
            if !new_streams.iter().any(|s| s.pid == ecm_pid) {
                new_streams.push(StreamEntry { pid: ecm_pid, stream_type: 0 });
                self.pid_map[ecm_pid as usize].ref_count += 1;
            }
        }

        // Elementary streams.
        while head + 5 <= tail {
            let stream_type = data[head];
            let pid = (((data[head + 1] & 0x1f) as u16) << 8) | (data[head + 2] as u16);
            let es_info_len = (((data[head + 3] & 0x0f) as usize) << 8) | (data[head + 4] as usize);
            head += 5;
            let es_ecm_pid = if head + es_info_len <= tail {
                find_ca_descriptor_pid(&data[head..head + es_info_len], self.ca_system_id)
            } else {
                None
            };
            head += es_info_len;

            let dec_idx = if let Some(ep) = es_ecm_pid {
                let idx = self.ensure_decryptor(ep);
                if !new_streams.iter().any(|s| s.pid == ep) {
                    new_streams.push(StreamEntry { pid: ep, stream_type: 0 });
                    self.pid_map[ep as usize].ref_count += 1;
                }
                Some(idx)
            } else {
                primary_dec_idx
            };

            // Bind PID→decryptor.
            self.pid_map[pid as usize].map_type = PidMapType::Other;
            self.pid_map[pid as usize].ref_count += 1;
            self.bind_stream_decryptor(pid, dec_idx);

            new_streams.push(StreamEntry { pid, stream_type });
        }

        self.programs[pgrm_idx].streams = new_streams;

        // Release primary ref.
        if let Some(idx) = primary_dec_idx {
            self.decryptors[idx].ref_count = self.decryptors[idx].ref_count.saturating_sub(1);
            if self.decryptors[idx].ref_count == 0 {
                self.remove_decryptor(idx);
            }
        }

        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Internal: ECM
    // -----------------------------------------------------------------------

    fn check_ecm_complete(&self) -> bool {
        if self.decryptors.is_empty() {
            return true;
        }
        let any_phase_2 = self.decryptors.iter().any(|d| d.phase >= 2);
        let all_phase_0 = self.decryptors.iter().all(|d| d.phase == 0);
        if any_phase_2 { return true; }
        if all_phase_0 { return false; }
        true
    }

    fn find_ecm(&mut self) -> B25Result<()> {
        let unit = self.unit_size;
        let mut offset = self.sbuf_offset;

        loop {
            if offset + unit >= self.sbuf.len() {
                break;
            }
            if self.sbuf[offset] != 0x47 || self.sbuf[offset + unit] != 0x47 {
                if let Some(new_off) = self.resync(offset) {
                    offset = new_off;
                } else {
                    break;
                }
                continue;
            }

            let hdr = extract_ts_header(&self.sbuf[offset..]);

            if hdr.pid == PID_PAT {
                let payload_bytes = {
                    let (payload, _) = self.packet_payload(&hdr, offset);
                    payload.to_vec()
                };
                if !payload_bytes.is_empty() {
                    if self.pat.put(&hdr, &payload_bytes).is_err() {
                        self.sbuf_offset = offset + unit;
                        return Err(B25Error::PatParseFailure);
                    }
                    if self.pat.get_count() > 0 {
                        self.proc_pat()?;
                        let keep = self.sbuf.split_off(offset);
                        self.sbuf = keep;
                        self.sbuf_offset = 0;
                        return Ok(());
                    }
                }
                offset += unit;
                continue;
            }

            if self.pid_map[hdr.pid as usize].map_type == PidMapType::Ecm {
                let dec_idx = match self.pid_map[hdr.pid as usize].target_idx {
                    Some(i) => i,
                    None => { offset += unit; continue; }
                };

                if self.decryptors[dec_idx].phase == 0 {
                    let payload_bytes = {
                        let (payload, _) = self.packet_payload(&hdr, offset);
                        payload.to_vec()
                    };
                    if !payload_bytes.is_empty() {
                        if self.decryptors[dec_idx].ecm.put(&hdr, &payload_bytes).is_err() {
                            self.sbuf_offset = offset + unit;
                            return Err(B25Error::EcmParseFailure);
                        }
                        if self.decryptors[dec_idx].ecm.get_count() > 0 {
                            let warn = self.proc_ecm(dec_idx)?;
                            if warn.is_none() || warn == Some(B25Warn::UnpurchasedEcm) {
                                self.decryptors[dec_idx].phase = 1;
                                if self.check_ecm_complete() {
                                    offset += unit;
                                    break;
                                }
                            }
                        }
                    }
                } else {
                    self.decryptors[dec_idx].phase = 2;
                    offset += unit;
                    break;
                }
            }

            offset += unit;
        }

        self.sbuf_offset = offset;
        Ok(())
    }

    fn proc_ecm(&mut self, dec_idx: usize) -> B25Result<Option<B25Warn>> {
        let sect = self.decryptors[dec_idx].ecm.get().ok_or(B25Error::EcmParseFailure)?;

        if sect.hdr.table_id != TS_SECTION_ID_ECM_S {
            return Ok(Some(B25Warn::TsSectionIdMismatch));
        }

        if self.decryptors[dec_idx].locked > 0 {
            self.decryptors[dec_idx].unpurchased += 1;
            return Ok(Some(B25Warn::UnpurchasedEcm));
        }

        let bcas = self.bcas.as_mut().ok_or(B25Error::EmptyBCasCard)?;

        // ECM payload: section data minus 4-byte CRC.
        let ecm_payload = {
            let d = sect.data();
            let len = d.len().saturating_sub(4);
            d[..len].to_vec()
        };

        let res = bcas.proc_ecm(&ecm_payload).map_err(|_| B25Error::EcmProcFailure)?;

        // 0x0800 / 0x0400 / 0x0200 = purchased
        if res.return_code != 0x0800 && res.return_code != 0x0400 && res.return_code != 0x0200 {
            self.decryptors[dec_idx].m2 = None;
            self.decryptors[dec_idx].unpurchased += 1;
            self.decryptors[dec_idx].last_error = res.return_code;
            self.decryptors[dec_idx].locked += 1;
            return Ok(Some(B25Warn::UnpurchasedEcm));
        }

        // Lazily create MULTI2 instance.
        if self.decryptors[dec_idx].m2.is_none() {
            let stat: BCasInitStatus = self.bcas.as_ref().unwrap()
                .get_init_status()
                .map_err(|_| B25Error::InvalidBCasStatus)?;

            let mut m2 = Multi2::with_simd(self.multi2_simd);
            m2.set_round(self.multi2_round);
            m2.set_system_key(&stat.system_key).map_err(|_| B25Error::InvalidBCasStatus)?;
            m2.set_init_cbc(&stat.init_cbc).map_err(|_| B25Error::InvalidBCasStatus)?;
            self.decryptors[dec_idx].m2 = Some(m2);
        }

        self.decryptors[dec_idx].m2.as_mut().unwrap()
            .set_scramble_key(&res.scramble_key)
            .map_err(|_| B25Error::DecryptFailure)?;

        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Internal: CAT / EMM
    // -----------------------------------------------------------------------

    fn proc_cat(&mut self, sect: TsSection) -> B25Result<()> {
        if sect.hdr.table_id != TS_SECTION_ID_CONDITIONAL_ACCESS {
            return Ok(());
        }

        let data = sect.data();
        let len = data.len().saturating_sub(4);
        if let Some(emm_pid) = find_ca_descriptor_pid(&data[..len], self.ca_system_id) {
            self.emm_pid = emm_pid;
            self.pid_map[emm_pid as usize].ref_count = 1;
            self.pid_map[emm_pid as usize].map_type = PidMapType::Emm;
            self.pid_map[emm_pid as usize].target_idx = None;
        }

        self.pid_map[PID_CAT as usize].ref_count = 1;
        self.pid_map[PID_CAT as usize].map_type = PidMapType::Cat;

        Ok(())
    }

    fn proc_emm(&mut self) -> B25Result<()> {
        let emm_parser = match self.emm.as_mut() {
            Some(p) => p,
            None => return Ok(()),
        };

        while emm_parser.get_count() > 0 {
            let sect = match emm_parser.get() {
                Some(s) => s,
                None => break,
            };

            if sect.hdr.table_id == TS_SECTION_ID_EMM_MESSAGE {
                continue;
            }
            if sect.hdr.table_id != TS_SECTION_ID_EMM_S {
                continue;
            }

            let data = sect.data();
            let tail = data.len().saturating_sub(4);
            let mut head = 0;

            while head + 13 <= tail {
                // Parse EMM fixed part.
                let card_id = load_be_u48(&data[head..]);
                let assoc_len = data[head + 6] as usize;
                let elem_len = assoc_len + 7;

                if head + elem_len > tail {
                    break;
                }

                if self.card_ids.contains(&card_id) {
                    let emm_elem = data[head..head + elem_len].to_vec();
                    if let Some(bcas) = self.bcas.as_mut() {
                        bcas.proc_emm(&emm_elem).map_err(|_| B25Error::EmmProcFailure)?;
                    }
                    // Unlock all decryptors so they can re-fetch keys.
                    for dec in &mut self.decryptors {
                        dec.locked = 0;
                    }
                }

                head += elem_len;
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: main processing loop
    // -----------------------------------------------------------------------

    fn proc_arib_std_b25(&mut self) -> B25Result<()> {
        let unit = self.unit_size;
        let mut curr = 0usize;
        let tail = self.sbuf.len();

        // Reserve output space.
        self.dbuf.reserve(tail - curr);

        while curr + unit <= tail {
            // Resync.
            if self.sbuf[curr] != 0x47 {
                if curr + unit < tail && self.sbuf[curr + unit] != 0x47 {
                    match self.resync(curr) {
                        Some(p) => {
                            if p > curr + (unit - TS_PACKET_SIZE) {
                                let extra = p - (unit - TS_PACKET_SIZE);
                                self.dbuf.extend_from_slice(&self.sbuf[extra..p]);
                            }
                            curr = p;
                        }
                        None => break,
                    }
                    continue;
                }
            }

            let hdr = extract_ts_header(&self.sbuf[curr..]);
            let crypt = hdr.transport_scrambling_control;
            let pid = hdr.pid;

            if hdr.transport_error_indicator {
                let end = (curr + unit).min(tail);
                self.dbuf.extend_from_slice(&self.sbuf[curr..end]);
                curr += unit;
                continue;
            }

            if pid == PID_NULL && self.strip_null {
                curr += unit;
                continue;
            }

            let (pay_off, pay_len) = payload_range(&hdr, &self.sbuf[curr..]);

            // Decrypt if scrambled.
            if crypt != 0 {
                if hdr.adaptation_field_control & 0x01 != 0 {
                    let dec_idx = if self.pid_map[pid as usize].map_type == PidMapType::Other {
                        self.pid_map[pid as usize].target_idx
                    } else if self.pid_map[pid as usize].map_type == PidMapType::Unknown
                        && self.decryptors.len() == 1
                    {
                        Some(0)
                    } else {
                        None
                    };

                    if let Some(idx) = dec_idx {
                        if self.decryptors[idx].m2.is_some() {
                            // Copy packet to a mutable buffer, decrypt, then push.
                            let pkt_len = unit.min(tail - curr);
                            let mut pkt = self.sbuf[curr..curr + pkt_len].to_vec();
                            self.decryptors[idx].m2.as_ref().unwrap()
                                .decrypt(crypt as u32, &mut pkt[pay_off..pay_off + pay_len])
                                .map_err(|_| B25Error::DecryptFailure)?;
                            pkt[3] &= 0x3f; // clear scrambling bits
                            self.pid_map[pid as usize].normal_packet += 1;
                            self.dbuf.extend_from_slice(&pkt);
                            curr += unit;

                            // Handle ECM in this packet.
                            self.handle_post_decrypt(pid, &pkt, pay_off, pay_len, &hdr)?;
                            continue;
                        } else {
                            self.pid_map[pid as usize].undecrypted += 1;
                        }
                    } else {
                        self.pid_map[pid as usize].undecrypted += 1;
                    }
                } else {
                    self.sbuf[curr + 3] &= 0x3f;
                    self.pid_map[pid as usize].normal_packet += 1;
                }
            } else {
                self.pid_map[pid as usize].normal_packet += 1;
            }

            // Output the packet.
            let end = (curr + unit).min(tail);
            self.dbuf.extend_from_slice(&self.sbuf[curr..end]);

            // Handle special PIDs inline (non-decrypted path).
            if crypt == 0 || hdr.adaptation_field_control & 0x01 == 0 {
                let pkt = self.sbuf[curr..end].to_vec();
                self.handle_post_decrypt(pid, &pkt, pay_off, pay_len, &hdr)?;
            }

            curr += unit;

            if self.pid_map[PID_PAT as usize].map_type == PidMapType::Pat {
                // If PAT changed, restart from current position.
            }
        }

        // Compact sbuf: keep unprocessed tail.
        let remaining = tail - curr;
        if remaining > 0 && curr > 0 {
            self.sbuf.copy_within(curr..tail, 0);
        }
        self.sbuf.truncate(remaining);
        self.sbuf_offset = 0;

        Ok(())
    }

    fn handle_post_decrypt(
        &mut self,
        pid: u16,
        pkt: &[u8],
        pay_off: usize,
        pay_len: usize,
        hdr: &TsHeader,
    ) -> B25Result<()> {
        let payload = &pkt[pay_off..pay_off + pay_len];
        match self.pid_map[pid as usize].map_type {
            PidMapType::Ecm => {
                let dec_idx = match self.pid_map[pid as usize].target_idx {
                    Some(i) => i,
                    None => return Err(B25Error::EcmParseFailure),
                };
                let _ = self.decryptors[dec_idx].ecm.put(hdr, payload);
                if self.decryptors[dec_idx].ecm.get_count() > 0 {
                    self.proc_ecm(dec_idx)?;
                }
            }
            PidMapType::Pmt => {
                let pgrm_idx = match self.pid_map[pid as usize].target_idx {
                    Some(i) => i,
                    None => return Err(B25Error::PmtParseFailure),
                };
                let _ = self.programs[pgrm_idx].pmt.put(hdr, payload);
                if self.programs[pgrm_idx].pmt.get_count() > 0 {
                    self.proc_pmt(pgrm_idx)?;
                }
            }
            PidMapType::Emm => {
                if self.emm_proc_on {
                    let parser = self.emm.get_or_insert_with(TsSectionParser::new);
                    let _ = parser.put(hdr, payload);
                    self.proc_emm()?;
                }
            }
            PidMapType::Cat => {
                let parser = self.cat.get_or_insert_with(TsSectionParser::new);
                let _ = parser.put(hdr, payload);
                if let Some(s) = self.cat.as_mut().and_then(|p| p.get()) {
                    self.proc_cat(s)?;
                }
            }
            PidMapType::Pat => {
                let _ = self.pat.put(hdr, payload);
                if self.pat.get_count() > 0 {
                    self.proc_pat()?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: decryptor management
    // -----------------------------------------------------------------------

    fn ensure_decryptor(&mut self, ecm_pid: u16) -> usize {
        // Check if already exists via PID map.
        if self.pid_map[ecm_pid as usize].map_type == PidMapType::Ecm {
            if let Some(idx) = self.pid_map[ecm_pid as usize].target_idx {
                return idx;
            }
        }

        let idx = self.decryptors.len();
        self.decryptors.push(Decryptor::new(ecm_pid));
        self.pid_map[ecm_pid as usize].map_type = PidMapType::Ecm;
        self.pid_map[ecm_pid as usize].target_idx = Some(idx);
        idx
    }

    fn remove_decryptor(&mut self, idx: usize) {
        let ecm_pid = self.decryptors[idx].ecm_pid;
        if self.pid_map[ecm_pid as usize].target_idx == Some(idx) {
            self.pid_map[ecm_pid as usize].map_type = PidMapType::Unknown;
            self.pid_map[ecm_pid as usize].target_idx = None;
        }
        // Swap-remove to keep indices compact; update PID map for moved decryptor.
        let last = self.decryptors.len() - 1;
        if idx != last {
            self.decryptors.swap(idx, last);
            let moved_pid = self.decryptors[idx].ecm_pid;
            if self.pid_map[moved_pid as usize].target_idx == Some(last) {
                self.pid_map[moved_pid as usize].target_idx = Some(idx);
            }
            // Update any PID map entries that pointed to last.
            for pm in self.pid_map.iter_mut() {
                if pm.target_idx == Some(last) && pm.map_type != PidMapType::Pmt {
                    pm.target_idx = Some(idx);
                }
            }
            // Update program stream entries.
            for pgrm in &mut self.programs {
                // (PMT target_idx stays the same; decryptors are only referenced
                //  through pid_map for ECM PIDs and through pid_map.target for Other PIDs)
                let _ = pgrm; // nothing needed since we fix pid_map above
            }
        }
        self.decryptors.pop();
    }

    fn bind_stream_decryptor(&mut self, pid: u16, dec_idx: Option<usize>) {
        let old_idx = self.pid_map[pid as usize].target_idx;
        if old_idx == dec_idx {
            return;
        }
        if let Some(old) = old_idx {
            if old < self.decryptors.len() {
                self.decryptors[old].ref_count = self.decryptors[old].ref_count.saturating_sub(1);
                if self.decryptors[old].ref_count == 0 {
                    self.remove_decryptor(old);
                    return; // indices may have changed; bail out
                }
            }
        }
        if let Some(new) = dec_idx {
            if new < self.decryptors.len() {
                self.decryptors[new].ref_count += 1;
            }
        }
        self.pid_map[pid as usize].target_idx = dec_idx;
    }

    fn unref_pid(&mut self, pid: u16) {
        let ref_count = self.pid_map[pid as usize].ref_count;
        if ref_count == 0 {
            return;
        }
        self.pid_map[pid as usize].ref_count -= 1;
        if self.pid_map[pid as usize].ref_count == 0 {
            if let Some(idx) = self.pid_map[pid as usize].target_idx {
                if self.pid_map[pid as usize].map_type == PidMapType::Other
                    && idx < self.decryptors.len()
                {
                    self.decryptors[idx].ref_count = self.decryptors[idx].ref_count.saturating_sub(1);
                    if self.decryptors[idx].ref_count == 0 {
                        self.remove_decryptor(idx);
                    }
                }
            }
            self.pid_map[pid as usize] = PidMap::default();
        }
    }

    // -----------------------------------------------------------------------
    // Internal: sync helpers
    // -----------------------------------------------------------------------

    fn resync(&self, offset: usize) -> Option<usize> {
        let unit = self.unit_size;
        let data = &self.sbuf;
        let mut i = offset;
        while i + unit < data.len() {
            if data[i] == 0x47 && data[i + unit] == 0x47 {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Returns `(payload_start_offset_from_pkt_start, payload_len)` within the
    /// 188-byte TS packet at `sbuf[offset..]`.
    fn packet_payload<'a>(&'a self, hdr: &TsHeader, offset: usize) -> (&'a [u8], usize) {
        let pkt = &self.sbuf[offset..];
        payload_slice(hdr, pkt)
    }
}

impl Default for AribStdB25 {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Returns the payload slice and length for a TS packet.
fn payload_slice<'a>(hdr: &TsHeader, pkt: &'a [u8]) -> (&'a [u8], usize) {
    let mut off = 4usize;
    if hdr.adaptation_field_control & 0x02 != 0 {
        let af_len = pkt[4] as usize;
        off += 1 + af_len;
    }
    let max = TS_PACKET_SIZE.min(pkt.len());
    if off >= max {
        return (&[], 0);
    }
    (&pkt[off..max], max - off)
}

/// Returns (payload offset, payload length) within the packet slice.
fn payload_range(hdr: &TsHeader, pkt: &[u8]) -> (usize, usize) {
    let mut off = 4usize;
    if hdr.adaptation_field_control & 0x02 != 0 {
        if pkt.len() > 4 {
            let af_len = pkt[4] as usize;
            off += 1 + af_len;
        }
    }
    let max = TS_PACKET_SIZE.min(pkt.len());
    if off >= max { (off, 0) } else { (off, max - off) }
}

/// Scan `descriptors` for the first CA descriptor matching `ca_system_id`.
/// Returns the CA PID, or `None` if not found.
fn find_ca_descriptor_pid(descriptors: &[u8], ca_system_id: u16) -> Option<u16> {
    let mut i = 0;
    while i + 2 <= descriptors.len() {
        let tag = descriptors[i];
        let len = descriptors[i + 1] as usize;
        i += 2;
        if tag == TS_DESCRIPTOR_TAG_CA && len >= 4 && i + len <= descriptors.len() {
            let sys_id = ((descriptors[i] as u16) << 8) | (descriptors[i + 1] as u16);
            let ca_pid = (((descriptors[i + 2] & 0x1f) as u16) << 8) | (descriptors[i + 3] as u16);
            if sys_id == ca_system_id {
                return Some(ca_pid);
            }
        }
        i += len;
    }
    None
}

fn load_be_u48(p: &[u8]) -> i64 {
    let mut r = p[0] as i64;
    for i in 1..6 {
        r <<= 8;
        r |= p[i] as i64;
    }
    r
}
