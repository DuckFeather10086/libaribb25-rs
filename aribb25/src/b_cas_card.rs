//! B-CAS Smart Card interface.
//!
//! Communicates with a B-CAS or A-CAS smart card via PC/SC (PCSC-lite on
//! macOS/Linux, WinSCard on Windows) to process ECM and EMM messages.

use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use crate::error::{BCasCardError, BCasResult};

/// Initial status returned by the card after connection.
#[derive(Debug, Clone)]
pub struct BCasInitStatus {
    pub system_key: [u8; 32],
    pub init_cbc: [u8; 8],
    pub bcas_card_id: i64,
    pub card_status: u16,
    pub ca_system_id: u16,
}

/// A list of card IDs stored on the card.
#[derive(Debug, Default, Clone)]
pub struct BCasId {
    pub data: Vec<i64>,
}

/// Power-on control date entry.
#[derive(Debug, Clone, Default)]
pub struct BCasPwrOnCtrl {
    pub s_yy: i32, pub s_mm: i32, pub s_dd: i32,
    pub l_yy: i32, pub l_mm: i32, pub l_dd: i32,
    pub hold_time: i32,
    pub broadcaster_group_id: i32,
    pub network_id: u16,
    pub transport_id: u16,
}

/// Result of ECM processing.
#[derive(Debug, Clone)]
pub struct BCasEcmResult {
    pub scramble_key: [u8; 16],
    pub return_code: u16,
}

// ---------------------------------------------------------------------------
// APDU command templates
// ---------------------------------------------------------------------------

const INITIAL_SETTING_CONDITIONS_CMD: &[u8]        = &[0x90, 0x30, 0x00, 0x00, 0x00];
const CARD_ID_INFORMATION_ACQUIRE_CMD: &[u8]        = &[0x90, 0x32, 0x00, 0x00, 0x00];
const POWER_ON_CONTROL_INFORMATION_REQUEST_CMD: &[u8] = &[0x90, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00];
const ECM_RECEIVE_CMD_HEADER: &[u8]                = &[0x90, 0x34, 0x00, 0x00];
const EMM_RECEIVE_CMD_HEADER: &[u8]                = &[0x90, 0x36, 0x00, 0x00];

// ACAS variant commands
const INITIAL_SETTING_CONDITIONS_CMD_ACAS: &[u8]   = &[0x80, 0x5e, 0x00, 0x00, 0x00];
const CARD_ID_INFORMATION_ACQUIRE_CMD_ACAS: &[u8]  = &[0x80, 0x5e, 0x00, 0x01, 0x00];
const ECM_RECEIVE_CMD_HEADER_ACAS: &[u8]           = &[0x80, 0x34, 0x00, 0x02];
const EMM_RECEIVE_CMD_HEADER_ACAS: &[u8]           = &[0x80, 0x36, 0x00, 0x01];

const BUFFER_MAX: usize = 4 * 1024;

/// ACAS/BCAS operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcasMode {
    /// Auto-detect (try B-CAS first, then A-CAS).
    Auto,
    /// Force B-CAS mode.
    BCas,
    /// Force A-CAS mode.
    ACas,
}

/// B-CAS / A-CAS smart card interface.
pub struct BCasCard {
    ctx: Option<Context>,
    card: Option<Card>,
    stat: Option<BCasInitStatus>,
    ids: Vec<i64>,
    pwc: Vec<BCasPwrOnCtrl>,
    acas_mode: AcasMode,
    connected_as_acas: bool,
    reader_pattern: String,
    send_buf: Vec<u8>,
    recv_buf: Vec<u8>,
}

impl BCasCard {
    pub fn new() -> Self {
        Self {
            ctx: None,
            card: None,
            stat: None,
            ids: Vec::new(),
            pwc: Vec::new(),
            acas_mode: AcasMode::Auto,
            connected_as_acas: false,
            reader_pattern: String::new(),
            send_buf: vec![0u8; BUFFER_MAX],
            recv_buf: vec![0u8; BUFFER_MAX],
        }
    }

    /// Override the card-reader name matching pattern.
    /// Pass an empty string to connect to the first available reader.
    pub fn set_reader_pattern(&mut self, pattern: &str) {
        self.reader_pattern = pattern.to_owned();
    }

    /// Set the ACAS mode before calling `init()`.
    pub fn set_acas_mode(&mut self, mode: AcasMode) -> BCasResult<()> {
        self.acas_mode = mode;
        Ok(())
    }

    /// Connect to a smart-card reader and initialise the card.
    pub fn init(&mut self) -> BCasResult<()> {
        self.teardown();

        let ctx = Context::establish(Scope::User).map_err(BCasCardError::PcSc)?;
        let reader_list = ctx.list_readers_owned().map_err(BCasCardError::PcSc)?;

        if reader_list.is_empty() {
            return Err(BCasCardError::NoSmartCardReader);
        }

        let tries: &[bool] = match self.acas_mode {
            AcasMode::Auto => &[false, true],
            AcasMode::BCas => &[false],
            AcasMode::ACas => &[true],
        };

        for &acas in tries {
            for reader_cstr in &reader_list {
                // Filter by pattern if one is set.
                let reader_str = reader_cstr.to_string_lossy();
                if !self.reader_pattern.is_empty()
                    && !reader_str.contains(self.reader_pattern.as_str())
                {
                    continue;
                }

                match self.connect_card(&ctx, reader_cstr, acas) {
                    Ok(true) => {
                        self.ctx = Some(ctx);
                        self.connected_as_acas = acas;
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }

        Err(BCasCardError::AllReadersConnectionFailed)
    }

    /// Returns the init status (system key, init CBC, card ID, …).
    pub fn get_init_status(&self) -> BCasResult<BCasInitStatus> {
        self.stat.clone().ok_or(BCasCardError::NotInitialized)
    }

    /// Returns the list of card IDs stored on the card.
    pub fn get_id(&mut self) -> BCasResult<Vec<i64>> {
        if self.card.is_none() {
            return Err(BCasCardError::NotInitialized);
        }
        let acas = self.connected_as_acas;

        let cmd = if acas {
            CARD_ID_INFORMATION_ACQUIRE_CMD_ACAS
        } else {
            CARD_ID_INFORMATION_ACQUIRE_CMD
        };

        let slen = cmd.len();
        self.send_buf[..slen].copy_from_slice(cmd);

        let rlen = {
            let card = self.card.as_ref().unwrap();
            let resp = card.transmit(&self.send_buf[..slen], &mut self.recv_buf)
                .map_err(BCasCardError::PcSc)?;
            resp.len()
        };

        if rlen < 19 {
            return Err(BCasCardError::TransmitFailed);
        }

        let num = self.recv_buf[6] as usize;
        let mut p = 7usize;
        let mut ids = Vec::with_capacity(num);
        for _ in 0..num {
            if p + 10 > rlen {
                return Err(BCasCardError::TransmitFailed);
            }
            ids.push(load_be_u48(&self.recv_buf[p + 2..]));
            p += 10;
        }

        self.ids = ids.clone();
        Ok(ids)
    }

    /// Returns power-on control information from the card.
    pub fn get_pwr_on_ctrl(&mut self) -> BCasResult<Vec<BCasPwrOnCtrl>> {
        if self.card.is_none() {
            return Err(BCasCardError::NotInitialized);
        }

        let slen = POWER_ON_CONTROL_INFORMATION_REQUEST_CMD.len();
        self.send_buf[..slen].copy_from_slice(POWER_ON_CONTROL_INFORMATION_REQUEST_CMD);
        self.send_buf[5] = 0;

        let rlen = {
            let card = self.card.as_ref().unwrap();
            let resp = card.transmit(&self.send_buf[..slen], &mut self.recv_buf)
                .map_err(BCasCardError::PcSc)?;
            resp.len()
        };

        if rlen < 18 || self.recv_buf[6] != 0 {
            return Err(BCasCardError::TransmitFailed);
        }

        let code = load_be_u16(&self.recv_buf[4..]);
        if code == 0xa101 {
            return Ok(Vec::new());
        } else if code != 0x2100 {
            return Err(BCasCardError::TransmitFailed);
        }

        let num = (self.recv_buf[7] as usize) + 1;
        let mut result = Vec::with_capacity(num);
        result.push(extract_power_on_ctrl_response(&self.recv_buf.clone()));

        for i in 1..num {
            self.send_buf[5] = i as u8;
            let rlen2 = {
                let card = self.card.as_ref().unwrap();
                let resp = card.transmit(&self.send_buf[..slen], &mut self.recv_buf)
                    .map_err(BCasCardError::PcSc)?;
                resp.len()
            };
            if rlen2 < 18 || self.recv_buf[6] != i as u8 {
                return Err(BCasCardError::TransmitFailed);
            }
            result.push(extract_power_on_ctrl_response(&self.recv_buf.clone()));
        }

        self.pwc = result.clone();
        Ok(result)
    }

    /// Send an ECM to the card and receive the descrambling key.
    pub fn proc_ecm(&mut self, ecm_data: &[u8]) -> BCasResult<BCasEcmResult> {
        if self.card.is_none() {
            return Err(BCasCardError::NotInitialized);
        }
        let acas = self.connected_as_acas;

        let hdr = if acas { ECM_RECEIVE_CMD_HEADER_ACAS } else { ECM_RECEIVE_CMD_HEADER };
        let slen = build_apdu(&mut self.send_buf, hdr, ecm_data);

        let rlen = transmit_with_retry(
            self.card.as_ref().unwrap(),
            &self.send_buf[..slen],
            &mut self.recv_buf,
            2,
        )?;

        if acas {
            if rlen < 22 {
                return Ok(BCasEcmResult {
                    scramble_key: [0u8; 16],
                    return_code: 0xa103,
                });
            }
            let mut key = [0u8; 16];
            key.copy_from_slice(&self.recv_buf[..16]);
            let return_code = match load_be_u16(&self.recv_buf[18..]) {
                0xc001 => 0x0800,
                0xc000 => 0xa901,
                _ => {
                    if key == [0xff; 16] { 0xa902 } else { 0x0800 }
                }
            };
            Ok(BCasEcmResult { scramble_key: key, return_code })
        } else {
            if rlen < 25 {
                return Err(BCasCardError::TransmitFailed);
            }
            let mut key = [0u8; 16];
            key.copy_from_slice(&self.recv_buf[6..22]);
            let return_code = load_be_u16(&self.recv_buf[4..]);
            Ok(BCasEcmResult { scramble_key: key, return_code })
        }
    }

    /// Send an EMM to the card.
    pub fn proc_emm(&mut self, emm_data: &[u8]) -> BCasResult<()> {
        if self.card.is_none() {
            return Err(BCasCardError::NotInitialized);
        }
        let acas = self.connected_as_acas;

        let hdr = if acas { EMM_RECEIVE_CMD_HEADER_ACAS } else { EMM_RECEIVE_CMD_HEADER };
        let slen = build_apdu(&mut self.send_buf, hdr, emm_data);

        transmit_with_retry(
            self.card.as_ref().unwrap(),
            &self.send_buf[..slen],
            &mut self.recv_buf,
            2,
        )?;
        Ok(())
    }

    /// Returns the IDs cached from the last `get_id()` call.
    pub fn cached_ids(&self) -> &[i64] {
        &self.ids
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn teardown(&mut self) {
        self.card = None;
        self.ctx = None;
        self.stat = None;
    }

    fn connect_card(&mut self, ctx: &Context, reader: &std::ffi::CStr, acas: bool) -> BCasResult<bool> {
        let card = match ctx.connect(reader, ShareMode::Shared, Protocols::T1) {
            Ok(c) => c,
            Err(_) => return Ok(false),
        };

        let cmd = if acas {
            INITIAL_SETTING_CONDITIONS_CMD_ACAS
        } else {
            INITIAL_SETTING_CONDITIONS_CMD
        };
        let slen = cmd.len();
        self.send_buf[..slen].copy_from_slice(cmd);

        let rlen = match card.transmit(&self.send_buf[..slen], &mut self.recv_buf) {
            Ok(resp) => resp.len(),
            Err(_) => return Ok(false),
        };

        let min_len = if acas { 46 } else { 57 };
        if rlen < min_len {
            return Ok(false);
        }

        let p = self.recv_buf.clone();

        if acas {
            let mut sys = [0u8; 32];
            sys.copy_from_slice(&p[8..40]);
            let mut cbc = [0u8; 8];
            cbc.copy_from_slice(&p[8..16]);
            self.stat = Some(BCasInitStatus {
                system_key: sys,
                init_cbc: cbc,
                bcas_card_id: 0,
                card_status: 0,
                ca_system_id: load_be_u16(&p) as u16,
            });
        } else {
            let code = load_be_u16(&p[4..]);
            if code != 0x2100 {
                return Ok(false);
            }
            let mut sys = [0u8; 32];
            sys.copy_from_slice(&p[16..48]);
            let mut cbc = [0u8; 8];
            cbc.copy_from_slice(&p[48..56]);
            self.stat = Some(BCasInitStatus {
                system_key: sys,
                init_cbc: cbc,
                bcas_card_id: load_be_u48(&p[8..]),
                card_status: load_be_u16(&p[2..]) as u16,
                ca_system_id: load_be_u16(&p[6..]) as u16,
            });
        }

        self.card = Some(card);
        Ok(true)
    }
}

impl Default for BCasCard {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

fn transmit_with_retry(card: &Card, send: &[u8], recv: &mut Vec<u8>, retries: u32) -> BCasResult<usize> {
    let mut last_err = BCasCardError::TransmitFailed;
    for _ in 0..=retries {
        match card.transmit(send, recv.as_mut_slice()) {
            Ok(resp) => return Ok(resp.len()),
            Err(e) => last_err = BCasCardError::PcSc(e),
        }
    }
    Err(last_err)
}

/// Builds an APDU command in `buf` and returns the byte count.
fn build_apdu(buf: &mut [u8], header: &[u8], data: &[u8]) -> usize {
    let hlen = header.len();
    buf[..hlen].copy_from_slice(header);
    buf[hlen] = data.len() as u8;
    buf[hlen + 1..hlen + 1 + data.len()].copy_from_slice(data);
    buf[hlen + 1 + data.len()] = 0;
    hlen + 1 + data.len() + 1
}

fn load_be_u16(p: &[u8]) -> u16 {
    ((p[0] as u16) << 8) | (p[1] as u16)
}

fn load_be_u48(p: &[u8]) -> i64 {
    let mut r = p[0] as i64;
    for i in 1..6 {
        r <<= 8;
        r |= p[i] as i64;
    }
    r
}

fn extract_power_on_ctrl_response(src: &[u8]) -> BCasPwrOnCtrl {
    let reference = ((src[9] as i32) << 8) | (src[10] as i32);
    let start = reference - src[11] as i32;
    let limit = start + (src[12] as i32) - 1;

    let (s_yy, s_mm, s_dd) = extract_mjd(start);
    let (l_yy, l_mm, l_dd) = extract_mjd(limit);

    BCasPwrOnCtrl {
        s_yy, s_mm, s_dd,
        l_yy, l_mm, l_dd,
        hold_time: src[13] as i32,
        broadcaster_group_id: src[8] as i32,
        network_id:   ((src[14] as u16) << 8) | (src[15] as u16),
        transport_id: ((src[16] as u16) << 8) | (src[17] as u16),
    }
}

fn extract_mjd(mut mjd: i32) -> (i32, i32, i32) {
    mjd -= 51604; // base: 2000-03-01
    if mjd < 0 { mjd += 0x10000; }

    let a1 = mjd / 146097;
    let m1 = mjd % 146097;
    let a2 = m1 / 36524;
    let m2 = m1 - a2 * 36524;
    let a3 = m2 / 1461;
    let m3 = m2 - a3 * 1461;
    let a4 = (m3 / 365).min(3);
    let m4 = m3 - a4 * 365;

    let mw = (1071 * m4 + 450) >> 15;
    let dw = m4 - ((979 * mw + 16) >> 5);

    let mut yw = a1 * 400 + a2 * 100 + a3 * 4 + a4 + 2000;
    let mut mm = mw + 3;
    if mm > 12 { mm -= 12; yw += 1; }

    (yw, mm, dw + 1)
}
