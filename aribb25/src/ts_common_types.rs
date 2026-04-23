//! Common TS (MPEG Transport Stream) data types.

/// Parsed MPEG-TS packet header.
#[derive(Debug, Default, Clone, Copy)]
pub struct TsHeader {
    pub sync: u8,
    pub transport_error_indicator: bool,
    pub payload_unit_start_indicator: bool,
    pub transport_priority: bool,
    pub pid: u16,
    pub transport_scrambling_control: u8,
    pub adaptation_field_control: u8,
    pub continuity_counter: u8,
}

/// Parsed TS section header.
#[derive(Debug, Default, Clone)]
pub struct TsSectionHeader {
    pub table_id: u8,
    pub section_syntax_indicator: bool,
    pub private_indicator: bool,
    pub section_length: u16,
    pub table_id_extension: u16,
    pub version_number: u8,
    pub current_next_indicator: bool,
    pub section_number: u8,
    pub last_section_number: u8,
}

/// A fully-assembled TS section with its raw bytes and parsed header.
#[derive(Debug, Clone)]
pub struct TsSection {
    pub hdr: TsSectionHeader,
    /// Full raw bytes of the section (including header bytes).
    pub raw: Vec<u8>,
    /// Byte offset within `raw` at which the payload data starts.
    pub data_offset: usize,
}

impl TsSection {
    /// Returns the payload data slice (after the section header).
    pub fn data(&self) -> &[u8] {
        &self.raw[self.data_offset..]
    }
}

/// Parse a TS packet header from a 4-byte prefix.
pub fn extract_ts_header(src: &[u8]) -> TsHeader {
    TsHeader {
        sync: src[0],
        transport_error_indicator:    (src[1] & 0x80) != 0,
        payload_unit_start_indicator: (src[1] & 0x40) != 0,
        transport_priority:           (src[1] & 0x20) != 0,
        pid: (((src[1] & 0x1f) as u16) << 8) | (src[2] as u16),
        transport_scrambling_control: (src[3] >> 6) & 0x03,
        adaptation_field_control:     (src[3] >> 4) & 0x03,
        continuity_counter:            src[3]        & 0x0f,
    }
}
