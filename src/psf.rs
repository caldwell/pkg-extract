use anyhow::{Result, bail};

const PSF_MAGIC: u32 = 0x00505346;
const PSF_VERSION_1_0: u32 = 0x00000100;
const PSF_VERSION_1_1: u32 = 0x00000101;

#[allow(dead_code)]
pub enum PsfValue {
    Binary(Vec<u8>),
    Text(String),
    Integer(i32),
}

pub struct PsfEntry {
    pub key: String,
    pub value: PsfValue,
}

pub struct Psf {
    pub entries: Vec<PsfEntry>,
}

impl Psf {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            bail!("PSF too short");
        }
        let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let key_table_offset = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let data_table_offset = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
        let index_table_entries = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;

        if magic != PSF_MAGIC {
            bail!("Invalid PSF magic 0x{magic:08x}");
        }
        if version != PSF_VERSION_1_0 && version != PSF_VERSION_1_1 {
            bail!("Unsupported PSF version 0x{version:08x}");
        }

        let mut entries = Vec::with_capacity(index_table_entries);
        for i in 0..index_table_entries {
            let raw = &data[20 + i * 16..20 + (i + 1) * 16];
            let key_offset = u16::from_le_bytes(raw[0..2].try_into().unwrap()) as usize;
            let param_fmt = u16::from_le_bytes(raw[2..4].try_into().unwrap());
            let param_len = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
            let _param_max_len = u32::from_le_bytes(raw[8..12].try_into().unwrap()) as usize;
            let data_offset = u32::from_le_bytes(raw[12..16].try_into().unwrap()) as usize;

            let key = read_cstr(data, key_table_offset + key_offset)?;
            let value_start = data_table_offset + data_offset;
            if value_start + param_len > data.len() {
                bail!("PSF entry out of bounds");
            }
            let value_bytes = &data[value_start..value_start + param_len];
            let value = match param_fmt {
                0x0004 => PsfValue::Binary(value_bytes.to_vec()),
                0x0204 => PsfValue::Text(
                    String::from_utf8_lossy(trim_nul(value_bytes)).into_owned(),
                ),
                0x0404 => {
                    if param_len < 4 {
                        bail!("PSF integer too short");
                    }
                    PsfValue::Integer(i32::from_le_bytes(value_bytes[..4].try_into().unwrap()))
                }
                _ => bail!("Unknown PSF entry format 0x{param_fmt:04x}"),
            };
            entries.push(PsfEntry { key, value });
        }

        Ok(Psf { entries })
    }

    pub fn get_string(&self, key: &str) -> Option<&str> {
        self.entries.iter().find_map(|e| match &e.value {
            PsfValue::Text(s) if e.key == key => Some(s.as_str()),
            _ => None,
        })
    }
}

fn read_cstr(data: &[u8], start: usize) -> Result<String> {
    if start >= data.len() {
        bail!("PSF key offset out of bounds");
    }
    let end = data[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(data.len());
    Ok(String::from_utf8_lossy(&data[start..end]).into_owned())
}

fn trim_nul(buf: &[u8]) -> &[u8] {
    match buf.iter().position(|&b| b == 0) {
        Some(p) => &buf[..p],
        None => buf,
    }
}
