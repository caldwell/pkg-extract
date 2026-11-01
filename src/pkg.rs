use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use flate2::{Decompress, FlushDecompress};

use crate::crypto;
use crate::pkg_entry_name::entry_name_by_type;

pub const PKG_MAGIC: u32 = 0x7F434E54;
const PFSC_MAGIC: u32 = 0x43534650;

const PFS_FILE: u32 = 2;
const PFS_DIR: u32 = 3;
const PFS_CURRENT_DIR: u32 = 4;
#[allow(dead_code)]
const PFS_PARENT_DIR: u32 = 5;

const SECTOR_SIZE: usize = 0x10000;
const PKG_HEADER_SIZE: usize = 0x1000;
const PKG_ENTRY_SIZE: usize = 32;
const INODE_STRIDE: usize = 0xA8;

const FLAG_NAMES: &[(u32, &str)] = &[
    (0x100000, "FIRST_PATCH"),
    (0x200000, "PATCHGO"),
    (0x400000, "REMASTER"),
    (0x800000, "PS_CLOUD"),
    (0x2000000, "GD_AC"),
    (0x4000000, "NON_GAME"),
    (0x8000000, "UNKNOWN_0x8000000"),
    (0x40000000, "SUBSEQUENT_PATCH"),
    (0x41000000, "DELTA_PATCH"),
    (0x60000000, "CUMULATIVE_PATCH"),
];

/// Peeks the magic to decide whether `path` looks like a PKG.
pub fn is_pkg_file(path: &Path) -> Result<bool> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buf = [0u8; 4];
    if file.read_exact(&mut buf).is_err() {
        return Ok(false);
    }
    Ok(u32::from_be_bytes(buf) == PKG_MAGIC)
}

#[derive(Debug, Clone)]
struct PkgHeader {
    magic: u32,
    pkg_table_entry_count: u32,
    pkg_table_entry_offset: u32,
    pkg_content_offset: u64,
    pkg_content_size: u64,
    pkg_content_flags: u32,
    pkg_content_id: [u8; 0x24],
    pfs_image_offset: u64,
    pkg_size: u64,
    pfs_cache_size: u32,
}

impl PkgHeader {
    fn parse(buf: &[u8]) -> Self {
        let r32 = |o: usize| u32::from_be_bytes(buf[o..o + 4].try_into().unwrap());
        let r64 = |o: usize| u64::from_be_bytes(buf[o..o + 8].try_into().unwrap());
        let mut content_id = [0u8; 0x24];
        content_id.copy_from_slice(&buf[0x40..0x40 + 0x24]);
        Self {
            magic: r32(0x000),
            pkg_table_entry_count: r32(0x010),
            pkg_table_entry_offset: r32(0x018),
            pkg_content_offset: r64(0x030),
            pkg_content_size: r64(0x038),
            pkg_content_flags: r32(0x078),
            pkg_content_id: content_id,
            pfs_image_offset: r64(0x410),
            pkg_size: r64(0x430),
            pfs_cache_size: r32(0x43C),
        }
    }
}

struct PkgEntry {
    id: u32,
    offset: u32,
    size: u32,
    raw: [u8; PKG_ENTRY_SIZE],
}

impl PkgEntry {
    fn parse(buf: &[u8]) -> Self {
        let mut raw = [0u8; PKG_ENTRY_SIZE];
        raw.copy_from_slice(&buf[..PKG_ENTRY_SIZE]);
        let r32 = |o: usize| u32::from_be_bytes(buf[o..o + 4].try_into().unwrap());
        Self {
            id: r32(0),
            offset: r32(16),
            size: r32(20),
            raw,
        }
    }
}

struct Inode {
    mode: u16,
    size: i64,
    blocks: u32,
    loc: u32,
}

impl Inode {
    fn parse(buf: &[u8]) -> Self {
        Self {
            mode: u16::from_le_bytes(buf[0..2].try_into().unwrap()),
            size: i64::from_le_bytes(buf[8..16].try_into().unwrap()),
            blocks: u32::from_le_bytes(buf[0x60..0x64].try_into().unwrap()),
            loc: u32::from_le_bytes(buf[0x64..0x68].try_into().unwrap()),
        }
    }
}

struct FsTableEntry {
    name: String,
    inode: u32,
    ty: u32,
}

pub struct Pkg {
    file: File,
    path: PathBuf,
    header: PkgHeader,
    title_id: String,
    flag_strings: Vec<&'static str>,
    pub sfo: Vec<u8>,

    extract_path: PathBuf,
    fs_table: Vec<FsTableEntry>,
    inode_buf: Vec<Inode>,
    sector_map: Vec<u64>,
    pfsc_offset: u64,
    extract_paths: HashMap<u32, PathBuf>,
    data_key: [u8; 16],
    tweak_key: [u8; 16],
}

impl Pkg {
    /// Opens the PKG, parses the header + file table, and extracts the embedded param.sfo
    /// into [`Pkg::sfo`]. Does not extract any files on disk.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let pkg_file_size = file.metadata()?.len();

        let mut hdr_buf = [0u8; PKG_HEADER_SIZE];
        file.read_exact(&mut hdr_buf).context("read PKG header")?;
        let header = PkgHeader::parse(&hdr_buf);
        if header.magic != PKG_MAGIC {
            bail!("not a PKG (bad magic 0x{:08x})", header.magic);
        }
        if header.pkg_size > pkg_file_size {
            bail!("PKG file size is different");
        }
        if header.pkg_content_offset + header.pkg_content_size > header.pkg_size {
            bail!("Content size is bigger than pkg size");
        }

        let flag_strings = FLAG_NAMES
            .iter()
            .filter_map(|(flag, name)| (header.pkg_content_flags & flag != 0).then_some(*name))
            .collect::<Vec<_>>();

        // Title ID is 9 bytes starting at offset 7 within content_id (which is at 0x40).
        let title_id =
            String::from_utf8_lossy(&header.pkg_content_id[7..7 + 9]).into_owned();

        // First pass: find and read param.sfo.
        let mut sfo = Vec::new();
        file.seek(SeekFrom::Start(header.pkg_table_entry_offset as u64))
            .context("seek to PKG table entry offset")?;
        let mut table_buf =
            vec![0u8; header.pkg_table_entry_count as usize * PKG_ENTRY_SIZE];
        file.read_exact(&mut table_buf).context("read PKG table")?;
        for i in 0..header.pkg_table_entry_count as usize {
            let entry = PkgEntry::parse(&table_buf[i * PKG_ENTRY_SIZE..(i + 1) * PKG_ENTRY_SIZE]);
            if entry_name_by_type(entry.id) == "param.sfo" {
                file.seek(SeekFrom::Start(entry.offset as u64))
                    .context("seek to param.sfo")?;
                sfo = vec![0u8; entry.size as usize];
                file.read_exact(&mut sfo).context("read param.sfo")?;
                break;
            }
        }

        Ok(Pkg {
            file,
            path: path.to_path_buf(),
            header,
            title_id,
            flag_strings,
            sfo,
            extract_path: PathBuf::new(),
            fs_table: Vec::new(),
            inode_buf: Vec::new(),
            sector_map: Vec::new(),
            pfsc_offset: 0,
            extract_paths: HashMap::new(),
            data_key: [0u8; 16],
            tweak_key: [0u8; 16],
        })
    }

    pub fn title_id(&self) -> &str {
        &self.title_id
    }

    pub fn flags_label(&self) -> String {
        self.flag_strings.join(", ")
    }

    pub fn file_count(&self) -> usize {
        self.fs_table.len()
    }

    /// Writes the sce_sys/* entries, decrypts the PFS image header, and walks inodes/dirents
    /// so that the per-file calls to [`Pkg::extract_file`] can run.
    pub fn extract(&mut self, extract_path: &Path) -> Result<()> {
        self.extract_path = extract_path.to_path_buf();

        let n_files = self.header.pkg_table_entry_count as usize;
        self.file
            .seek(SeekFrom::Start(self.header.pkg_table_entry_offset as u64))
            .context("seek to PKG table entry offset")?;
        let mut table_buf = vec![0u8; n_files * PKG_ENTRY_SIZE];
        self.file.read_exact(&mut table_buf).context("read PKG table")?;

        let mut dk3 = [0u8; 32];
        let mut iv_key = [0u8; 32];
        let mut img_key = [0u8; 256];
        let mut ekpfs_key = [0u8; 32];

        for i in 0..n_files {
            let entry =
                PkgEntry::parse(&table_buf[i * PKG_ENTRY_SIZE..(i + 1) * PKG_ENTRY_SIZE]);
            let name = entry_name_by_type(entry.id);

            let out_name: String = if name.is_empty() {
                entry.id.to_string()
            } else {
                name.to_string()
            };
            let out_path = self.extract_path.join("sce_sys").join(&out_name);
            if let Some(p) = out_path.parent() {
                std::fs::create_dir_all(p).with_context(|| format!("mkdir {}", p.display()))?;
            }

            if name.is_empty() {
                self.copy_entry_to_file(&entry, &out_path)?;
                continue;
            }

            match entry.id {
                0x10 => {
                    self.file.seek(SeekFrom::Start(entry.offset as u64))?;
                    let mut seed_digest = [0u8; 32];
                    self.file.read_exact(&mut seed_digest)?;
                    let mut digest1 = [[0u8; 32]; 7];
                    for d in digest1.iter_mut() {
                        self.file.read_exact(d)?;
                    }
                    let mut key1 = [[0u8; 256]; 7];
                    for k in key1.iter_mut() {
                        self.file.read_exact(k)?;
                    }
                    crypto::rsa2048_decrypt(&mut dk3, &key1[3], true)?;
                }
                0x20 => {
                    self.file.seek(SeekFrom::Start(entry.offset as u64))?;
                    let mut img_key_data = [0u8; 256];
                    self.file.read_exact(&mut img_key_data)?;

                    let mut combined = [0u8; 64];
                    combined[..PKG_ENTRY_SIZE].copy_from_slice(&entry.raw);
                    combined[PKG_ENTRY_SIZE..].copy_from_slice(&dk3);

                    crypto::iv_key_hash256(&mut iv_key, &combined);
                    let decrypted = crypto::aes_cbc_decrypt(&iv_key, &img_key_data)?;
                    img_key.copy_from_slice(&decrypted);
                    crypto::rsa2048_decrypt(&mut ekpfs_key, &img_key, false)?;
                }
                _ => {}
            }

            self.copy_entry_to_file(&entry, &out_path)?;

            if matches!(entry.id, 0x400 | 0x401 | 0x402 | 0x403) {
                let r_size = entry.size as usize;
                let m_size = r_size.div_ceil(16) * 16;
                self.file.seek(SeekFrom::Start(entry.offset as u64))?;
                let mut data = vec![0u8; r_size];
                self.file.read_exact(&mut data)?;
                data.resize(m_size, 0);

                let mut combined = [0u8; 64];
                combined[..PKG_ENTRY_SIZE].copy_from_slice(&entry.raw);
                combined[PKG_ENTRY_SIZE..].copy_from_slice(&dk3);
                let mut entry_iv_key = [0u8; 32];
                crypto::iv_key_hash256(&mut entry_iv_key, &combined);
                let mut dec = crypto::aes_cbc_decrypt(&entry_iv_key, &data)?;
                dec.truncate(r_size);
                std::fs::write(&out_path, &dec)
                    .with_context(|| format!("write {}", out_path.display()))?;
            }
        }

        // Read the PFS seed from the image offset + 0x370.
        self.file
            .seek(SeekFrom::Start(self.header.pfs_image_offset + 0x370))
            .context("seek to pfs image seed")?;
        let mut seed = [0u8; 16];
        self.file.read_exact(&mut seed).context("read pfs seed")?;

        let (data_key, tweak_key) = crypto::pfs_gen_crypto_key(&ekpfs_key, &seed);
        self.data_key = data_key;
        self.tweak_key = tweak_key;

        // Decrypt the first `length` bytes of the PFS image and locate PFSC.
        let length = self.header.pfs_cache_size as usize * 2;
        if length == 0 {
            return Ok(());
        }

        let mut pfs_encrypted = vec![0u8; length];
        self.file.seek(SeekFrom::Start(self.header.pfs_image_offset))?;
        self.file.read_exact(&mut pfs_encrypted)?;
        let mut pfs_decrypted = vec![0u8; length];
        crypto::decrypt_pfs(
            &self.data_key,
            &self.tweak_key,
            &pfs_encrypted,
            &mut pfs_decrypted,
            0,
        );

        let pfsc_rel = find_pfsc_offset(&pfs_decrypted)
            .context("failed to locate PFSC header in pfs image")?;
        self.pfsc_offset = pfsc_rel as u64;

        // The C++ reference copies `length - pfsc_offset` bytes from pfs_decrypted into a
        // `length`-sized zero-padded buffer; subsequent reads can overshoot the useful region
        // and would then land in that zero padding. Mirror that behaviour so we don't panic.
        let mut pfsc = vec![0u8; length];
        pfsc[..length - pfsc_rel].copy_from_slice(&pfs_decrypted[pfsc_rel..]);

        // PFSCHdr layout: magic(4) unk4(4) unk8(4) block_sz(4) block_sz2(8) block_offsets(8)
        // data_start(8) data_length(8).
        let block_sz2 = i64::from_le_bytes(pfsc[0x10..0x18].try_into().unwrap());
        let block_offsets = i64::from_le_bytes(pfsc[0x18..0x20].try_into().unwrap()) as usize;
        let data_length = i64::from_le_bytes(pfsc[0x28..0x30].try_into().unwrap());
        let num_blocks = (data_length / block_sz2) as usize;

        self.sector_map = (0..=num_blocks)
            .map(|i| {
                let o = block_offsets + i * 8;
                if o + 8 > pfsc.len() {
                    0
                } else {
                    u64::from_le_bytes(pfsc[o..o + 8].try_into().unwrap())
                }
            })
            .collect();

        // Walk inodes and dirents to populate fs_table + extract_paths.
        let mut ent_size: usize = 0;
        let mut ndinode: u32 = 0;
        let mut ndinode_counter: u32 = 0;
        let mut dinode_reached = false;
        let mut uroot_reached = false;
        let mut occupied_blocks: usize = 0;
        let mut current_dir = self.extract_path.clone();

        let mut decompressed = vec![0u8; SECTOR_SIZE];
        let mut decompressor = Decompress::new(true);

        for i in 0..num_blocks {
            let sector_offset = self.sector_map[i] as usize;
            let sector_size = (self.sector_map[i + 1] - self.sector_map[i]) as usize;
            let compressed = &pfsc[sector_offset..sector_offset + sector_size];

            if sector_size == SECTOR_SIZE {
                decompressed[..].copy_from_slice(compressed);
            } else {
                decompress_pfsc(&mut decompressor, compressed, &mut decompressed)?;
            }

            if i == 0 {
                ndinode = u32::from_le_bytes(decompressed[0x30..0x34].try_into().unwrap());
                occupied_blocks =
                    (ndinode as usize * INODE_STRIDE).div_ceil(SECTOR_SIZE);
            }

            if i >= 1 && i <= occupied_blocks {
                for p in (0..SECTOR_SIZE).step_by(INODE_STRIDE) {
                    if p + INODE_STRIDE > SECTOR_SIZE {
                        break;
                    }
                    let node = Inode::parse(&decompressed[p..p + INODE_STRIDE]);
                    if node.mode == 0 {
                        break;
                    }
                    self.inode_buf.push(node);
                }
            }

            // Root / uroot. "flat_path_table" literal at offset 0x10 means uroot block.
            if &decompressed[0x10..0x10 + 15] == b"flat_path_table" {
                uroot_reached = true;
            }

            if uroot_reached {
                ent_size = 0;
                let mut off = 0usize;
                while off < SECTOR_SIZE {
                    let dirent = parse_dirent(&decompressed[off..]);
                    ent_size = dirent.entsize as usize;
                    if dirent.ino != 0 {
                        ndinode_counter += 1;
                    } else {
                        let parent_path = self.extract_path.parent().unwrap_or(Path::new(""));
                        let filename_matches = parent_path
                            .file_name()
                            .map(|f| f.to_string_lossy() == self.title_id)
                            .unwrap_or(false);
                        let ends_with_patch = self
                            .extract_path
                            .to_string_lossy()
                            .ends_with("-patch");

                        let target = if !filename_matches && !ends_with_patch {
                            parent_path.join(&self.title_id)
                        } else {
                            self.extract_path.clone()
                        };
                        self.extract_paths.insert(ndinode_counter, target);
                        uroot_reached = false;
                        break;
                    }
                    off += ent_size.max(1);
                }
            }

            if decompressed[0x10] == b'.' && &decompressed[0x28..0x2A] == b".." {
                dinode_reached = true;
            }

            if dinode_reached {
                ent_size = 0;
                let mut off = 0usize;
                let mut end_reached = false;
                while off < SECTOR_SIZE {
                    let dirent = parse_dirent(&decompressed[off..]);
                    if dirent.ino == 0 {
                        break;
                    }
                    ent_size = dirent.entsize as usize;
                    let name_bytes =
                        &dirent.name_slice[..dirent.namelen.min(dirent.name_slice.len())];
                    let name = String::from_utf8_lossy(name_bytes).into_owned();

                    let entry = FsTableEntry {
                        name,
                        inode: dirent.ino as u32,
                        ty: dirent.ty as u32,
                    };

                    if entry.ty == PFS_CURRENT_DIR {
                        if let Some(p) = self.extract_paths.get(&entry.inode) {
                            current_dir = p.clone();
                        }
                    }
                    self.extract_paths
                        .insert(entry.inode, current_dir.join(&entry.name));

                    if entry.ty == PFS_FILE || entry.ty == PFS_DIR {
                        if entry.ty == PFS_DIR {
                            let dir = self.extract_paths.get(&entry.inode).unwrap().clone();
                            std::fs::create_dir_all(&dir)
                                .with_context(|| format!("mkdir {}", dir.display()))?;
                        }
                        ndinode_counter += 1;
                        if ndinode_counter + 1 == ndinode {
                            end_reached = true;
                        }
                    }

                    self.fs_table.push(entry);
                    off += ent_size.max(1);
                }
                if end_reached {
                    break;
                }
            }
            let _ = ent_size;
        }

        Ok(())
    }

    fn copy_entry_to_file(&mut self, entry: &PkgEntry, out_path: &Path) -> Result<()> {
        self.file.seek(SeekFrom::Start(entry.offset as u64))?;
        let mut data = vec![0u8; entry.size as usize];
        self.file.read_exact(&mut data)?;
        std::fs::write(out_path, &data)
            .with_context(|| format!("write {}", out_path.display()))?;
        Ok(())
    }

    /// Writes one file from the PFS image to disk. `index` is in `0..file_count()`.
    pub fn extract_file(&mut self, index: usize) -> Result<()> {
        let entry = &self.fs_table[index];
        if entry.ty != PFS_FILE {
            return Ok(());
        }

        let inode = &self.inode_buf[entry.inode as usize];
        let sector_loc = inode.loc as usize;
        let nblocks = inode.blocks as usize;
        let bsize = inode.size as usize;

        let out_path = self
            .extract_paths
            .get(&entry.inode)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no path for inode {}", entry.inode))?;
        if let Some(p) = out_path.parent() {
            std::fs::create_dir_all(p).ok();
        }
        let mut out = BufWriter::new(
            File::create(&out_path).with_context(|| format!("create {}", out_path.display()))?,
        );

        let pfsc_buf_size = 0x11000usize;
        let mut encrypted = vec![0u8; pfsc_buf_size];
        let mut decrypted = vec![0u8; pfsc_buf_size];
        let mut decompressed = vec![0u8; SECTOR_SIZE];
        let mut decompressor = Decompress::new(true);

        let mut size_decompressed: usize = 0;
        let mut pkg_file = File::open(&self.path)
            .with_context(|| format!("re-open {}", self.path.display()))?;

        for j in 0..nblocks {
            let sector_offset = self.sector_map[sector_loc + j] as usize;
            let sector_size =
                (self.sector_map[sector_loc + j + 1] - self.sector_map[sector_loc + j]) as usize;

            let abs = self.pfsc_offset as usize + sector_offset;
            let aligned = abs & !0xFFF;
            let within = abs - aligned;
            let file_off = self.header.pfs_image_offset as usize + aligned;
            let current_sector_xts = (aligned / 0x1000) as u64;

            pkg_file.seek(SeekFrom::Start(file_off as u64))?;
            // The C++ reference reads up to `pfsc_buf_size` bytes and tolerates short reads
            // at EOF; the trailing bytes aren't used for the current sector's actual data.
            encrypted.iter_mut().for_each(|b| *b = 0);
            read_as_much_as_possible(&mut pkg_file, &mut encrypted)?;
            crypto::decrypt_pfs(
                &self.data_key,
                &self.tweak_key,
                &encrypted,
                &mut decrypted,
                current_sector_xts,
            );

            let compressed = &decrypted[within..within + sector_size];

            if sector_size == SECTOR_SIZE {
                decompressed[..].copy_from_slice(compressed);
            } else {
                decompress_pfsc(&mut decompressor, compressed, &mut decompressed)?;
            }

            size_decompressed += SECTOR_SIZE;
            if j < nblocks - 1 {
                out.write_all(&decompressed)?;
            } else {
                let write_size = SECTOR_SIZE - (size_decompressed - bsize);
                out.write_all(&decompressed[..write_size])?;
            }
        }
        out.flush()?;
        Ok(())
    }
}

fn find_pfsc_offset(pfs_image: &[u8]) -> Option<usize> {
    let mut i = 0x20000;
    while i + 4 <= pfs_image.len() {
        let magic = u32::from_le_bytes(pfs_image[i..i + 4].try_into().unwrap());
        if magic == PFSC_MAGIC {
            return Some(i);
        }
        i += 0x10000;
    }
    None
}

fn read_as_much_as_possible(file: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

fn decompress_pfsc(
    decompressor: &mut Decompress,
    input: &[u8],
    output: &mut [u8],
) -> Result<()> {
    decompressor.reset(true);
    decompressor
        .decompress(input, output, FlushDecompress::Finish)
        .context("zlib inflate")?;
    Ok(())
}

struct DirentView<'a> {
    ino: i32,
    ty: i32,
    namelen: usize,
    entsize: i32,
    name_slice: &'a [u8],
}

fn parse_dirent(buf: &[u8]) -> DirentView<'_> {
    let ino = i32::from_le_bytes(buf[0..4].try_into().unwrap());
    let ty = i32::from_le_bytes(buf[4..8].try_into().unwrap());
    let namelen = i32::from_le_bytes(buf[8..12].try_into().unwrap()).max(0) as usize;
    let entsize = i32::from_le_bytes(buf[12..16].try_into().unwrap());
    let name_end = (16 + namelen).min(buf.len());
    DirentView {
        ino,
        ty,
        namelen,
        entsize,
        name_slice: &buf[16..name_end],
    }
}
