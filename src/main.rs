#![allow(clippy::collapsible_else_if)]

use byteorder::{LittleEndian, ReadBytesExt};
use clap::Parser;
use flate2::read::DeflateDecoder; // Raw deflate decoder
use glob::glob;
use log; // Logging framework
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error; // Error derivation

// --- Magic Numbers (Log Entry Types) ---
const MAGIC_NO_COMPRESS_START: u8 = 0x03; // XOR
const MAGIC_NO_COMPRESS_START1: u8 = 0x06; // Uncompressed
const MAGIC_NO_COMPRESS_NO_CRYPT_START: u8 = 0x08; // Uncompressed
const MAGIC_COMPRESS_START: u8 = 0x04; // XOR + Raw Deflate
const MAGIC_COMPRESS_START1: u8 = 0x05; // Chunked + XOR + Raw Deflate
const MAGIC_COMPRESS_START2: u8 = 0x07; // Needs ECDH/TEA + Raw Deflate
const MAGIC_COMPRESS_NO_CRYPT_START: u8 = 0x09; // Raw Deflate

const MAGIC_SYNC_ZSTD_START: u8 = 0x0A; // Needs ECDH/TEA + Zstd
const MAGIC_SYNC_NO_CRYPT_ZSTD_START: u8 = 0x0B; // Zstd
const MAGIC_ASYNC_ZSTD_START: u8 = 0x0C; // Needs ECDH/TEA + Zstd
const MAGIC_ASYNC_NO_CRYPT_ZSTD_START: u8 = 0x0D; // Zstd

const MAGIC_END: u8 = 0x00; // End marker for log entries
const BASE_XOR_KEY: u8 = 0xCC; // Key Modifier for simple XOR

// --- Error Handling ---
#[derive(Error, Debug)]
enum DecodeError {
    #[error("I/O Error: {0}")]
    Io(#[from] io::Error), // File I/O, byteorder, zstd/flate2 reads

    #[error("Glob Error: {0}")]
    Glob(#[from] glob::GlobError),

    #[error("Glob Pattern Error: {0}")]
    GlobPattern(#[from] glob::PatternError),

    #[error("Decompression Error: {0}")]
    Decompression(#[source] io::Error), // Specific variant for flate2/zstd failures

    #[error("Invalid Data: {0}")]
    InvalidData(String), // Structural issues, bad lengths, failed XOR/chunking

    #[error("Log entry sequence not found or file empty")]
    NotFound,

    #[error("Unsupported format/magic byte: {0:#04x}")]
    UnsupportedFormat(u8),
}

// --- Helper Functions ---

/// Determines the expected length of the cryptography key field based on the magic byte.
fn get_crypt_key_len(magic_start: u8) -> Option<usize> {
    match magic_start {
        MAGIC_NO_COMPRESS_START | MAGIC_COMPRESS_START | MAGIC_COMPRESS_START1 => Some(4),
        MAGIC_COMPRESS_START2
        | MAGIC_NO_COMPRESS_START1
        | MAGIC_NO_COMPRESS_NO_CRYPT_START
        | MAGIC_COMPRESS_NO_CRYPT_START
        | MAGIC_SYNC_ZSTD_START
        | MAGIC_SYNC_NO_CRYPT_ZSTD_START
        | MAGIC_ASYNC_ZSTD_START
        | MAGIC_ASYNC_NO_CRYPT_ZSTD_START => Some(64),
        _ => None,
    }
}

/// Checks if a structurally valid log entry starts at the given offset.
/// Validates magic byte, header presence, length field, and end marker boundary.
/// Returns `Ok(next_entry_offset)` on structural validity, `Err(reason)` otherwise.
fn check_log_header(buffer: &[u8], offset: usize) -> Result<usize, String> {
    let buffer_len = buffer.len();
    if offset >= buffer_len {
        return Err("Offset is outside buffer bounds".to_string());
    }

    let magic_start = buffer[offset];
    let crypt_key_len = get_crypt_key_len(magic_start).ok_or_else(|| {
        format!(
            "Unknown magic start byte {:#04x} at offset {}",
            magic_start, offset
        )
    })?;

    // Structure: magic(1) + seq(2) + begin_hour(1) + end_hour(1) + data_length(4) + crypt_key(N)
    let header_len = 1 + 2 + 1 + 1 + 4 + crypt_key_len;

    let header_end_offset = offset
        .checked_add(header_len)
        .ok_or("Integer overflow calculating header end offset")?;
    if header_end_offset > buffer_len {
        return Err(format!(
            "Buffer too small for header (needs {} bytes, have {})",
            header_len,
            buffer_len - offset
        ));
    }

    let length_field_offset = offset + 1 + 2 + 1 + 1;
    let data_length = Cursor::new(&buffer[length_field_offset..length_field_offset + 4])
        .read_u32::<LittleEndian>()
        .map_err(|e| format!("Failed to read data length field: {}", e))?
        as usize;

    let data_start_offset = header_end_offset; // Data starts immediately after header
    let data_end_offset = data_start_offset.checked_add(data_length).ok_or_else(|| {
        format!(
            "Integer overflow calculating data end offset (start={}, len={})",
            data_start_offset, data_length
        )
    })?;
    let magic_end_offset = data_end_offset; // MAGIC_END is immediately after data

    let next_entry_offset = magic_end_offset
        .checked_add(1)
        .ok_or("Integer overflow calculating next entry offset")?;

    if magic_end_offset >= buffer_len {
        return Err(format!("Calculated MAGIC_END offset {} out of bounds (len {}). Corrupt length/truncated. Off={}, HdrLen={}, DataLen={}", magic_end_offset, buffer_len, offset, header_len, data_length));
    }

    let magic_end_actual = buffer[magic_end_offset];
    if magic_end_actual != MAGIC_END {
        return Err(format!(
            "Expected MAGIC_END ({:#04x}) at offset {}, found {:#04x}.",
            MAGIC_END, magic_end_offset, magic_end_actual
        ));
    }

    Ok(next_entry_offset)
}

const MIN_ENTRY_SIZE: usize = 1 + 2 + 1 + 1 + 4 + 64 + 1 + 1; // Max header + data(1) + end_magic(1)

/// Tries to find the starting offset of the first sequence of `count` structurally valid log entries.
fn find_log_start_pos(buffer: &[u8], count: u32) -> Option<usize> {
    if count == 0 || buffer.len() < MIN_ENTRY_SIZE {
        return None;
    }
    let search_limit = buffer.len().saturating_sub(MIN_ENTRY_SIZE);
    log::debug!(
        "find_log_start_pos(count={}): Searching up to offset {}.",
        count,
        search_limit
    );

    'outer: for start_offset in 0..=search_limit {
        if get_crypt_key_len(buffer[start_offset]).is_none() {
            continue;
        }
        log::trace!("find_log_start_pos: Potential start at {}", start_offset);
        let mut current_offset = start_offset;
        for i in 0..count {
            match check_log_header(buffer, current_offset) {
                Ok(next_offset) => {
                    if next_offset <= current_offset {
                        log::error!("Logic error: check_log_header({}) returned non-progressing offset {}. Aborting search for start {}.", current_offset, next_offset, start_offset);
                        continue 'outer;
                    }
                    log::trace!(
                        "find_log_start_pos: Check {} Ok. Offset {} -> Next {}",
                        i,
                        current_offset,
                        next_offset
                    );
                    current_offset = next_offset;
                    if i == count - 1 {
                        log::debug!(
                            "find_log_start_pos: Success. Found {} entries starting at {}.",
                            count,
                            start_offset
                        );
                        return Some(start_offset);
                    }
                    // Optimization: if next offset is already past buffer end, no point continuing inner loop
                    if current_offset >= buffer.len() && i < count - 1 {
                        log::trace!("find_log_start_pos: Next offset {} reached buffer end prematurely. Aborting check for start {}.", current_offset, start_offset);
                        continue 'outer;
                    }
                }
                Err(ref reason) => {
                    log::trace!("find_log_start_pos: Check {} failed at {}: '{}'. Aborting check for start {}.", i, current_offset, reason, start_offset);
                    continue 'outer;
                }
            }
        }
    }
    log::debug!(
        "find_log_start_pos(count={}): No valid sequence found.",
        count
    );
    None
}

/// Decodes a single log entry, handling data preparation (XOR/chunking) and decompression.
/// Appends decoded data or error messages to `out_buffer`.
/// Returns `Ok(next_entry_offset)` even if decoding failed, to allow skipping.
/// Returns `Err(DecodeError::NotFound)` only if the initial offset is invalid or end of file reached prematurely.
fn decode_single_entry(
    buffer: &[u8],
    offset: usize,
    out_buffer: &mut Vec<u8>,
    last_seq: &mut u16,
) -> Result<usize, DecodeError> {
    // Validate header structure first. If this fails, we might try to find the next one.
    let (header_len, seq, length, magic_start) = match validate_and_parse_header(buffer, offset) {
        Ok(header_info) => header_info,
        Err(e) => {
            // If header validation fails at the current offset, try finding the next valid one.
            log::warn!(
                "Header check failed at offset {}: '{}'. Searching for next valid entry.",
                offset,
                e
            );
            return find_next_valid_entry_start(buffer, offset, out_buffer)
                .map_err(|_| DecodeError::NotFound); // If find fails, treat as NotFound
        }
    };

    log::debug!(
        "Processing entry: offset={}, magic={:#04x}, seq={}, data_len={}",
        offset,
        magic_start,
        seq,
        length
    );

    // --- Sequence Gap Check ---
    check_sequence_gap(seq, last_seq, out_buffer);

    // --- Prepare Data (Slice, XOR, Chunking) ---
    let data_result = prepare_data_for_decode(buffer, offset, header_len, length, magic_start, seq);

    let data_ready = match data_result {
        Ok(data) => data,
        Err(e) => {
            // If data preparation (e.g., chunking) fails, log & skip.
            log_and_append_error(&e, offset, seq, magic_start, out_buffer);
            // Calculate next offset to skip this broken entry
            let next_offset = offset + header_len + length + 1;
            return Ok(next_offset);
        }
    };

    // --- Decompression ---
    let processing_outcome = decompress_data(&data_ready, magic_start, offset, seq);

    // --- Handle Outcome ---
    match processing_outcome {
        Ok(processed_data) => {
            if !processed_data.is_empty() {
                out_buffer.extend_from_slice(&processed_data);
            } else if length > 0 {
                log::warn!("Processing entry at offset {} resulted in empty output (original data length: {}).", offset, length);
            }
        }
        Err(e) => {
            log_and_append_error(&e, offset, seq, magic_start, out_buffer);
            // Still proceed to calculate next offset below to skip entry
        }
    }

    // --- Calculate offset for the next entry ---
    let next_entry_offset = offset + header_len + length + 1;
    Ok(next_entry_offset)
}

// --- Sub-functions for decode_single_entry ---

/// Validates header at offset and extracts key fields.
fn validate_and_parse_header(
    buffer: &[u8],
    offset: usize,
) -> Result<(usize, u16, usize, u8), String> {
    if offset >= buffer.len() {
        return Err("Offset >= buffer length".to_string());
    }

    let magic_start = buffer[offset];
    let crypt_key_len = get_crypt_key_len(magic_start)
        .ok_or_else(|| format!("Invalid magic byte {:#04x}", magic_start))?;
    let header_len = 1 + 2 + 1 + 1 + 4 + crypt_key_len;

    if offset + header_len > buffer.len() {
        return Err(format!(
            "Buffer too small for header (needs {}, have {})",
            header_len,
            buffer.len() - offset
        ));
    }

    // Use check_log_header logic implicitly by checking its return value
    check_log_header(buffer, offset)?; // If this passes, structure is OK

    // Parse fields now that structure is validated
    let mut cursor = Cursor::new(&buffer[offset + 1..offset + header_len]); // Skip magic
    let seq = cursor
        .read_u16::<LittleEndian>()
        .map_err(|e| e.to_string())?;
    let _begin_hour = cursor.read_u8().map_err(|e| e.to_string())?;
    let _end_hour = cursor.read_u8().map_err(|e| e.to_string())?;
    let length = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| e.to_string())? as usize;

    Ok((header_len, seq, length, magic_start))
}

/// Checks for gaps in log sequence numbers.
fn check_sequence_gap(seq: u16, last_seq: &mut u16, out_buffer: &mut Vec<u8>) {
    if seq > 1 && *last_seq != 0 && seq != (*last_seq + 1) {
        let expected = *last_seq + 1;
        let missing_end = seq - 1;
        let warning = format!(
            "[!] Sequence gap: Expected {}, got {}. Missing: {}-{}\n",
            expected, seq, expected, missing_end
        );
        out_buffer.extend_from_slice(warning.as_bytes());
        log::warn!("{}", warning.trim_end());
    }
    if seq != 0 {
        *last_seq = seq;
    }
}

/// Extracts data slice, applies XOR, handles chunking.
fn prepare_data_for_decode(
    buffer: &[u8],
    offset: usize,
    header_len: usize,
    length: usize,
    magic_start: u8,
    seq: u16,
) -> Result<Vec<u8>, DecodeError> {
    let data_start = offset + header_len;
    let data_end = data_start + length;
    if data_end > buffer.len() {
        return Err(DecodeError::InvalidData(format!(
            "Data range [{}:{}) exceeds buffer len {}",
            data_start,
            data_end,
            buffer.len()
        )));
    }
    let original_data_slice = &buffer[data_start..data_end];

    // --- Simple XOR ---
    let xor_key = match magic_start {
        MAGIC_NO_COMPRESS_START | MAGIC_COMPRESS_START | MAGIC_COMPRESS_START1 => {
            let key = BASE_XOR_KEY ^ (seq as u8) ^ magic_start;
            log::trace!("Applying XOR key {:#04x}", key);
            key
        }
        _ => 0,
    };

    // --- Chunking & XOR ---
    let mut data_ready = match magic_start {
        MAGIC_COMPRESS_START1 => {
            // Chunked format
            let mut reassembled = Vec::with_capacity(length);
            let mut current_pos = 0;
            while current_pos < original_data_slice.len() {
                if current_pos + 2 > original_data_slice.len() {
                    return Err(DecodeError::InvalidData(
                        "Incomplete chunk length".to_string(),
                    ));
                }
                let chunk_len = Cursor::new(&original_data_slice[current_pos..current_pos + 2])
                    .read_u16::<LittleEndian>()? as usize;
                current_pos += 2;
                let chunk_end = current_pos + chunk_len;
                if chunk_end > original_data_slice.len() {
                    return Err(DecodeError::InvalidData(format!(
                        "Chunk len {} exceeds data bounds",
                        chunk_len
                    )));
                }
                reassembled.extend_from_slice(&original_data_slice[current_pos..chunk_end]);
                current_pos = chunk_end;
            }
            reassembled // XOR will be applied below
        }
        _ => original_data_slice.to_vec(), // Other formats: just copy
    };

    // Apply XOR if needed (works on both reassembled and copied data)
    if xor_key != 0 {
        for byte in data_ready.iter_mut() {
            *byte ^= xor_key;
        }
    }

    Ok(data_ready)
}

/// Performs decompression based on magic byte.
fn decompress_data(
    data_ready: &[u8],
    magic_start: u8,
    offset: usize,
    seq: u16,
) -> Result<Vec<u8>, DecodeError> {
    match magic_start {
        // No Compression
        MAGIC_NO_COMPRESS_START | MAGIC_NO_COMPRESS_START1 | MAGIC_NO_COMPRESS_NO_CRYPT_START => {
            Ok(data_ready.to_vec()) // Return owned vec
        }
        // Raw Deflate
        MAGIC_COMPRESS_START | MAGIC_COMPRESS_START1 | MAGIC_COMPRESS_NO_CRYPT_START => {
            if data_ready.is_empty() {
                Ok(Vec::new())
            } else {
                let mut decoder = DeflateDecoder::new(data_ready);
                // Create the buffer first
                let mut decompressed = Vec::with_capacity(data_ready.len() * 3);
                // Read into the buffer, map error, then return the buffer on success
                decoder
                    .read_to_end(&mut decompressed)
                    .map(|_| decompressed) // On Ok(usize), return Ok(decompressed Vec)
                    .map_err(DecodeError::Decompression)
            }
        }
        // Raw Deflate (Encrypted) - FIX HERE
        MAGIC_COMPRESS_START2 => {
            log::warn!("Entry at offset {} (seq {}, magic {:#04x}) needs ECDH/TEA decryption (unsupported). Attempting raw DEFLATE.", offset, seq, magic_start);
            if data_ready.is_empty() {
                Ok(Vec::new())
            } else {
                let mut decoder = DeflateDecoder::new(data_ready);
                // Create the buffer first
                let mut decompressed = Vec::with_capacity(data_ready.len() * 3);
                // Read into the buffer, map error, then return the buffer on success
                decoder
                    .read_to_end(&mut decompressed)
                    .map(|_| decompressed) // <-- Add this map step
                    .map_err(DecodeError::Decompression)
            }
        }
        // Zstd (No Crypt)
        MAGIC_ASYNC_NO_CRYPT_ZSTD_START | MAGIC_SYNC_NO_CRYPT_ZSTD_START => {
            zstd::decode_all(data_ready).map_err(DecodeError::Decompression)
        }
        // Zstd (Encrypted)
        MAGIC_SYNC_ZSTD_START | MAGIC_ASYNC_ZSTD_START => {
            log::warn!("Entry at offset {} (seq {}, magic {:#04x}) requires ECDH/TEA decryption (unsupported). Attempting ZSTD.", offset, seq, magic_start);
            zstd::decode_all(data_ready).map_err(DecodeError::Decompression)
        }
        _ => Err(DecodeError::UnsupportedFormat(magic_start)),
    }
}

/// Logs an error and appends a message to the output buffer.
fn log_and_append_error(
    e: &DecodeError,
    offset: usize,
    seq: u16,
    magic_start: u8,
    out_buffer: &mut Vec<u8>,
) {
    let error_msg = format!(
        "[!] Failed entry offset={}, seq={}, magic={:#04x}: {}\n",
        offset, seq, magic_start, e
    );
    out_buffer.extend_from_slice(error_msg.as_bytes());
    log::error!("{}", error_msg.trim_end());
}

/// Tries to find the start of the next valid entry after a failure.
fn find_next_valid_entry_start(
    buffer: &[u8],
    failed_offset: usize,
    out_buffer: &mut Vec<u8>,
) -> Result<usize, DecodeError> {
    let search_start = failed_offset + 1;
    if search_start >= buffer.len() {
        return Err(DecodeError::NotFound);
    }

    match find_log_start_pos(&buffer[search_start..], 1) {
        Some(relative_offset) => {
            let absolute_offset = search_start + relative_offset;
            let skipped_bytes = absolute_offset - failed_offset;
            let warning = format!(
                "[!] Skipped {} potentially corrupt bytes after offset {}.\n",
                skipped_bytes, failed_offset
            );
            out_buffer.extend_from_slice(warning.as_bytes());
            log::warn!("{}", warning.trim_end());
            Ok(absolute_offset) // Return the offset of the next valid entry
        }
        None => Err(DecodeError::NotFound), // No more valid entries found after this point
    }
}

/// Parses a single xlog file, handles decoding loop and output writing.
fn parse_file(input_path: &Path, output_path: &Path) -> Result<(), DecodeError> {
    log::info!("Processing {}", input_path.display());
    let buffer = fs::read(input_path)?; // Propagates io::Error

    if buffer.is_empty() {
        log::warn!("Input file is empty: {}", input_path.display());
        File::create(output_path)?; // Create empty output
        return Ok(());
    }

    // --- Find Initial Start ---
    let initial_offset = match find_log_start_pos(&buffer, 2) {
        // Prefer 2 consecutive
        Some(offset) => offset,
        None => find_log_start_pos(&buffer, 1) // Fallback to 1
            .ok_or_else(|| {
                log::error!("No valid log entries found in {}", input_path.display());
                // Create empty file on total failure before returning error
                if let Err(e) = File::create(output_path) {
                    log::error!(
                        "Failed to create empty output file {}: {}",
                        output_path.display(),
                        e
                    );
                }
                DecodeError::NotFound
            })?,
    };

    if initial_offset > 0 {
        log::warn!(
            "Skipping first {} bytes, starting decode at offset {}.",
            initial_offset,
            initial_offset
        );
    }

    // --- Decoding Loop ---
    let mut out_buffer = Vec::with_capacity(buffer.len() * 2); // Heuristic preallocation
    let mut last_seq = 0u16;
    let mut current_offset = initial_offset;

    while current_offset < buffer.len() {
        match decode_single_entry(&buffer, current_offset, &mut out_buffer, &mut last_seq) {
            Ok(next_offset) => {
                if next_offset <= current_offset {
                    // Should ideally not happen with new structure
                    log::error!(
                        "Decode loop stalled: offset {} -> {}. Aborting file.",
                        current_offset,
                        next_offset
                    );
                    out_buffer.extend_from_slice(b"[!] Internal Error: Decode loop stalled.\n");
                    break;
                }
                current_offset = next_offset;
            }
            Err(DecodeError::NotFound) => {
                log::info!(
                    "Stopped processing near offset {}: End of valid data.",
                    current_offset
                );
                break; // Normal end condition when recovery fails
            }
            Err(e) => {
                // Should be less common now as decode_single_entry tries to return Ok on failure
                log::error!(
                    "Unexpected error in decode loop at {}: {}. Aborting file.",
                    current_offset,
                    e
                );
                let error_msg = format!("[!] Unexpected Loop Error: {}. Aborting.\n", e);
                out_buffer.extend_from_slice(error_msg.as_bytes());
                break;
            }
        }
    } // End while loop

    // --- Write Output ---
    if out_buffer.is_empty() && initial_offset == 0 && buffer.len() > 0 {
        log::warn!(
            "Processing completed, but no log content was successfully decoded for: {}",
            input_path.display()
        );
    }
    log::info!(
        "Writing {} bytes to {}",
        out_buffer.len(),
        output_path.display()
    );

    if let Some(parent) = output_path.parent() {
        // Ensure output dir exists
        fs::create_dir_all(parent)?;
    }
    fs::write(output_path, &out_buffer)?; // Write content

    Ok(())
}

// --- Command Line Interface ---
#[derive(Parser, Debug)]
#[command(author, version, about = "Decodes XLog files (Rust Port)", long_about = None)]
struct Cli {
    #[arg()]
    input: Option<PathBuf>,
    #[arg()]
    output: Option<PathBuf>,
}

// --- Main Execution & Argument Handling Helpers ---

/// Processes a single input file to the specified output file.
fn process_single_file(
    input: &Path,
    output: &Path,
    first_error: &mut Option<Box<dyn std::error::Error>>,
) {
    if let Err(e) = parse_file(input, output) {
        log::error!("Failed processing {}: {}", input.display(), e);
        if first_error.is_none() {
            *first_error = Some(format!("Failed on {}: {}", input.display(), e).into());
        }
    }
}

/// Processes all *.xlog files in a given directory.
fn process_directory(
    dir: &Path,
    first_error: &mut Option<Box<dyn std::error::Error>>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let pattern = dir.join("*.xlog");
    let pattern_str = pattern.to_str().ok_or("Invalid directory path encoding")?;
    log::info!("Searching for files matching: {}", pattern_str);
    let mut found_files = false;

    for entry in glob(pattern_str)? {
        match entry {
            Ok(xlog_path) => {
                if xlog_path.is_file() {
                    found_files = true;
                    let mut log_path = xlog_path.clone();
                    log_path.set_extension("log");
                    log::debug!("Queueing {} -> {}", xlog_path.display(), log_path.display());
                    process_single_file(&xlog_path, &log_path, first_error);
                }
            }
            Err(e) => {
                log::error!("Error accessing file during glob search: {}", e);
                if first_error.is_none() {
                    *first_error = Some(e.into());
                }
            }
        }
    }
    Ok(found_files)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let mut first_error: Option<Box<dyn std::error::Error>> = None;

    match (cli.input.as_ref(), cli.output.as_ref()) {
        // Case 1: Input File and Output File
        (Some(input), Some(output)) => {
            if input.is_dir() {
                return Err("Input cannot be directory when output is specified.".into());
            }
            if output.is_dir() {
                return Err("Output path cannot be a directory.".into());
            }
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            } // Ensure output dir exists
            process_single_file(input, output, &mut first_error);
        }
        // Case 2: Input (File or Dir), Default Output Name(s)
        (Some(input), None) => {
            if input.is_dir() {
                let found = process_directory(input, &mut first_error)?;
                if !found {
                    log::warn!("No *.xlog files found in directory: {}", input.display());
                }
            } else {
                // Input is file
                if !input.exists() {
                    return Err(format!("Input file not found: {}", input.display()).into());
                }
                let mut output = input.clone();
                output.set_extension("log");
                process_single_file(input, &output, &mut first_error);
            }
        }
        // Case 3: No Input (Current Dir), Default Output Names
        (None, None) => {
            let current_dir = std::env::current_dir()?;
            log::info!(
                "No input specified, searching current directory: {}",
                current_dir.display()
            );
            let found = process_directory(&current_dir, &mut first_error)?;
            if !found {
                log::warn!("No *.xlog files found in current directory.");
            }
        }
        // Case 4: No Input, Output Specified (Invalid)
        (None, Some(_)) => {
            return Err("Cannot specify output file without specifying input file.".into());
        }
    }

    // Return first error encountered, or Ok
    match first_error {
        Some(err) => {
            log::error!("Processing finished with errors.");
            Err(err)
        }
        None => {
            log::info!("Processing finished successfully.");
            Ok(())
        }
    }
}
