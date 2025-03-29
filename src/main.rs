#![allow(clippy::collapsible_else_if)] // Keep if you prefer this style

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
const MAGIC_NO_COMPRESS_START1: u8 = 0x06; // Uncompressed (Sync Zlib header in C name was misleading)
const MAGIC_NO_COMPRESS_NO_CRYPT_START: u8 = 0x08; // Uncompressed
const MAGIC_COMPRESS_START: u8 = 0x04; // XOR + Raw Deflate
const MAGIC_COMPRESS_START1: u8 = 0x05; // Chunked + XOR + Raw Deflate
const MAGIC_COMPRESS_START2: u8 = 0x07; // Async + Encrypted (ECDH/TEA) + Raw Deflate
const MAGIC_COMPRESS_NO_CRYPT_START: u8 = 0x09; // Async + Raw Deflate

const MAGIC_SYNC_ZSTD_START: u8 = 0x0A; // Sync + Encrypted (ECDH/TEA) + Zstd
const MAGIC_SYNC_NO_CRYPT_ZSTD_START: u8 = 0x0B; // Sync + Zstd
const MAGIC_ASYNC_ZSTD_START: u8 = 0x0C; // Async + Encrypted (ECDH/TEA) + Zstd
const MAGIC_ASYNC_NO_CRYPT_ZSTD_START: u8 = 0x0D; // Async + Zstd

const MAGIC_END: u8 = 0x00; // End marker for log entries

// C code used simpler XOR based on this
const BASE_XOR_KEY: u8 = 0xCC;

// --- Error Handling ---
#[derive(Error, Debug)]
enum DecodeError {
    #[error("I/O Error: {0}")]
    Io(#[from] io::Error), // Handles file I/O, byteorder reads, zstd, flate2 reads

    #[error("Glob Error: {0}")]
    Glob(#[from] glob::GlobError),

    #[error("Glob Pattern Error: {0}")]
    GlobPattern(#[from] glob::PatternError),

    #[error("Decompression Error: {0}")]
    Decompression(io::Error), // Specific variant for flate2/zstd failures during decode

    #[error("Invalid Data: {0}")]
    InvalidData(String),

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
        _ => None, // Unknown/Unsupported magic byte
    }
}

/// Checks if a structurally valid log entry starts at the given offset.
/// Validates magic byte, header presence, length field, and end marker boundary.
/// Does *not* perform decompression or validate content.
///
/// Returns `Ok(next_entry_offset)` on structural validity, `Err(reason)` otherwise.
fn check_log_header(buffer: &[u8], offset: usize) -> Result<usize, String> {
    if offset >= buffer.len() {
        return Err("Offset reaches end of buffer".to_string());
    }

    // Check magic byte and determine crypt key length
    let magic_start = buffer[offset];
    let crypt_key_len = get_crypt_key_len(magic_start).ok_or_else(|| {
        format!(
            "Unknown magic start byte {:#04x} at offset {}",
            magic_start, offset
        )
    })?;

    // Minimum header length calculation (common fields + crypt key)
    // Structure: magic(1) + seq(2) + begin_hour(1) + end_hour(1) + data_length(4) + crypt_key(N)
    let header_len = 1 + 2 + 1 + 1 + 4 + crypt_key_len;

    // Check if buffer is long enough for the calculated header
    if offset
        .checked_add(header_len)
        .map_or(true, |end| end > buffer.len())
    // Checks overflow or if end > buffer.len()
    {
        return Err(format!(
            "Buffer too small for header. Need {} bytes from offset {}, have {} total bytes.",
            header_len,
            offset,
            buffer.len()
        ));
    }

    // Read data length field (u32 LE) safely
    let length_field_offset = offset + 1 + 2 + 1 + 1; // Offset to the 4-byte length field
    let data_length = match buffer.get(length_field_offset..length_field_offset + 4) {
        Some(slice) => match Cursor::new(slice).read_u32::<LittleEndian>() {
            Ok(l) => l as usize,
            Err(e) => return Err(format!("Failed to read length field: {}", e)),
        },
        None => unreachable!("Buffer length check should have caught this"), // Should be impossible
    };

    // --- Safe offset calculations using checked_add ---
    let data_start_offset = offset + header_len;

    let data_end_offset = match data_start_offset.checked_add(data_length) {
        Some(val) => val,
        None => {
            return Err(format!(
            "Overflow calculating data end offset (start={} + length={}). Corrupt length field?",
            data_start_offset, data_length
        ))
        }
    };

    // MAGIC_END byte is immediately after the data block
    let magic_end_offset = data_end_offset;

    // The next entry starts right after the MAGIC_END byte
    let next_entry_offset = match magic_end_offset.checked_add(1) {
        Some(val) => val,
        None => {
            return Err("Overflow calculating next entry offset. Corrupt length field?".to_string())
        }
    };

    // Check if the calculated end marker offset is within buffer bounds
    if magic_end_offset >= buffer.len() {
        return Err(format!(
            "Calculated MAGIC_END offset {} is out of bounds (buffer len {}). Corrupt length or truncated entry. Off={}, HdrLen={}, DataLen={}",
            magic_end_offset, buffer.len(), offset, header_len, data_length
        ));
    }

    // Verify the actual byte value at the expected end marker position
    let magic_end_actual = buffer[magic_end_offset];
    if magic_end_actual != MAGIC_END {
        return Err(format!(
            "Expected MAGIC_END ({:#04x}) at offset {}, found {:#04x}. Corrupt data or length field.",
            MAGIC_END, magic_end_offset, magic_end_actual
        ));
    }

    // All structural checks passed.
    Ok(next_entry_offset)
}

// Define a minimum plausible size for a valid entry to optimize search start.
// Uses the largest possible header size (64-byte key) + 1 data byte + end byte.
const MIN_ENTRY_SIZE: usize = 1 + 2 + 1 + 1 + 4 + 64 + 1 + 1;

/// Tries to find the starting offset of the first sequence of `count` structurally valid log entries.
/// Used to find the initial entry or to skip over corrupted data.
fn find_log_start_pos(buffer: &[u8], count: u32) -> Option<usize> {
    if count == 0 || buffer.len() < MIN_ENTRY_SIZE {
        log::debug!("find_log_start_pos: Invalid params or buffer too small.");
        return None;
    }

    // Avoid searching too close to the end where 'count' entries cannot possibly fit.
    let search_limit = buffer.len().saturating_sub(MIN_ENTRY_SIZE);

    log::debug!(
        "find_log_start_pos(count={}): Searching buffer (size {}) up to offset {}.",
        count,
        buffer.len(),
        search_limit
    );

    'outer: for start_offset in 0..=search_limit {
        // Quick check: Is it a potentially valid magic byte?
        if get_crypt_key_len(buffer[start_offset]).is_none() {
            continue; // Skip if not a known magic start byte
        }

        log::trace!("find_log_start_pos: Potential start at {}", start_offset);

        // Check if `count` valid entries follow consecutively from here
        let mut current_offset = start_offset;
        for i in 0..count {
            match check_log_header(buffer, current_offset) {
                Ok(next_offset) => {
                    // This check ensures forward progress, preventing infinite loops on corrupt data.
                    if next_offset <= current_offset {
                        log::error!("Logic error: next_offset ({}) <= current_offset ({}) from check_log_header at offset {}. Aborting check for start {}.", next_offset, current_offset, current_offset, start_offset);
                        continue 'outer; // Invalid sequence, try next start_offset
                    }

                    log::trace!(
                        "find_log_start_pos: Check {} Ok. Offset {} -> Next {}",
                        i,
                        current_offset,
                        next_offset
                    );
                    current_offset = next_offset; // Advance to where the next entry should start

                    // If this was the last check needed in the sequence, we found it.
                    if i == count - 1 {
                        log::debug!("find_log_start_pos: Found sequence of {} valid entries starting at {}. Final next_offset={}", count, start_offset, current_offset);
                        return Some(start_offset); // Success!
                    }
                }
                Err(ref reason) => {
                    // Found an invalid entry in the sequence.
                    log::trace!("find_log_start_pos: Check {} failed at offset {}: '{}'. Aborting check for start {}.", i, current_offset, reason, start_offset);
                    continue 'outer; // Invalid sequence, try next start_offset
                }
            }
            // Boundary check: Ensure the next offset to check is still within the buffer
            // (or exactly at the end, which is fine for the loop check).
            if current_offset > buffer.len() {
                log::trace!("find_log_start_pos: Next offset {} exceeds buffer length {}. Aborting check for start {}.", current_offset, buffer.len(), start_offset);
                continue 'outer; // Cannot check further, sequence invalid.
            }
        }
        // This point should only be reached if count is 0, which is handled at the start.
    }

    log::debug!(
        "find_log_start_pos(count={}): No valid sequence found.",
        count
    );
    None // No sequence of `count` valid entries found
}

/// Decodes a single log entry starting at `offset`, handling potential corruption and different formats.
/// Appends decoded data to `out_buffer`. Updates `last_seq`.
/// Returns the offset of the *next* entry or an Error.
fn decode_buffer(
    buffer: &[u8],
    offset: usize,
    out_buffer: &mut Vec<u8>,
    last_seq: &mut u16,
) -> Result<usize, DecodeError> {
    if offset >= buffer.len() {
        return Err(DecodeError::NotFound); // Base case: trying to read past end
    }

    // --- Attempt to Validate Header / Skip Corrupted Data ---
    let mut current_offset = offset;
    if let Err(header_err) = check_log_header(buffer, current_offset) {
        log::warn!(
            "Header check failed at offset {}: '{}'. Attempting to find next valid entry.",
            current_offset,
            header_err
        );
        // Try to find the start of the *next* valid entry
        let search_start = current_offset + 1;
        if search_start >= buffer.len() {
            log::error!(
                "Header check failed near end of buffer (offset {}), no more data to search.",
                current_offset
            );
            return Err(DecodeError::NotFound); // No more data left
        }

        match find_log_start_pos(&buffer[search_start..], 1) {
            Some(fix_pos_relative) => {
                // Found a potentially valid entry after the corruption
                let fix_pos_absolute = search_start + fix_pos_relative;
                let skipped_bytes = fix_pos_absolute - current_offset;
                let warning = format!(
                    "[!] decode_log_file: Skipped {} bytes of potentially corrupt data starting at offset {}. Original Header Error: {}\n", // Use [!] for user-visible warnings
                    skipped_bytes, current_offset, header_err
                );
                out_buffer.extend_from_slice(warning.as_bytes());
                log::warn!("{}", warning.trim_end()); // Log without extra newline
                current_offset = fix_pos_absolute; // Jump to the found position
            }
            None => {
                // Corruption occurred, and no further valid entries were found
                let warning = format!(
                    "[!] decode_log_file: Header error at offset {} ('{}') and no subsequent valid entries found. Processing stopped.\n",
                    current_offset, header_err
                );
                out_buffer.extend_from_slice(warning.as_bytes());
                log::error!("{}", warning.trim_end());
                return Err(DecodeError::NotFound); // Indicate end of usable data
            }
        }
    }

    // --- Re-check offset bounds after potential jump ---
    if current_offset >= buffer.len() {
        log::debug!("Reached end of buffer after skipping corruption.");
        return Err(DecodeError::NotFound);
    }

    // --- Read Validated Header Fields ---
    let magic_start = buffer[current_offset];
    // crypt_key_len should always be Some here, as check_log_header/find_log_start_pos succeeded
    let crypt_key_len = get_crypt_key_len(magic_start).ok_or_else(|| {
        // This should be unreachable if check_log_header passed
        DecodeError::InvalidData(format!(
            "Internal logic error: Validated header has unknown magic {:#04x} at offset {}",
            magic_start, current_offset
        ))
    })?;

    let header_len = 1 + 2 + 1 + 1 + 4 + crypt_key_len;
    // Basic header bounds check (defense in depth)
    if current_offset + header_len > buffer.len() {
        return Err(DecodeError::InvalidData(format!(
            "Validated header length {} exceeds buffer size {} at offset {}",
            header_len,
            buffer.len(),
            current_offset
        )));
    }

    // Use cursor for safe reading from the offset guaranteed by check_log_header
    let mut header_cursor = Cursor::new(&buffer[current_offset..current_offset + header_len]);
    header_cursor.set_position(1); // Skip magic byte

    let seq = header_cursor.read_u16::<LittleEndian>()?;
    let _begin_hour = header_cursor.read_u8()?; // Field exists but often unused
    let _end_hour = header_cursor.read_u8()?; // Field exists but often unused
    let length = header_cursor.read_u32::<LittleEndian>()? as usize; // Data block length

    log::debug!(
        "Processing entry: offset={}, magic={:#04x}, seq={}, data_len={}",
        current_offset,
        magic_start,
        seq,
        length
    );

    // --- Sequence Gap Check ---
    // seq=0 is often a special marker (e.g., start info), seq=1 is first real log
    if seq > 1 && *last_seq != 0 && seq != (*last_seq + 1) {
        let expected_seq = *last_seq + 1;
        let missing_range_end = seq.saturating_sub(1); // Avoid underflow if seq is 1
        let warning = format!(
                 "[!] decode_log_file: Log sequence gap detected. Expected {}, got {}. Range {}-{} missing.\n",
                 expected_seq, seq, expected_seq, missing_range_end
             );
        out_buffer.extend_from_slice(warning.as_bytes());
        log::warn!("{}", warning.trim_end());
    }
    // Update last sequence number seen (skip seq=0)
    if seq != 0 {
        *last_seq = seq;
    }

    // --- Extract Data Slice ---
    let data_start_offset = current_offset + header_len;
    let data_end_offset = data_start_offset + length;
    // Final check that data slice is within bounds (should be guaranteed by check_log_header)
    if data_end_offset > buffer.len() {
        return Err(DecodeError::InvalidData(format!("Data range [{}:{}) exceeds buffer bounds (len {}) for entry at offset {}. File truncated?", data_start_offset, data_end_offset, buffer.len(), current_offset)));
    }
    let original_data_slice = &buffer[data_start_offset..data_end_offset];

    // --- Prepare Data (Apply XOR if needed, Handle Chunking) ---

    // Determine if simple XOR is needed based on C code logic
    let xor_key: u8 = match magic_start {
        MAGIC_NO_COMPRESS_START | MAGIC_COMPRESS_START | MAGIC_COMPRESS_START1 => {
            let key = BASE_XOR_KEY ^ (seq as u8) ^ magic_start;
            log::trace!(
                "Applying XOR key {:#04x} for magic {:#04x}",
                key,
                magic_start
            );
            key
        }
        _ => 0, // No simple XOR for other types
    };

    // Process data: might involve copying, chunk reassembly, and XORing.
    // Result is owned Vec<u8> ready for decompression or use.
    let data_result: Result<Vec<u8>, DecodeError> = match magic_start {
        // Handle chunked format: Reassemble first, then XOR.
        MAGIC_COMPRESS_START1 => {
            let mut reassembled_data = Vec::with_capacity(length); // Initial guess
            let mut current_pos = 0;
            while current_pos < original_data_slice.len() {
                // Need 2 bytes for chunk length
                if current_pos + 2 > original_data_slice.len() {
                    return Err(DecodeError::InvalidData(format!(
                        "Incomplete chunk length at data offset {}",
                        current_pos
                    )));
                }
                // Read chunk length safely
                let mut chunk_len_cursor =
                    Cursor::new(&original_data_slice[current_pos..current_pos + 2]);
                let chunk_len = chunk_len_cursor.read_u16::<LittleEndian>()? as usize;
                current_pos += 2; // Advance past length field

                let chunk_end = current_pos + chunk_len;
                if chunk_end > original_data_slice.len() {
                    return Err(DecodeError::InvalidData(format!(
                        "Chunk length {} exceeds data slice bounds at data offset {}",
                        chunk_len,
                        current_pos - 2
                    )));
                }
                // Append chunk data
                reassembled_data.extend_from_slice(&original_data_slice[current_pos..chunk_end]);
                current_pos = chunk_end; // Advance past chunk data
            }
            // Apply XOR *after* reassembly
            if xor_key != 0 {
                for byte in reassembled_data.iter_mut() {
                    *byte ^= xor_key;
                }
            }
            Ok(reassembled_data)
        }
        // For all other formats: Copy the data, then apply XOR if needed.
        _ => {
            let mut data_copy = original_data_slice.to_vec();
            if xor_key != 0 {
                for byte in data_copy.iter_mut() {
                    *byte ^= xor_key;
                }
            }
            Ok(data_copy)
        }
    }; // End data preparation

    // Get the prepared data Vec<u8>, handling potential errors from chunking etc.
    let data_ready = match data_result {
        Ok(data) => data,
        Err(e) => {
            let error_msg = format!(
                "[!] decode_log_file: Failed preparing data for entry at offset {} (seq {}): {}\n",
                current_offset, seq, e
            );
            out_buffer.extend_from_slice(error_msg.as_bytes());
            log::error!("{}", error_msg.trim_end());
            // Attempt to recover by skipping to the next theoretical entry position
            let next_entry_offset = current_offset + header_len + length + 1;
            return Ok(next_entry_offset);
        }
    };

    // --- Decompression / Processing ---
    // `data_ready` is the owned Vec<u8> after potential XORing and chunking.
    let processing_outcome: Result<Vec<u8>, DecodeError> = match magic_start {
        // --- No Compression ---
        MAGIC_NO_COMPRESS_START            /* 0x03, XOR applied above */ |
        MAGIC_NO_COMPRESS_START1           /* 0x06 */ |
        MAGIC_NO_COMPRESS_NO_CRYPT_START   /* 0x08 */ => {
             Ok(data_ready) // Data is already final (potentially after XOR)
        }

        // --- Raw Deflate ---
        MAGIC_COMPRESS_START               /* 0x04, XOR + Raw Deflate */ |
        MAGIC_COMPRESS_START1              /* 0x05, Chunked + XOR + Raw Deflate */ |
        MAGIC_COMPRESS_NO_CRYPT_START      /* 0x09, Raw Deflate */ => {
            if data_ready.is_empty() {
                 Ok(Vec::new()) // Handle empty input
            } else {
                let mut decoder = DeflateDecoder::new(data_ready.as_slice());
                let mut decompressed = Vec::with_capacity(data_ready.len() * 3); // Heuristic buffer size
                // Use map_err to convert io::Error to DecodeError::Decompression
                decoder.read_to_end(&mut decompressed)
                    .map(|_| decompressed) // On success, return the decompressed Vec
                    .map_err(DecodeError::Decompression)
            }
        }
        // --- Raw Deflate (Encryption Skipped) ---
         MAGIC_COMPRESS_START2 /* 0x07 */ => {
            log::warn!("Entry at offset {} (seq {} magic {:#04x}) requires ECDH/TEA decryption (unsupported). Attempting raw DEFLATE on potentially encrypted data.", current_offset, seq, magic_start);
            if data_ready.is_empty() { Ok(Vec::new()) } else {
                let mut decoder = DeflateDecoder::new(data_ready.as_slice());
                let mut decompressed = Vec::with_capacity(data_ready.len() * 3);
                decoder.read_to_end(&mut decompressed)
                    .map(|_| decompressed)
                    .map_err(DecodeError::Decompression)
            }
        }

        // --- Zstd (No Encryption) ---
        MAGIC_ASYNC_NO_CRYPT_ZSTD_START  /* 0x0D */ |
        MAGIC_SYNC_NO_CRYPT_ZSTD_START   /* 0x0B */ => {
             zstd::decode_all(data_ready.as_slice())
                .map_err(DecodeError::Decompression)
        }
        // --- Zstd (Encryption Skipped) ---
        MAGIC_SYNC_ZSTD_START            /* 0x0A */ |
         MAGIC_ASYNC_ZSTD_START          /* 0x0C */ => {
            log::warn!("Entry at offset {} (seq {} magic {:#04x}) requires ECDH/TEA decryption (unsupported). Attempting ZSTD on potentially encrypted data.", current_offset, seq, magic_start);
             zstd::decode_all(data_ready.as_slice())
                .map_err(DecodeError::Decompression)
         }

        // Should not happen if get_crypt_key_len worked earlier
        _ => Err(DecodeError::UnsupportedFormat(magic_start)),
    }; // End match magic_start for decompression/processing

    // --- Handle Processing Outcome ---
    match processing_outcome {
        Ok(processed_data) => {
            // Append successfully decoded data to the output buffer
            if !processed_data.is_empty() {
                out_buffer.extend_from_slice(&processed_data);
            } else if length > 0 {
                // Log if original data wasn't empty but result is
                log::warn!("Processing entry at offset {} resulted in empty output (original data length: {}).", current_offset, length);
            }
        }
        Err(e) => {
            // Log the error and append a message to the output file
            let error_msg = format!( "[!] decode_log_file: Processing failed for entry at offset {} (seq {}, magic {:#04x}): {}\n", current_offset, seq, magic_start, e );
            out_buffer.extend_from_slice(error_msg.as_bytes());
            log::error!("{}", error_msg.trim_end());
            // Recovery: Proceed to calculate next offset, effectively skipping failed entry's content.
        }
    }

    // --- Calculate offset for the next entry ---
    // This happens regardless of success/failure for the current entry.
    // next_offset = current_entry_start + header_length + data_length + magic_end_byte(1)
    let next_entry_offset = current_offset + header_len + length + 1;
    Ok(next_entry_offset)
}

/// Parses a single xlog file, decodes its entries, and writes the output to a corresponding .log file.
fn parse_file(input_path: &Path, output_path: &Path) -> Result<(), DecodeError> {
    log::info!("Processing file: {:?}", input_path.display());
    let buffer = match fs::read(input_path) {
        Ok(b) => b,
        Err(e) => {
            log::error!(
                "Failed to read input file {:?}: {}",
                input_path.display(),
                e
            );
            return Err(e.into()); // Convert io::Error to DecodeError::Io
        }
    };

    if buffer.is_empty() {
        log::warn!("Input file is empty: {:?}", input_path.display());
        // Create empty output file to match behavior, propagate potential IO error
        File::create(output_path)?;
        return Ok(());
    }

    // --- Find Initial Reliable Starting Point ---
    // Prefer finding 2 consecutive valid headers to increase confidence against false positives.
    let initial_offset = match find_log_start_pos(&buffer, 2) {
        Some(offset) => {
            log::debug!(
                "Found initial offset {} validated by 2 consecutive entries.",
                offset
            );
            offset
        }
        None => {
            // Fallback: Try finding just 1 valid header. Might be less reliable.
            log::warn!("Could not find 2 consecutive valid entries. Trying to find just 1.");
            match find_log_start_pos(&buffer, 1) {
                Some(offset) => {
                    log::warn!("Found initial start offset {} validated by only 1 entry. Proceeding cautiously.", offset);
                    offset
                }
                None => {
                    // If even one valid header cannot be found, the file is likely unusable.
                    log::error!(
                        "No valid log entries found in file: {:?}",
                        input_path.display()
                    );
                    // Create an empty output file, but return error upstream.
                    File::create(output_path)?;
                    return Err(DecodeError::NotFound);
                }
            }
        }
    };

    // Log if we skipped initial bytes
    if initial_offset > 0 {
        log::warn!(
            "First valid log entry starts at offset {}. Skipping initial {} bytes.",
            initial_offset,
            initial_offset
        );
    } else {
        log::info!("First valid log entry starts at offset 0.");
    }

    // --- Decoding Loop ---
    let mut out_buffer: Vec<u8> = Vec::new(); // Buffer for decoded output content
    let mut last_seq: u16 = 0; // Track sequence numbers for gap detection
    let mut current_offset = initial_offset;

    loop {
        // Check if we've processed past the end of the buffer
        if current_offset >= buffer.len() {
            log::debug!(
                "Reached or passed end of buffer at offset {}.",
                current_offset
            );
            break;
        }

        match decode_buffer(&buffer, current_offset, &mut out_buffer, &mut last_seq) {
            Ok(next_offset) => {
                // Sanity check: Ensure decode_buffer always returns an offset > current
                if next_offset <= current_offset {
                    log::error!("Decode loop stalled: next_offset ({}) <= current_offset ({}). Aborting file processing.", next_offset, current_offset);
                    out_buffer.extend_from_slice(
                        b"[!] decode_log_file: Decode loop stalled. Aborting.\n",
                    );
                    break; // Prevent infinite loop
                }
                current_offset = next_offset; // Advance to the next entry
            }
            Err(DecodeError::NotFound) => {
                log::info!("Finished processing log entries near offset {}. No more valid entries found or required skipping.", current_offset);
                break; // Normal exit condition when end of valid data reached
            }
            Err(e) => {
                // Catch unexpected errors during the loop itself (should be rare)
                log::error!(
                    "Unexpected error during decoding loop near offset {}: {}. Aborting file.",
                    current_offset,
                    e
                );
                let err_msg = format!("[!] decode_log_file: Unexpected error: {}. Aborting.\n", e);
                out_buffer.extend_from_slice(err_msg.as_bytes());
                break; // Exit loop on unexpected issues
            }
        }
    } // End loop

    // --- Write Output ---
    if out_buffer.is_empty() && initial_offset == 0 && buffer.len() > 0 {
        // Log if the file wasn't empty, started at 0, but produced no output (or only error lines).
        log::warn!(
            "Processing completed, but no log content was successfully decoded for: {:?}",
            input_path.display()
        );
    } else {
        log::info!(
            "Writing decoded log content to: {:?}",
            output_path.display()
        );
    }

    match File::create(output_path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(&out_buffer) {
                log::error!(
                    "Failed to write output file {:?}: {}",
                    output_path.display(),
                    e
                );
                return Err(e.into());
            }
        }
        Err(e) => {
            log::error!(
                "Failed to create output file {:?}: {}",
                output_path.display(),
                e
            );
            return Err(e.into());
        }
    }

    Ok(()) // Successfully processed this file
}

// --- Command Line Interface ---
#[derive(Parser, Debug)]
#[command(author, version, about = "Decodes WeChat XLog files using various compression/XOR schemes.", long_about = None)]
struct Cli {
    /// Input .xlog file or directory containing .xlog files.
    /// If a directory, all .xlog files within will be processed.
    /// If omitted, searches for .xlog files in the current directory.
    #[arg()]
    input: Option<PathBuf>,

    /// Output .log file path.
    /// If input is a file, this specifies the exact output path.
    /// If input is a directory or omitted, this argument is ignored,
    /// and output files are created adjacent to inputs with a .log extension.
    /// Cannot be a directory.
    #[arg()]
    output: Option<PathBuf>,
}

// --- Main Execution ---
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging (reads RUST_LOG environment variable, defaults to info level)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    let mut final_result: Result<(), Box<dyn std::error::Error>> = Ok(()); // Track overall success/failure

    // --- Argument Processing Logic ---
    match (cli.input, cli.output) {
        // === Case 1: Specific Input File and Output File ===
        (Some(input_path), Some(output_path)) => {
            if input_path.is_dir() {
                return Err(
                    "Input path cannot be a directory when a specific output path is given.".into(),
                );
            }
            if output_path.is_dir() {
                return Err("Output path cannot be a directory.".into());
            }
            // Ensure output directory exists
            if let Some(parent) = output_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                    log::info!("Created output directory: {:?}", parent.display());
                }
            }
            // Process the single file
            if let Err(e) = parse_file(&input_path, &output_path) {
                log::error!("Error processing {}: {}", input_path.display(), e);
                // Keep the specific error for return
                final_result = Err(format!("Failed on {}: {}", input_path.display(), e).into());
            }
        }

        // === Case 2: Specific Input (File or Directory), Default Output ===
        (Some(input_path), None) => {
            if input_path.is_dir() {
                // Process all *.xlog files in the input directory
                let pattern = input_path.join("*.xlog");
                let pattern_str = pattern
                    .to_str()
                    .ok_or("Invalid input directory path encoding.")?;
                log::info!("Searching for files matching: {}", pattern_str);
                let mut files_found = false;

                for entry in glob(pattern_str)? {
                    match entry {
                        Ok(xlog_path) => {
                            if xlog_path.is_file() {
                                files_found = true;
                                let mut log_path = xlog_path.clone();
                                log_path.set_extension("log"); // Output alongside input
                                log::debug!(
                                    "Processing {:?} -> {:?}",
                                    xlog_path.display(),
                                    log_path.display()
                                );
                                if let Err(e) = parse_file(&xlog_path, &log_path) {
                                    log::error!("Error processing {}: {}", xlog_path.display(), e);
                                    // Keep the first error encountered
                                    if final_result.is_ok() {
                                        final_result = Err(format!(
                                            "Failed on {}: {}",
                                            xlog_path.display(),
                                            e
                                        )
                                        .into());
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("Error accessing file during glob search: {}", e);
                            if final_result.is_ok() {
                                final_result = Err(e.into());
                            }
                        }
                    }
                } // End glob loop
                if !files_found {
                    log::warn!(
                        "No .xlog files found in directory: {:?}",
                        input_path.display()
                    );
                }
            } else {
                // Input is a single file with default output name
                if !input_path.exists() {
                    return Err(format!("Input file not found: {}", input_path.display()).into());
                }
                let mut log_path = input_path.clone();
                log_path.set_extension("log"); // Output alongside input
                if let Err(e) = parse_file(&input_path, &log_path) {
                    log::error!("Error processing {}: {}", input_path.display(), e);
                    final_result = Err(format!("Failed on {}: {}", input_path.display(), e).into());
                }
            }
        }

        // === Case 3: No Input Specified (Use Current Directory), Default Output ===
        (None, None) => {
            let pattern = "*.xlog";
            log::info!(
                "No input specified. Searching for '{}' in current directory.",
                pattern
            );
            let mut files_found = false;

            for entry in glob(pattern)? {
                match entry {
                    Ok(xlog_path) => {
                        if xlog_path.is_file() {
                            files_found = true;
                            let mut log_path = xlog_path.clone();
                            log_path.set_extension("log");
                            log::debug!(
                                "Found: {:?}, outputting to {:?}",
                                xlog_path.display(),
                                log_path.display()
                            );
                            if let Err(e) = parse_file(&xlog_path, &log_path) {
                                log::error!("Error processing {}: {}", xlog_path.display(), e);
                                if final_result.is_ok() {
                                    final_result =
                                        Err(format!("Failed on {}: {}", xlog_path.display(), e)
                                            .into());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Error accessing file during glob search: {}", e);
                        if final_result.is_ok() {
                            final_result = Err(e.into());
                        }
                    }
                }
            } // End glob loop
            if !files_found {
                log::warn!("No .xlog files found in current directory.");
            }
        }

        // === Case 4: No Input, Specific Output (Invalid Combination) ===
        (None, Some(_)) => {
            return Err("Output path specified without an input path.".into());
        }
    } // End match cli args

    // --- Final Status Report ---
    if final_result.is_ok() {
        log::info!("Processing finished successfully.");
    } else {
        log::error!("Processing finished with errors. See logs above.");
        // Error is already in final_result, just return it to indicate failure
    }
    final_result
}
