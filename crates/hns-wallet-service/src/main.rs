#![forbid(unsafe_code)]

use std::io::{self, ErrorKind, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use hns_wallet_ffi::{declared_payload_len, LENGTH_PREFIX_BYTES};
use hns_wallet_provider::MemoryProviderState;
use hns_wallet_service::{UnavailableRuntime, WalletService};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut service = WalletService::new_ephemeral(
        MemoryProviderState::default(),
        UnavailableRuntime,
    )?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
        match input.read(&mut prefix[..1]) {
            Ok(0) => return Ok(()),
            Ok(1) => {}
            Ok(_) => unreachable!("one-byte read returned more than one byte"),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
        input.read_exact(&mut prefix[1..])?;
        let length = declared_payload_len(prefix)?;
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + length);
        frame.extend_from_slice(&prefix);
        frame.resize(LENGTH_PREFIX_BYTES + length, 0);
        input.read_exact(&mut frame[LENGTH_PREFIX_BYTES..])?;
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?;
        let response = service.process_frame(&frame, now_unix_ms)?;
        output.write_all(&response)?;
        output.flush()?;
    }
}
