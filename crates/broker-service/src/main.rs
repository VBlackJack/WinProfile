/*
 * Copyright 2026 Julien Bombled
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

mod handler;

use audit_journal::{AuditLogger, SnapshotEngine};
use broker_protocol::{
    create_secure_pipe_server_instance, verify_pipe_client_identity,
    BrokerRequest, BrokerResponse,
};
use handler::handle_broker_request;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, DisconnectNamedPipe};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("WinProfile Privileged Broker Service starting...");

    let snapshot_engine = SnapshotEngine::new(None)?;
    let audit_logger = AuditLogger::new(None, 500)?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc_handler(r);

    tracing::info!("Broker listening on secure local Named Pipe: \\\\.\\pipe\\WinProfileBrokerSecure");

    while running.load(Ordering::SeqCst) {
        let pipe_handle = match create_secure_pipe_server_instance() {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(err = %e, "Failed to create named pipe instance");
                std::thread::sleep(std::time::Duration::from_millis(500));
                continue;
            }
        };

        // Wait for incoming client connection
        let connect_status = unsafe { ConnectNamedPipe(pipe_handle.as_raw(), std::ptr::null_mut()) };
        if connect_status == 0 {
            let last_err = unsafe { GetLastError() };
            // 535 = ERROR_PIPE_CONNECTED
            if last_err != 535 {
                tracing::warn!(err = last_err, "ConnectNamedPipe error");
                continue;
            }
        }

        // Verify client identity via impersonation
        if let Err(e) = verify_pipe_client_identity(&pipe_handle) {
            tracing::warn!(err = %e, "Rejected unauthorized named pipe client");
            unsafe { DisconnectNamedPipe(pipe_handle.as_raw()) };
            continue;
        }

        // Read request length
        let mut req_len = 0u32;
        let mut bytes_read = 0u32;
        let read_len_res = unsafe {
            ReadFile(
                pipe_handle.as_raw(),
                &mut req_len as *mut u32 as *mut u8,
                4,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };

        if read_len_res == 0 || bytes_read < 4 || req_len > 1024 * 1024 {
            unsafe { DisconnectNamedPipe(pipe_handle.as_raw()) };
            continue;
        }

        let mut req_buf = vec![0u8; req_len as usize];
        let read_payload_res = unsafe {
            ReadFile(
                pipe_handle.as_raw(),
                req_buf.as_mut_ptr(),
                req_len,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };

        if read_payload_res == 0 {
            unsafe { DisconnectNamedPipe(pipe_handle.as_raw()) };
            continue;
        }

        let response = match serde_json::from_slice::<BrokerRequest>(&req_buf[..bytes_read as usize]) {
            Ok(request) => handle_broker_request(request, &snapshot_engine, &audit_logger),
            Err(e) => BrokerResponse::Error {
                code: 400,
                message: format!("Malformed request: {e}"),
            },
        };

        // Write response back to client
        if let Ok(resp_bytes) = serde_json::to_vec(&response) {
            let resp_len = resp_bytes.len() as u32;
            let mut bytes_written = 0u32;

            unsafe {
                WriteFile(
                    pipe_handle.as_raw(),
                    &resp_len as *const u32 as *const u8,
                    4,
                    &mut bytes_written,
                    std::ptr::null_mut(),
                );
                WriteFile(
                    pipe_handle.as_raw(),
                    resp_bytes.as_ptr(),
                    resp_len,
                    &mut bytes_written,
                    std::ptr::null_mut(),
                );
            }
        }

        unsafe { DisconnectNamedPipe(pipe_handle.as_raw()) };
    }

    tracing::info!("WinProfile Broker Service terminated cleanly.");
    Ok(())
}

fn ctrlc_handler(_running: Arc<AtomicBool>) {
    tracing::info!("Shutdown signal received, terminating service");
}
