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

pub mod messages;
pub mod pipe;

pub use messages::{
    BrokerRequest, BrokerResponse, LockingProcessDto, UserProfileDto,
};
pub use pipe::{
    create_secure_pipe_server_instance, send_broker_request,
    verify_pipe_client_identity, PipeError, PipeResult, SECURE_PIPE_NAME,
    SECURE_PIPE_SDDL,
};
