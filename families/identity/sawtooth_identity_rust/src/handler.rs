/*
 * Copyright 2018 Intel Corporation
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
 * ------------------------------------------------------------------------------
 */

use crypto::digest::Digest;
use crypto::sha2::Sha512;
use protobuf;

use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;
use sawtooth_sdk::processor::handler::TransactionHandler;
//use sawtooth_sdk::messaging::future::FutureTimeoutError;
//use sawtooth_sdk::processor::exceptions::InternalError;

use sawtooth_sdk::messages::transaction::TransactionHeader;
//use sawtooth_sdk::protobuf::setting_pb2::Setting;
use identities::IdentityPayload;
use sawtooth_sdk::messages::identity::{ Policy,
                                        PolicyList,
                                        Role,
                                        RoleList};


// The identity namespace is special: it is not derived from a hash.
const IDENTITY_NAMESPACE: &str =  "00001d";
const POLICY_PREFIX: &str = "00";
const ROLE_PREFIX: &str = "01";
const ALLOWED_SIGNER_SETTING: &str = "sawtooth.identity.allowed_keys";

// Constants to be used when constructing config namespace addresses
const SETTING_NAMESPACE: &str = "000000";
const _SETTING_MAX_KEY_PARTS: u32 = 4;
const _SETTING_ADDRESS_PART_SIZE: u32 = 16;

// Number of seconds to wait for state operations to succeed
const STATE_TIMEOUT_SEC: u32 = 10;

const ALLOWED_SIGNER_ADDRESS: &str = "TEST";//_setting_key_to_address(
//    "sawtooth.identity.allowed_keys")

pub struct IdentityTransactionHandler {
    family_name: String,
    family_versions: Vec<String>,
    namespaces: Vec<String>,
}

impl IdentityTransactionHandler {
    pub fn new() -> IdentityTransactionHandler {
        IdentityTransactionHandler {
            family_name: "sawtooth_identity".to_string(),
            family_versions: vec!["1.0".to_string()],
            namespaces: vec![IDENTITY_NAMESPACE.to_string()],
        }
    }
}

impl TransactionHandler for IdentityTransactionHandler {
    fn family_name(&self) -> String {
        self.family_name.clone()
    }

    fn family_versions(&self) -> Vec<String> {
        self.family_versions.clone()
    }

    fn namespaces(&self) -> Vec<String> {
        self.namespaces.clone()
    }

    fn apply(
        &self,
        request: &TpProcessRequest,
        context: &mut TransactionContext,
    ) -> Result<(), ApplyError> {
        Err(ApplyError::InvalidTransaction(String::from("Transaction type unset")))
    }

 }

// fn unpack_payload(payload: &[u8]) -> Result<IdentityPayload, ApplyError> {
//      protobuf::parse_from_bytes(&payload).map_err(|err| {
//          warn!(
//              "Invalid transaction: Failed to unmarshal IdentityTransaction: {:?}",
//              err
//          );
//          ApplyError::InvalidTransaction(format!(
//              "Failed to unmarshal IdentityTransaction: {:?}",
//              err
//          ))
//      })
// }
fn _check_allowed_transactor(request: &TpProcessRequest,
                             context: &mut TransactionContext) {
                                 ()
    //let header = unpack_payload(request.header);
    // let entries_list = _get_data(ALLOWED_SIGNER_ADDRESS, context).unwrap_or_else(|err| {
    //     ApplyError::InvalidTransaction(format!(
    //         "Invalid Transaction. Failed to get state {:?}",
    //         err
    //     ));
    //     ()
    // });

    // match entries_list {
    //     None => ()
    //         //request.get_signature();
    //         //println!("{:?}", "TEST2" );
    //         // ApplyError::InvalidTransaction(format!(
    //         // "The transaction signer is not authorized to submit transactions: {:?}",
    //         // &header.signer_public_key
    //     //))}
    //     Some => {
    //         ()
    //     }
    //
    // }
}

fn _get_data(header: &TransactionHeader,
    context: &mut TransactionContext) -> Result<Option<Vec<u8>>, ApplyError> {
        Err(ApplyError::InvalidTransaction(String::from("Transaction type unset")))

    }
