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
use crypto::sha2::Sha256;
use protobuf;

use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;
use sawtooth_sdk::processor::handler::TransactionHandler;
//use sawtooth_sdk::messaging::future::FutureTimeoutError;
//use sawtooth_sdk::processor::exceptions::InternalError;

use sawtooth_sdk::messages::transaction::TransactionHeader;
//use sawtooth_sdk::protobuf::setting_pb2::Setting;
use identities::{ IdentityPayload,
                  IdentityPayload_IdentityType};
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
const _SETTING_MAX_KEY_PARTS: usize = 4;
const _SETTING_ADDRESS_PART_SIZE: usize = 16;

// Number of seconds to wait for state operations to succeed
const STATE_TIMEOUT_SEC: u32 = 10;

///Computes the address for the given setting key.
/// Keys are broken into four parts, based on the dots in the string. For
/// example, the key `a.b.c` address is computed based on `a`, `b`, `c` and
/// padding. A longer key, for example `a.b.c.d.e`, is still
/// broken into four parts, but the remaining pieces are in the last part:
/// `a`, `b`, `c` and `d.e`.
///
/// Each of these pieces has a short hash computed (the first
/// _SETTING_ADDRESS_PART_SIZE characters of its SHA256 hash in hex), and is
/// joined into a single address, with the config namespace
/// (_SETTING_NAMESPACE) added at the beginning.
///
/// Args:
///     key (str): the setting key
/// Returns:
///     str: the computed address
///

fn setting_key_to_address(key: &str) -> String {
    // Split the key into _SETTING_MAX_KEY_PARTS parts, maximum, compute the
    // short hash of each, and then pad if necessary

    let key_parts: Vec<&str> = key.splitn(_SETTING_MAX_KEY_PARTS, ".").collect();
    let mut addr_parts: Vec<_> = key_parts.iter().map(|x| setting_short_hash(x)).collect();
    let len_addr_parts = addr_parts.len();
    addr_parts.extend(
        vec![get_setting_address_padding();_SETTING_MAX_KEY_PARTS - &len_addr_parts].iter().cloned());
    SETTING_NAMESPACE.to_string() + &addr_parts.join("")
}

fn setting_short_hash(byte_str: &str) -> String {
    let mut sha = Sha256::new();
    sha.input(byte_str.as_bytes());
    sha.result_str()[.._SETTING_ADDRESS_PART_SIZE].to_string()
}

fn get_setting_address_padding() -> String {
    setting_short_hash("")
}

fn get_allowed_signer_address() -> String {
    setting_key_to_address("sawtooth.identity.allowed_keys")
}

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
        transaction: &TpProcessRequest,
        context: &mut TransactionContext,
    ) -> Result<(), ApplyError> {
        let mut payload = unpack_payload(transaction.get_payload())?;

        match payload.get_field_type() {
            IdentityPayload_IdentityType::ROLE => {
                Ok(())
            }
            IdentityPayload_IdentityType::POLICY => {
                set_policy(&payload, context)
            }
            IdentityPayload_IdentityType::IDENTITY_TYPE_UNSET => Err(
                ApplyError::InvalidTransaction(String::from("The IdentityType must be either a ROLE or a POLICY")),
            ),
        }
    }

 }

fn unpack_payload(payload: &[u8]) -> Result<IdentityPayload, ApplyError> {
     protobuf::parse_from_bytes(&payload).map_err(|err| {
         warn!(
             "Invalid transaction: Failed to unmarshal IdentityTransaction: {:?}",
             err
         );
         ApplyError::InvalidTransaction(format!(
             "Failed to unmarshal IdentityTransaction: {:?}",
             err
         ))
     })
}

fn unpack_policy(payload_data: &[u8]) -> Result<Policy, ApplyError> {
     protobuf::parse_from_bytes(&payload_data).map_err(|err| {
         warn!(
             "Invalid transaction: Failed to unmarshal IdentityPayload data: {:?}",
             err
         );
         ApplyError::InvalidTransaction(format!(
             "Failed to unmarshal IdentityPayload data: {:?}",
             err
         ))
     })
}

fn unpack_policy_list(state_data: &[u8]) -> Result<PolicyList, ApplyError> {
     protobuf::parse_from_bytes(&state_data).map_err(|err| {
         warn!(
             "Invalid transaction: Failed to unmarshal IdentityPayload data: {:?}",
             err
         );
         ApplyError::InvalidTransaction(format!(
             "Failed to unmarshal IdentityPayload data: {:?}",
             err
         ))
     })
}

fn set_policy(payload: &IdentityPayload,
              context: &mut TransactionContext,
          ) -> Result<(), ApplyError> {
    let new_policy = unpack_policy(payload.get_data())?;
    if new_policy.get_entries().is_empty(){
        return Err(ApplyError::InvalidTransaction(format!("At least one entry must be in a policy.")))
    }
    if new_policy.get_name().is_empty(){
        return Err(ApplyError::InvalidTransaction(format!("The name must be set in a policy.")))
    }
    let address = get_policy_address(new_policy.get_name());
    let entries_list = get_data(&address, context)?;

    let policies:Vec<Policy> = match entries_list {
                    None => vec![new_policy.clone()],
                    Some(entries) => {
                        let policy_list = unpack_policy_list(&[entries[0]])?;
                        let mut policy_vec: Vec<Policy> = policy_list.get_policies().to_vec().into_iter()
                                                                     .filter(|x| x.get_name() != new_policy.get_name())
                                                                     .collect();
                        policy_vec.push(new_policy.clone());
                        policy_vec.sort_unstable_by(|p1, p2| p1.get_name().cmp(p2.get_name()));
                        policy_vec
                    }
            };


    let mut new_policy_list = PolicyList::new();

    new_policy_list.set_policies(protobuf::RepeatedField::from_vec(policies));

    let data = protobuf::Message::write_to_bytes(&new_policy_list).map_err(|err| {
        ApplyError::InvalidTransaction(format!("Failed to serialize PolicyList: {:?}", err))
    })?;

    context.set_state(&address, &data).map_err(|err| {
        warn!("Failed to set policy {} at {}", new_policy.get_name(), address);
        ApplyError::InternalError(format!("Unable to save policy {}", new_policy.get_name()))
    })?;
    //What is the data that should go here?
    //Is clone best option?

    // context.add_event("identity/update".to_string(),
    //                  vec![("updated".to_string(), new_policy.get_name().to_string())], &vec![])
    //                  .map_err(|err| {
    //                      warn!("Failed to add event {}", new_policy.get_name());
    //                      ApplyError::InternalError(format!("Failed to add event {}", new_policy.get_name()))
    //                  })
    debug!("Set policy : \n{:?}", new_policy);
    Ok(())
}

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

fn get_data(address: &str,
    context: &mut TransactionContext) -> Result<Option<Vec<u8>>, ApplyError> {
        let entries_list = context.get_state(address)?;
        return Ok(entries_list)
    }

fn to_hash(value: &str) -> String {
    let mut sha = Sha256::new();
    sha.input(value.as_bytes());
    sha.result_str()
}

fn get_policy_address(policy_name: &str) -> String {
    format!("{}{}{}", IDENTITY_NAMESPACE.to_string(), POLICY_PREFIX.to_string(),
            to_hash(policy_name)[..62].to_string())
}

const _MAX_KEY_PARTS: usize = 4;
const _FIRST_ADDRESS_PART_SIZE: usize = 14;
const _ADDRESS_PART_SIZE: usize = 16;

fn get_role_address(role_name: &str) -> String {
   let key_parts: Vec<&str> = role_name.splitn(_MAX_KEY_PARTS, ".").collect();
   let mut addr_parts: Vec<_> = vec![to_hash(key_parts[0])[.._FIRST_ADDRESS_PART_SIZE].to_string()];
   addr_parts.extend(key_parts[1..].iter().map(|x| to_hash(x)[.._ADDRESS_PART_SIZE].to_string()));
   let len_addr_parts = addr_parts.len();
   addr_parts.extend(
       vec![get_empty_part();_MAX_KEY_PARTS - &len_addr_parts].iter().cloned());
   format!("{}{}{}", IDENTITY_NAMESPACE.to_string(), ROLE_PREFIX.to_string(), addr_parts.join(""))
}
fn get_empty_part() -> String {
    to_hash("")[.._ADDRESS_PART_SIZE].to_string()
}
