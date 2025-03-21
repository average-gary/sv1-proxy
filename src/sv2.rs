use async_channel::{Receiver, Sender};
use codec_sv2::{Frame, HandshakeRole, Responder, StandardEitherFrame, StandardSv2Frame, Sv2Frame};
use key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use network_helpers_sv2::noise_connection::Connection;
use roles_logic_sv2::errors::Error as Sv2Error;
use roles_logic_sv2::mining_sv2::{
    Extranonce, OpenMiningChannelError, OpenStandardMiningChannelSuccess, SetCustomMiningJob, SubmitSharesExtended, SubmitSharesStandard, UpdateChannel
};
use roles_logic_sv2::parsers::{Mining, MiningDeviceMessages};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::AbortHandle;

// An atomic counter to assign each miner a unique constrained extranonce.
// This is shared between SV1 and SV2 miners to ensure unique IDs across both protocols.
pub static MINER_ID_COUNTER: AtomicUsize = AtomicUsize::new(0);

// ------------ SV2 ------------
pub type Message = MiningDeviceMessages<'static>;
pub type StdFrame = StandardSv2Frame<Message>;
pub type EitherFrame = StandardEitherFrame<Message>;

pub async fn handle_miner_sv2(
    socket: tokio::net::TcpStream,
    mut _job_rx: broadcast::Receiver<String>,
    share_tx: mpsc::Sender<String>,
    _job_params: Arc<Mutex<Option<crate::JobParams>>>,
    last_notify: Arc<Mutex<Option<String>>>,
    _last_difficulty: Arc<Mutex<Option<String>>>,
    _worker_name: String,
    _on_share_submitted: Arc<dyn Fn(String) + Send + Sync>,
    public_key: Secp256k1PublicKey,
    private_key: Secp256k1SecretKey,
) -> () {
    // parse server pubkey
    let responder = Responder::from_authority_kp(
        &public_key.into_bytes(),
        &private_key.into_bytes(),
        Duration::from_secs(360),
    );
    let responder = match responder {
        Ok(responder) => responder,
        Err(e) => {
            println!("Error creating Handshake responder: {:?}", e);
            return;
        }
    };

    let (receiver, sender, _, _): (
        Receiver<EitherFrame>,
        Sender<EitherFrame>,
        AbortHandle,
        AbortHandle,
    ) = Connection::new(socket, HandshakeRole::Responder(responder))
        .await
        .expect("Failed to create connection");

    let id = MINER_ID_COUNTER.fetch_add(1, Ordering::Relaxed) as u32;
    let node = DownstreamMiningNode::new(receiver, share_tx, id);

    let mut incoming: StdFrame = node.receiver.recv().await.unwrap().try_into().unwrap();
    let message_type = incoming.get_header().unwrap().msg_type();
    let payload = incoming.payload();
    let message: Result<Mining<'_>, Sv2Error> = (message_type, payload).try_into();
    match message {
        Ok(Mining::OpenStandardMiningChannel(m)) => {
            // Response is OpenStandardMiningChannelSuccess
            // TODO: what is extranonce_prefix?
            // TODO: convert target to U256
            println!(
                "Received OpenStandardMiningChannel from: {} with id: {}",
                std::str::from_utf8(m.user_identity.as_ref()).unwrap_or("Unknown identity"),
                m.get_request_id_as_u32()
            );
            println!("Received OpenStandardMiningChannel from: {} with id: {}", 
                std::str::from_utf8(m.user_identity.as_ref()).unwrap_or("Unknown identity"),
                m.get_request_id_as_u32()
            );
            let target = last_notify.lock().await.clone().unwrap().clone();
            // TODO: endianess might bite us here
            let target: [u8; 32] = target.as_bytes().try_into().unwrap();
            // TODO: wtf is an extranonce? and how is it used?
            let extranonce_prefix: Extranonce = Extranonce::new(10).unwrap();
            let success: OpenStandardMiningChannelSuccess = OpenStandardMiningChannelSuccess {
                request_id: m.get_request_id_as_u32().into(),
                channel_id: 0,
                target: target.into(),
                extranonce_prefix: extranonce_prefix.into(),
                group_channel_id: 0,
            };
            let response =
                MiningDeviceMessages::Mining(Mining::OpenStandardMiningChannelSuccess(success));
            let response_frame: Sv2Frame<MiningDeviceMessages, Vec<u8>> =
                response.try_into().unwrap();
            let either_frame: Frame<MiningDeviceMessages<'static>, Vec<u8>> = response_frame.into();
            let _ = sender.send(either_frame);
        }
        Ok(Mining::OpenExtendedMiningChannel(m)) => {
            // Error because we don't support extended mining channels
            println!(
                "Received OpenExtendedMiningChannel from: {} with id: {}",
                std::str::from_utf8(m.user_identity.as_ref()).unwrap_or("Unknown identity"),
                m.get_request_id_as_u32()
            );
            println!("OpenExtendedMiningChannel: {:?}", m);
            let error = OpenMiningChannelError::new_unknown_user(m.get_request_id_as_u32());
            let message = MiningDeviceMessages::Mining(
                roles_logic_sv2::parsers::Mining::OpenMiningChannelError(error),
            );
            let sv2_frame: Sv2Frame<MiningDeviceMessages, Vec<u8>> = message.try_into().unwrap();
            let either_frame: Frame<MiningDeviceMessages<'static>, Vec<u8>> = sv2_frame.into();
            let _ = sender.send(either_frame);
            return;
        }
        Ok(Mining::UpdateChannel(message)) => {
            // Client notifies the server about changes on the specified channel. If a client performs device/connection aggregation (i.e. it is a proxy), it MUST send this message when downstream channels change. This update can be debounced so that it is not sent more often than once in a second (for a very busy proxy).
            // Field Name	Data Type	Description
            // channel_id	U32	Channel identification
            // nominal_hash_rate	F32	See Open*Channel for details
            // maximum_target	U256	Maximum target is changed by server by sending SetTarget. This field is understood as device's request. There can be some delay between UpdateChannel and corresponding SetTarget messages, based on new job readiness on the server.
            // When maximum_target is smaller than currently used maximum target for the channel, upstream node MUST reflect the client's request (and send appropriate SetTarget message).
            
            let UpdateChannel {
                channel_id,
                nominal_hash_rate,
                maximum_target,
            } = message;
            
            println!("Received UpdateChannel: channel_id={}, nominal_hash_rate={}, maximum_target={:?}", 
                channel_id, nominal_hash_rate, maximum_target);
            // TODO: handle this message. probably something with the target. For now we just log it.
        }
        Ok(Mining::SubmitSharesStandard(message)) => {
            // TODO: convert from Sv2 to Sv1 share to then submit via the share_tx
            let SubmitSharesStandard {
                channel_id,
                sequence_number,
                job_id,
                nonce,
                ntime,
                version,
            } = message;
            println!("Received SubmitSharesStandard: channel_id={}, sequence_number={}, job_id={}, nonce={}, ntime={}, version={}", 
                channel_id, sequence_number, job_id, nonce, ntime, version);

        }
        Ok(Mining::SubmitSharesExtended(message)) => {
            // TODO: convert from Sv2 to Sv1 share to then submit via the share_tx
            let SubmitSharesExtended {
                channel_id,
                sequence_number,
                job_id,
                nonce,
                ntime,
                version,
                extranonce,
            } = message;
            println!("Received SubmitSharesExtended: channel_id={}, sequence_number={}, job_id={}, nonce={}, ntime={}, version={}, extranonce={:?}", 
                channel_id, sequence_number, job_id, nonce, ntime, version, extranonce);
        }
        Ok(Mining::SetCustomMiningJob(message)) => {
            let SetCustomMiningJob {
                channel_id,
                request_id,
                min_ntime,
                version,
                prev_hash,
                nbits,
                coinbase_tx_version,
                coinbase_prefix,
                coinbase_tx_input_n_sequence,
                coinbase_tx_value_remaining,
                coinbase_tx_outputs,
                coinbase_tx_locktime,
                merkle_path,
                extranonce_size,
                token,
            } = message;
            println!("ReceivedSetCustomMiningJob: channel_id={}, request_id={}, min_ntime={}, version={}, prev_hash={:?}, nbits={}, coinbase_tx_version={}, coinbase_prefix={:?}, coinbase_tx_input_n_sequence={}, coinbase_tx_value_remaining={}, coinbase_tx_outputs={:?}, coinbase_tx_locktime={}, merkle_path={:?}, extranonce_size={}, token={:?}",    
                channel_id, request_id, min_ntime, version, prev_hash, nbits, coinbase_tx_version, coinbase_prefix, coinbase_tx_input_n_sequence, coinbase_tx_value_remaining, coinbase_tx_outputs, coinbase_tx_locktime, merkle_path, extranonce_size, token);
            println!("THIS SHOULD NOT HAPPEN");
        }
        Ok(_) => println!("Unexpected message type: {}", message_type),
        Err(e) => println!("Error parsing message: {:?}", e),
    }
}

pub struct DownstreamMiningNode {
    pub id: u32,
    pub receiver: Receiver<EitherFrame>,
    pub sender: mpsc::Sender<String>,
}

impl DownstreamMiningNode {
    pub fn new(receiver: Receiver<EitherFrame>, sender: mpsc::Sender<String>, id: u32) -> Self {
        Self {
            id,
            receiver,
            sender,
        }
    }
} 