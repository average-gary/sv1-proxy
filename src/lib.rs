use async_channel::{Receiver, Sender};
use codec_sv2::{Frame, HandshakeRole, Responder, StandardEitherFrame, StandardSv2Frame, Sv2Frame};
use key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use network_helpers_sv2::noise_connection::Connection;
use roles_logic_sv2::errors::Error as Sv2Error;
use roles_logic_sv2::mining_sv2::{
    Extranonce, OpenMiningChannelError, OpenStandardMiningChannelSuccess, SetCustomMiningJob, SubmitSharesExtended, SubmitSharesStandard, UpdateChannel
};
use roles_logic_sv2::parsers::{Mining, MiningDeviceMessages};
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::AbortHandle;

mod sv2;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Config {
    keys: Keys,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Keys {
    public_key: String,
    private_key: String,
}

// Structure to hold upstream job parameters.
#[derive(Clone, Debug)]
pub struct JobParams {
    coinb1: String,
    coinb2: String,
    full_extranonce1: String,
    extranonce2_size: usize,
    difficulty: f64,
}

// Shared state to store upstream job parameters.
type SharedJobParams = Arc<Mutex<Option<JobParams>>>;

// Shared state to cache the most recent mining.notify message.
type SharedLastNotify = Arc<Mutex<Option<String>>>;

type SharedLastDifficulty = Arc<Mutex<Option<String>>>;

type SharedLastPrevHash = Arc<Mutex<Option<String>>>;

// An atomic counter to assign each miner a unique constrained extranonce.
static MINER_ID_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub async fn run_proxy(
    upstream_addr: &str,
    worker_name: &str,
    on_new_block: Arc<dyn Fn(String) + Send + Sync + 'static>,
    on_share_submitted: Arc<dyn Fn(String) + Send + Sync + 'static>,
) -> Result<(), Box<dyn Error>> {
    // Read configuration
    let config_content = fs::read_to_string("config.toml")?;
    let config: Config = toml::from_str(&config_content)?;
    let public_key = config.keys.public_key;
    let private_key = config.keys.private_key;

    // Connect to the upstream pool.
    let mut upstream_stream = TcpStream::connect(&upstream_addr).await?;
    println!("Connected to upstream at {}", upstream_addr);

    let configure_message = json!({
        "id": 1,
        "method": "mining.configure",
        "params": [["version-rolling"], {"version-rolling.mask": "1fffe000"}]
    })
    .to_string();
    upstream_stream
        .write_all(configure_message.as_bytes())
        .await?;
    upstream_stream.write_all(b"\n").await?;
    upstream_stream.flush().await?;
    println!("Sent configure request to upstream.");

    // Send subscribe request to upstream.
    let subscribe_message = json!({
        "id": 2,
        "method": "mining.subscribe",
        "params": []
    })
    .to_string();
    upstream_stream
        .write_all(subscribe_message.as_bytes())
        .await?;
    upstream_stream.write_all(b"\n").await?;
    upstream_stream.flush().await?;
    println!("Sent subscribe request to upstream.");

    // Send authorize request using the worker name passed via CLI.
    let authorize_message = json!({
        "id": 3,
        "method": "mining.authorize",
        "params": [worker_name, "x"]  // Replace "x" with a password if needed.
    })
    .to_string();
    upstream_stream
        .write_all(authorize_message.as_bytes())
        .await?;
    upstream_stream.write_all(b"\n").await?;
    upstream_stream.flush().await?;
    println!("Sent authorize request to upstream.");

    // Send suggest_difficulty request to upstream.
    let suggest_difficulty_message = json!({
        "id": 4,
        "method": "mining.suggest_difficulty",
        "params": [1000.0]  // Replace with the desired difficulty
    })
    .to_string();
    upstream_stream
        .write_all(suggest_difficulty_message.as_bytes())
        .await?;
    upstream_stream.write_all(b"\n").await?;
    upstream_stream.flush().await?;
    println!("Sent suggest_difficulty request to upstream.");

    // Split the upstream connection.
    let (upstream_reader, upstream_writer) = upstream_stream.into_split();

    let job_params: SharedJobParams = Arc::new(Mutex::new(None));
    let last_notify: SharedLastNotify = Arc::new(Mutex::new(None));
    let last_difficulty: SharedLastNotify = Arc::new(Mutex::new(None));
    let last_prev_hash: SharedLastPrevHash = Arc::new(Mutex::new(None));

    // Broadcast channel for job (mining.notify) messages.
    let (job_tx, _) = broadcast::channel::<String>(16);
    // MPSC channel for share submissions forwarded upstream.
    let (share_tx, share_rx) = mpsc::channel::<String>(16);

    // Spawn task to read from upstream.
    {
        let job_tx = job_tx.clone();
        let job_params = job_params.clone();
        let last_notify = last_notify.clone();
        let last_difficulty = last_difficulty.clone();
        let last_prev_hash = last_prev_hash.clone();
        tokio::spawn(async move {
            upstream_read_handler(
                upstream_reader,
                job_tx,
                job_params,
                last_notify,
                last_difficulty,
                on_new_block,
                last_prev_hash,
            )
            .await;
        });
    }

    // Spawn task to write share submissions to upstream.
    {
        tokio::spawn(async move {
            upstream_write_handler(upstream_writer, share_rx).await;
        });
    }

    // Listen for downstream miner connections.
    let local_addr = "0.0.0.0:3334"; // A port separate from upstream.
    let listener = TcpListener::bind(local_addr).await?;
    println!("Listening for miners on {}", local_addr);

    // Listen for SV2 miner connections on a different port
    let local_addr_sv2 = "0.0.0.0:3335"; // A separate port for SV2 miners
    let listener_sv2 = TcpListener::bind(local_addr_sv2).await?;
    println!("Listening for SV2 miners on {}", local_addr_sv2);

    // Spawn task to handle SV2 connections
    {
        let job_tx = job_tx.clone();
        let share_tx = share_tx.clone();
        let job_params = job_params.clone();
        let last_notify = last_notify.clone();
        let last_difficulty = last_difficulty.clone();
        let worker_name = worker_name.to_string();
        let on_share_submitted = on_share_submitted.clone();
        let public_key = public_key.clone();
        let private_key = private_key.clone();

        tokio::spawn(async move {
            loop {
                let (miner_socket, addr) = listener_sv2.accept().await.unwrap();
                println!("Accepted SV2 miner connection from {}", addr);
                let job_tx = job_tx.clone();
                let share_tx = share_tx.clone();
                let job_params = job_params.clone();
                let last_notify: Arc<Mutex<Option<String>>> = last_notify.clone();
                let last_difficulty: Arc<Mutex<Option<String>>> = last_difficulty.clone();
                let worker_name: String = worker_name.to_string();
                let on_share_submitted: Arc<dyn Fn(String) + Send + Sync> =
                    on_share_submitted.clone();
                let public_key = public_key.clone();
                let private_key = private_key.clone();
                tokio::spawn(async move {
                    let public_key = Secp256k1PublicKey::from_str(&public_key).unwrap();
                    let private_key = Secp256k1SecretKey::from_str(&private_key).unwrap();
                    handle_miner_sv2(
                        miner_socket,
                        job_tx.subscribe(),
                        share_tx,
                        job_params.clone(),
                        last_notify,
                        last_difficulty,
                        worker_name,
                        on_share_submitted,
                        public_key,
                        private_key,
                    )
                    .await;
                });
            }
        });
    }

    // Handle original SV1 connections
    loop {
        let (miner_socket, addr) = listener.accept().await?;
        println!("Accepted miner connection from {}", addr);
        let job_tx = job_tx.clone();
        let share_tx = share_tx.clone();
        let job_params = job_params.clone();
        let last_notify = last_notify.clone();
        let last_difficulty = last_difficulty.clone();
        let worker_name = worker_name.to_string();
        let on_share_submitted = on_share_submitted.clone();
        tokio::spawn(async move {
            handle_miner(
                miner_socket,
                job_tx.subscribe(),
                share_tx,
                job_params,
                last_notify,
                last_difficulty,
                worker_name,
                on_share_submitted,
            )
            .await;
        });
    }
}

/// Reads messages from upstream.
/// - For each mining.notify, updates the cached notify and broadcasts it.
/// - For the subscribe response (id==1), extracts extranonce parameters.
/// - For the authorize response (id==2) that succeeds, broadcasts the cached mining.notify.
async fn upstream_read_handler(
    reader: tokio::net::tcp::OwnedReadHalf,
    job_tx: broadcast::Sender<String>,
    job_params: SharedJobParams,
    last_notify: SharedLastNotify,
    last_difficutly: SharedLastDifficulty,
    on_new_block: Arc<dyn Fn(String) + Send + Sync + 'static>,
    last_prev_hash: SharedLastPrevHash,
) {
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        match buf_reader.read_line(&mut line).await {
            Ok(0) => {
                println!("Upstream closed connection");
                break;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                println!("Upstream message: {}", trimmed);
                if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
                    // Check if it's a mining.notify.
                    if let Some(method) = val.get("method").and_then(|m| m.as_str()) {
                        if method == "mining.notify" {
                            if let Some(params) = val.get("params").and_then(|p| p.as_array()) {
                                if let Some(prevhash_json) = params.get(1) {
                                    let new_prevhash =
                                        prevhash_json.as_str().unwrap_or("").to_string();

                                    let mut last_hash_guard = last_prev_hash.lock().await;
                                    let changed = match &*last_hash_guard {
                                        Some(old_hash) => *old_hash != new_prevhash,
                                        None => true,
                                    };

                                    if changed {
                                        *last_hash_guard = Some(new_prevhash);
                                        on_new_block(trimmed.to_string());
                                    }
                                }
                            }
                            {
                                // Cache the most recent notify.
                                let mut last_lock = last_notify.lock().await;
                                *last_lock = Some(trimmed.to_string());
                            }
                            let _ = job_tx.send(trimmed.to_string());
                            continue;
                        } else if method == "mining.set_difficulty" {
                            // Handle mining.set_difficulty
                            if let Some(params) = val.get("params").and_then(|p| p.as_array()) {
                                if let Some(difficulty) = params.get(0).and_then(|d| d.as_f64()) {
                                    let mut lock = job_params.lock().await;
                                    if let Some(ref mut job_params) = *lock {
                                        job_params.difficulty = difficulty;
                                        println!("Stored upstream difficulty: {}", difficulty);
                                    }
                                    drop(lock);
                                    // Cache the difficulty
                                    let mut last_lock = last_difficutly.lock().await;
                                    *last_lock = Some(trimmed.to_string());
                                    // Broadcast the set_difficulty message downstream
                                    let _ = job_tx.send(trimmed.to_string());
                                }
                            }
                            continue;
                        }
                    }
                    // Check for subscribe (id==1) response.
                    if let Some(id) = val.get("id").and_then(|v| v.as_u64()) {
                        if id == 2 {
                            if let Some(result) = val.get("result").and_then(|r| r.as_array()) {
                                if result.len() >= 3 {
                                    if let (Some(full_extranonce1), Some(extranonce2_size)) = (
                                        result.get(1).and_then(|v| v.as_str()),
                                        result.get(2).and_then(|v| v.as_u64()),
                                    ) {
                                        let params = JobParams {
                                            coinb1: "".to_string(),
                                            coinb2: "".to_string(),
                                            full_extranonce1: full_extranonce1.to_string(),
                                            extranonce2_size: extranonce2_size as usize,
                                            difficulty: 1000.0, // Default difficulty
                                        };
                                        let mut lock = job_params.lock().await;
                                        *lock = Some(params);
                                        println!("Stored upstream job parameters: {:?}", *lock);
                                    }
                                }
                            }
                        } else if id == 3 {
                            // This is the authorize response.
                            // If authorize was successful (result==true), broadcast the cached notify.
                            if let Some(result) = val.get("result") {
                                if result.as_bool().unwrap_or(false) {
                                    let cached = {
                                        let lock = last_notify.lock().await;
                                        lock.clone()
                                    };
                                    if let Some(notify_msg) = cached {
                                        println!(
                                            "Broadcasting cached mining.notify after authorize: {}",
                                            notify_msg
                                        );
                                        let _ = job_tx.send(notify_msg);
                                    }
                                } else {
                                    println!("Authorize failed: {}", trimmed);
                                }
                            }
                        }
                    }
                } else {
                    println!("Failed to parse JSON: {}", trimmed);
                }
            }
            Err(e) => {
                println!("Error reading from upstream: {:?}", e);
                break;
            }
        }
    }
}

/// Writes share submissions to the upstream pool.
async fn upstream_write_handler(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::Receiver<String>,
) {
    while let Some(share) = rx.recv().await {
        println!("Forwarding share to upstream: {}", share);
        if let Err(e) = writer.write_all(share.as_bytes()).await {
            println!("Error writing share to upstream: {:?}", e);
            break;
        }
        if let Err(e) = writer.write_all(b"\n").await {
            println!("Error writing newline to upstream: {:?}", e);
            break;
        }
    }
}

/// Handles a miner connection:
/// - Responds to the miner's subscribe with a constrained extranonce.
/// - Sends the current cached mining.notify if available.
/// - Forwards mining.notify messages (modified for the miner) and transforms share submissions.
async fn handle_miner(
    socket: TcpStream,
    mut job_rx: broadcast::Receiver<String>,
    share_tx: mpsc::Sender<String>,
    job_params: SharedJobParams,
    last_notify: SharedLastNotify,
    last_difficulty: SharedLastDifficulty,
    worker_name: String,
    on_share_submitted: Arc<dyn Fn(String) + Send + Sync + 'static>,
) {
    let miner_id = MINER_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let constrained_extranonce = format!("{:04x}", miner_id);
    println!(
        "Assigned constrained extranonce {} to miner {}",
        constrained_extranonce, miner_id
    );

    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Read the miner's configure request.
    if let Ok(n) = reader.read_line(&mut line).await {
        if n > 0 {
            println!("Miner {} sent: {}", miner_id, line.trim_end());

            // Build and send the configure response.
            let configure_response = json!({
                "id": 1,
                "result": {
                    "version-rolling": true,
                    "version-rolling.mask": "1fffe000",
                },
                "error": null
            });
            let response_str = serde_json::to_string(&configure_response).unwrap();
            if let Err(e) = writer.write_all(response_str.as_bytes()).await {
                println!(
                    "Error writing configure response to miner {}: {:?}",
                    miner_id, e
                );
                return;
            }
            if let Err(e) = writer.write_all(b"\n").await {
                println!("Error writing newline to miner {}: {:?}", miner_id, e);
                return;
            }
            if let Err(e) = writer.flush().await {
                println!("Error flushing writer for miner {}: {:?}", miner_id, e);
                return;
            }
            println!("Response to Miner {}: {}", miner_id, response_str);
            line.clear();
        }
    } else {
        println!("Failed to read configure request from miner {}", miner_id);
        return;
    }

    // Read the miner's subscribe request.
    if let Ok(n) = reader.read_line(&mut line).await {
        if n > 0 {
            println!("Miner {} sent: {}", miner_id, line.trim_end());
            // Wait for upstream parameters.
            let upstream_params = loop {
                let lock = job_params.lock().await;
                if let Some(ref params) = *lock {
                    break params.clone();
                }
                drop(lock);
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            };

            // Build and send the subscribe response.
            let subscribe_response = json!({
                "id": 2,
                "result": [
                    [
                        ["mining.set_difficulty", "1"],
                        ["mining.notify", "1"]
                    ],
                    upstream_params.full_extranonce1.clone() + &constrained_extranonce,
                    upstream_params.extranonce2_size - 2
                ],
                "error": null
            });
            let response_str = serde_json::to_string(&subscribe_response).unwrap();
            if let Err(e) = writer.write_all(response_str.as_bytes()).await {
                println!(
                    "Error writing subscribe response to miner {}: {:?}",
                    miner_id, e
                );
                return;
            }
            if let Err(e) = writer.write_all(b"\n").await {
                println!("Error writing newline to miner {}: {:?}", miner_id, e);
                return;
            }
            if let Err(e) = writer.flush().await {
                println!("Error flushing writer for miner {}: {:?}", miner_id, e);
                return;
            }
            println!("Response to Miner {}: {}", miner_id, response_str);
            line.clear();
        }
    } else {
        println!("Failed to read subscribe request from miner {}", miner_id);
        return;
    }

    // Read the miner's authorize request.
    if let Ok(n) = reader.read_line(&mut line).await {
        if n > 0 {
            println!("Miner {} sent: {}", miner_id, line.trim_end());

            // Build and send the authorize response.
            let authorize_response = json!({
                "id": 3,
                "result": true,
                "error": null
            });
            let response_str = serde_json::to_string(&authorize_response).unwrap();
            if let Err(e) = writer.write_all(response_str.as_bytes()).await {
                println!(
                    "Error writing authorize response to miner {}: {:?}",
                    miner_id, e
                );
                return;
            }
            if let Err(e) = writer.write_all(b"\n").await {
                println!("Error writing newline to miner {}: {:?}", miner_id, e);
                return;
            }
            if let Err(e) = writer.flush().await {
                println!("Error flushing writer for miner {}: {:?}", miner_id, e);
                return;
            }
            println!("Response to Miner {}: {}", miner_id, response_str);
            line.clear();
        }
    } else {
        println!("Failed to read authorize request from miner {}", miner_id);
        return;
    }

    // Immediately send the current mining.notify and mining.set_difficulty (if cached) after authorize.
    let cached_difficulty = {
        let lock = last_difficulty.lock().await;
        lock.clone()
    };
    if let Some(difficulty_msg) = cached_difficulty {
        println!(
            "Sending cached mining.set_difficulty to miner {}: {}",
            miner_id, difficulty_msg
        );
        if let Err(e) = writer.write_all(difficulty_msg.as_bytes()).await {
            println!("Error sending difficulty to miner {}: {:?}", miner_id, e);
        }
        if let Err(e) = writer.write_all(b"\n").await {
            println!("Error writing newline to miner {}: {:?}", miner_id, e);
        }
    }
    let cached_notify = {
        let lock = last_notify.lock().await;
        lock.clone()
    };
    if let Some(notify) = cached_notify {
        println!(
            "Sending cached mining.notify to miner {}: {}",
            miner_id, notify
        );
        if let Err(e) = writer.write_all(notify.as_bytes()).await {
            println!("Error sending notify to miner {}: {:?}", miner_id, e);
        }
        if let Err(e) = writer.write_all(b"\n").await {
            println!("Error writing newline to miner {}: {:?}", miner_id, e);
        }
    }

    // Process job notifications and miner messages concurrently.
    loop {
        tokio::select! {
            Ok(job_msg) = job_rx.recv() => {
                if let Err(e) = writer.write_all(job_msg.as_bytes()).await {
                    println!("Error sending job to miner {}: {:?}", miner_id, e);
                    break;
                }
                if let Err(e) = writer.write_all(b"\n").await {
                    println!("Error writing newline to miner {}: {:?}", miner_id, e);
                    break;
                }
            }
            result = reader.read_line(&mut line) => {
                match result {
                    Ok(0) => {
                        println!("Miner {} disconnected", miner_id);
                        break;
                    }
                    Ok(_) => {
                        println!("Received from miner {}: {}", miner_id, line.trim_end());
                        let upstream_params = {
                            let lock = job_params.lock().await;
                            if let Some(ref params) = *lock {
                                params.clone()
                            } else {
                                println!("No upstream parameters available for miner {}", miner_id);
                                continue;
                            }
                        };
                        // Check if the line is a share submission message
                        if let Ok(value) = serde_json::from_str::<Value>(&line) {
                            if let Some(method) = value.get("method").and_then(|m| m.as_str()) {
                                if method == "mining.submit" {
                                    on_share_submitted(line.trim().to_string());

                                    let transformed_share = transform_share_submission(
                                        &line,
                                        &constrained_extranonce,
                                        &upstream_params.full_extranonce1,
                                        &worker_name
                                    );
                                    if let Err(e) = share_tx.send(transformed_share).await {
                                        println!("Error sending share from miner {} upstream: {:?}", miner_id, e);
                                        break;
                                    }
                                    // Respond to the miner with the submission result.
                                    if let Some(id) = value.get("id") {
                                        let submission_response = json!({
                                            "id": id,
                                            "result": true,
                                            "error": null
                                        });
                                        let response_str = serde_json::to_string(&submission_response).unwrap();
                                        if let Err(e) = writer.write_all(response_str.as_bytes()).await {
                                            println!("Error writing submission response to miner {}: {:?}", miner_id, e);
                                            break;
                                        }
                                        if let Err(e) = writer.write_all(b"\n").await {
                                            println!("Error writing newline to miner {}: {:?}", miner_id, e);
                                            break;
                                        }
                                        if let Err(e) = writer.flush().await {
                                            println!("Error flushing writer for miner {}: {:?}", miner_id, e);
                                            break;
                                        }
                                        println!("Response to Miner {}: {}", miner_id, response_str);
                                    }
                                }
                            }
                        }
                        line.clear();
                    }
                    Err(e) => {
                        println!("Error reading from miner {}: {:?}", miner_id, e);
                        break;
                    }
                }
            }
        }
    }
}

/// Transforms a miner's share submission by replacing the constrained extranonce with the full upstream extranonce.
fn transform_share_submission(
    submission: &str,
    constrained_extranonce: &str,
    _full_extranonce: &str,
    worker_name: &str,
) -> String {
    if let Ok(mut value) = serde_json::from_str::<Value>(submission) {
        if let Some(method) = value.get("method").and_then(|m| m.as_str()) {
            if method == "mining.submit" {
                if let Some(params) = value.get_mut("params").and_then(|p| p.as_array_mut()) {
                    if params.len() >= 2 {
                        params[0] = Value::String(worker_name.to_string());
                        if let Some(extranonce_2) = params.get(2).and_then(|v| v.as_str()) {
                            params[2] =
                                Value::String(constrained_extranonce.to_string() + extranonce_2);
                        }
                    }
                }
            }
        }
        serde_json::to_string(&value).unwrap_or_else(|_| submission.to_string())
    } else {
        submission.to_string()
    }
}

// ------------ SV2 ------------
pub type Message = MiningDeviceMessages<'static>;
pub type StdFrame = StandardSv2Frame<Message>;
pub type EitherFrame = StandardEitherFrame<Message>;

async fn handle_miner_sv2(
    socket: TcpStream,
    mut _job_rx: broadcast::Receiver<String>,
    share_tx: mpsc::Sender<String>,
    _job_params: SharedJobParams,
    last_notify: SharedLastNotify,
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
    _id: u32,
    receiver: Receiver<EitherFrame>,
    _sender: mpsc::Sender<String>,
}

impl DownstreamMiningNode {
    pub fn new(receiver: Receiver<EitherFrame>, _sender: mpsc::Sender<String>, _id: u32) -> Self {
        Self {
            _id,
            receiver,
            _sender,
        }
    }
}
