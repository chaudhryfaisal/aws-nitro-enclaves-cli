// Copyright 2019-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

#[allow(unused_imports, dead_code)]
#[cfg(test)]
mod tests {
    use nitro_cli::common::commands_parser::{
        BuildEnclavesArgs, RunEnclavesArgs, SignEifArgs, TerminateEnclavesArgs,
    };
    use nitro_cli::common::json_output::EnclaveDescribeInfo;
    use nitro_cli::enclave_proc::commands::{describe_enclaves, run_enclaves, terminate_enclaves};
    use nitro_cli::enclave_proc::resource_manager::NE_ENCLAVE_DEBUG_MODE;
    use nitro_cli::enclave_proc::utils::{
        flags_to_string, generate_enclave_id, get_enclave_describe_info,
    };
    use nitro_cli::utils::{Console, PcrType};
    use nitro_cli::{
        build_enclaves, build_from_docker, describe_eif, enclave_console, get_file_pcr,
        new_enclave_name, sign_eif,
    };
    use nitro_cli::{CID_TO_CONSOLE_PORT_OFFSET, VMADDR_CID_HYPERVISOR};
    use serde_json::json;
    use std::convert::TryInto;
    use std::io::Write;
    use tempfile::{tempdir, TempDir};

    use aws_nitro_enclaves_cose::crypto::http::HttpSigningKey;
    use aws_nitro_enclaves_cose::crypto::Openssl;
    use aws_nitro_enclaves_cose::CoseSign1;
    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::{X509Name, X509};

    // Remote Docker image
    const SAMPLE_DOCKER: &str = "public.ecr.aws/aws-nitro-enclaves/hello:v1";
    pub const MAX_BOOT_TIMEOUT_SEC: u64 = 3;

    use actix_web::dev::ServerHandle;
    use actix_web::rt::task::JoinHandle;
    use actix_web::{web, App, HttpResponse, HttpServer};
    use aws_nitro_enclaves_cose::crypto::SigningPublicKey;
    use aws_nitro_enclaves_cose::error::CoseError;
    use aws_nitro_enclaves_cose::header_map::HeaderMap;
    use base64::engine::general_purpose;
    use base64::Engine;
    use log::{error, info, warn};
    use openssl::ecdsa::EcdsaSig;
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
    use std::convert::TryFrom;
    use std::fs;
    use std::fs::File;
    use std::io::Read;
    use std::sync::mpsc::Receiver;
    use std::sync::Arc;
    use std::time::Duration;

    fn setup_env() {
        if std::env::var("NITRO_CLI_BLOBS").is_err() {
            std::env::set_var("NITRO_CLI_BLOBS", "/usr/share/nitro_enclaves/blobs");
        }
        // Ensure tests run without picking up a network proxy (which causes reqwest to fail)
        for var in &[
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            std::env::remove_var(var);
        }
    }

    pub const SERVER_CERT: &str = "../dcaas-mock-backend-apis/certs/ecdsa/384/server.pem";
    pub const SERVER_KEY: &str = "../dcaas-mock-backend-apis/certs/ecdsa/384/server-pkcs8-key.pem";
    pub const CA_CERT: &str = "../dcaas-mock-backend-apis/certs/ecdsa/384/root-ca.pem";
    pub const SERVER_ADDR: &str = "127.0.0.1:9095";

    #[test]
    fn key_http_sign_verify_local_key_cose() {
        std::env::set_var("RUST_LOG", "trace");

        let private_key = format!(
            "https://{}/v2/core/sign/ecdsa-sha384;algorithm=ES384;ca={}",
            SERVER_ADDR, CA_CERT
        );
        let (receiver, srv_thread) = setup_server().expect("Failed to start test server");
        setup_env();

        let payload: [u8; 48] = [
            42, 24, 37, 97, 171, 250, 172, 219, 37, 215, 152, 47, 101, 223, 49, 28, 17, 246, 42, 7,
            66, 10, 162, 186, 9, 164, 3, 193, 208, 254, 125, 10, 103, 97, 40, 97, 104, 142, 211,
            78, 252, 167, 27, 200, 39, 171, 152, 59,
        ];
        let mut key_data = Vec::new();
        let mut key_file = File::open(SERVER_KEY).unwrap();
        key_file.read_to_end(&mut key_data).unwrap();
        let local_signing_key = PKey::private_key_from_pem(&key_data).unwrap();
        let local_cose_sign =
            CoseSign1::new::<Openssl>(&payload, &HeaderMap::new(), &local_signing_key)
                .map_err(|e| format!("Failed to create CoseSign1 with HTTP key: {}", e))
                .unwrap();

        let local_signature = local_cose_sign
            .as_bytes(false)
            .map_err(|e| format!("Failed to get signature bytes: {}", e))
            .unwrap();
        println!(
            "local_signature: {} -> {:x?}",
            local_signature.len(),
            local_signature
        );

        let http_signing_key = HttpSigningKey::new(private_key.as_str()).unwrap();
        let http_cose_sign =
            CoseSign1::new::<Openssl>(&payload, &HeaderMap::new(), &http_signing_key).unwrap();

        let http_signature = http_cose_sign.as_bytes(false).unwrap();
        println!(
            "http_signature: {} -> {:x?}",
            http_signature.len(),
            http_signature
        );

        assert!(local_cose_sign
            .verify_signature::<Openssl>(&local_signing_key)
            .expect("Failed to verify local_signature"));
        assert!(http_cose_sign
            .verify_signature::<Openssl>(&local_signing_key)
            .expect("Failed to verify http_signature"));

        stop_server(receiver, srv_thread).expect("Failed to stop test server");
    }

    #[test]
    fn local_key_build_sign_describe_simple_eif() {
        std::env::set_var("RUST_LOG", "trace");
        let dir = tempdir().unwrap();
        let dir_path = dir.path().to_str().unwrap();
        let eif_path = format!("{dir_path}/test.eif");

        let private_key = SERVER_KEY.to_string();
        let args = BuildEnclavesArgs {
            docker_uri: SAMPLE_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path,
            signing_certificate: Some(SERVER_CERT.to_string()),
            private_key: Some(private_key),
            img_name: None,
            img_version: None,
            metadata: None,
        };

        build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
            &args.img_name,
            &args.img_version,
            &args.metadata,
        )
        .expect("Docker build failed");

        let eif_info = describe_eif(args.output.clone()).unwrap();

        assert_eq!(eif_info.version, 4);
        assert!(eif_info.is_signed);
        assert!(eif_info.cert_info.is_some());
        assert!(eif_info.crc_check);
        assert!(eif_info.sign_check.is_some());
    }

    #[test]
    fn local_key_build_run_describe_terminate_simple_eif_image() {
        std::env::set_var("RUST_LOG", "trace");
        let dir = tempdir().unwrap();
        let dir_path = dir.path().to_str().unwrap();
        let eif_path = format!("{dir_path}/test.eif");

        let private_key = SERVER_KEY.to_string();
        let build_args = BuildEnclavesArgs {
            docker_uri: SAMPLE_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path,
            signing_certificate: Some(SERVER_CERT.to_string()),
            private_key: Some(private_key),
            img_name: None,
            img_version: None,
            metadata: None,
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
            &build_args.signing_certificate,
            &build_args.private_key,
            &build_args.img_name,
            &build_args.img_version,
            &build_args.metadata,
        )
        .expect("Docker build failed");

        let run_args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 1024,
            debug_mode: true,
            attach_console: false,
            enclave_name: Some("testName".to_string()),
        };

        run_describe_terminate(run_args);
    }

    #[test]
    fn key_http_build_run_describe_terminate_simple_eif_image() {
        std::env::set_var("RUST_LOG", "trace");
        let dir = tempdir().unwrap();
        let dir_path = dir.path().to_str().unwrap();

        let (receiver, srv_thread) = setup_server().expect("Failed to start test server");
        setup_env();
        for pre_digest in vec!["true", "false"] {
            let private_key = format!(
                "https://{}/v2/core/sign/ecdsa-sha384?pre_digest={pre_digest};algorithm=ES384;ca={};pre_digest={pre_digest}",
                SERVER_ADDR, CA_CERT
            );
            let eif_path = format!("{dir_path}/test.eif");
            let build_args = BuildEnclavesArgs {
                docker_uri: SAMPLE_DOCKER.to_string(),
                docker_dir: None,
                output: eif_path,
                signing_certificate: Some(SERVER_CERT.to_string()),
                private_key: Some(private_key),
                img_name: None,
                img_version: None,
                metadata: None,
            };

            build_from_docker(
                &build_args.docker_uri,
                &build_args.docker_dir,
                &build_args.output,
                &build_args.signing_certificate,
                &build_args.private_key,
                &build_args.img_name,
                &build_args.img_version,
                &build_args.metadata,
            )
            .expect("Docker build failed");

            let eif_info = describe_eif(build_args.output.clone()).unwrap();

            assert_eq!(eif_info.version, 4);
            assert!(eif_info.is_signed);
            assert!(eif_info.cert_info.is_some());
            assert!(eif_info.crc_check);
            assert!(eif_info.sign_check.is_some());

            let run_args = RunEnclavesArgs {
                enclave_cid: None,
                eif_path: build_args.output,
                cpu_ids: None,
                cpu_count: Some(2),
                memory_mib: 1024,
                debug_mode: true,
                attach_console: false,
                enclave_name: Some("testName".to_string()),
            };

            run_describe_terminate(run_args);
        }
        stop_server(receiver, srv_thread).expect("Failed to stop test server");
    }

    #[test]
    fn key_http_build_sign_describe_simple_eif() {
        std::env::set_var("RUST_LOG", "trace");
        let dir = tempdir().unwrap();
        let dir_path = dir.path().to_str().unwrap();

        let (receiver, srv_thread) = setup_server().expect("Failed to start test server");
        setup_env();
        for pre_digest in vec!["true", "false"] {
            let private_key = format!(
                "https://{}/v2/core/sign/ecdsa-sha384?pre_digest={pre_digest};algorithm=ES384;ca={};pre_digest={pre_digest}",
                SERVER_ADDR, CA_CERT
            );
            let eif_path = format!("{dir_path}/test.eif");
            let args = BuildEnclavesArgs {
                docker_uri: SAMPLE_DOCKER.to_string(),
                docker_dir: None,
                output: eif_path,
                signing_certificate: Some(SERVER_CERT.to_string()),
                private_key: Some(private_key),
                img_name: None,
                img_version: None,
                metadata: None,
            };

            build_from_docker(
                &args.docker_uri,
                &args.docker_dir,
                &args.output,
                &args.signing_certificate,
                &args.private_key,
                &args.img_name,
                &args.img_version,
                &args.metadata,
            )
            .expect("Docker build failed");

            let eif_info = describe_eif(args.output.clone()).unwrap();

            assert_eq!(eif_info.version, 4);
            assert!(eif_info.is_signed);
            assert!(eif_info.cert_info.is_some());
            assert!(eif_info.crc_check);
            assert!(eif_info.sign_check.is_some());
        }

        stop_server(receiver, srv_thread).expect("Failed to stop test server");
    }

    fn run_describe_terminate(args: RunEnclavesArgs) {
        setup_env();
        let req_enclave_cid = args.enclave_cid;
        let req_mem_size = args.memory_mib;
        let req_nr_cpus: u64 = args.cpu_count.unwrap().into();
        let debug_mode = args.debug_mode;
        let mut enclave_manager = run_enclaves(&args, None)
            .expect("Run enclaves failed")
            .enclave_manager;
        let enclave_cid = enclave_manager.get_console_resources_enclave_cid().unwrap();
        let enclave_flags = enclave_manager
            .get_console_resources_enclave_flags()
            .unwrap();
        if let Some(req_enclave_cid) = req_enclave_cid {
            assert_eq!(req_enclave_cid, enclave_cid);
        }

        if debug_mode {
            assert_eq!(enclave_flags & NE_ENCLAVE_DEBUG_MODE, NE_ENCLAVE_DEBUG_MODE);
        } else {
            assert_eq!(enclave_flags & NE_ENCLAVE_DEBUG_MODE, 0);
        }

        let cid_copy = enclave_cid;

        let console = Console::new_nonblocking(
            VMADDR_CID_HYPERVISOR,
            u32::try_from(cid_copy).unwrap() + CID_TO_CONSOLE_PORT_OFFSET,
        )
        .expect("Failed to connect to the console");
        let mut buffer: Vec<u8> = Vec::new();
        let duration: Duration = Duration::from_secs(MAX_BOOT_TIMEOUT_SEC);
        console
            .read_to_buffer(&mut buffer, duration)
            .expect("Failed to check that the enclave booted");

        let contents = String::from_utf8(buffer).unwrap();
        let boot = contents.contains("nsm: loading out-of-tree module");

        assert!(boot);

        let info = get_enclave_describe_info(&enclave_manager, false).unwrap();
        let replies: Vec<EnclaveDescribeInfo> = vec![info];
        let reply = &replies[0];
        let flags = &reply.flags;

        assert_eq!({ reply.enclave_cid }, enclave_cid);
        assert_eq!(reply.memory_mib, req_mem_size);
        assert_eq!({ reply.cpu_count }, req_nr_cpus);
        assert_eq!(reply.state, "RUNNING");
        if debug_mode {
            assert_eq!(flags, "DEBUG_MODE");
        } else {
            assert_eq!(flags, "NONE");
        }
        let _enclave_id = generate_enclave_id(0).expect("Describe enclaves failed");

        terminate_enclaves(&mut enclave_manager, None).expect("Terminate enclaves failed");

        let info = get_enclave_describe_info(&enclave_manager, false).unwrap();

        assert_eq!(info.enclave_cid, 0);
        assert_eq!(info.cpu_count, 0);
        assert_eq!(info.memory_mib, 0);
    }

    fn stop_server(
        rx: Receiver<ServerHandle>,
        srv_thread: std::thread::JoinHandle<()>,
    ) -> anyhow::Result<()> {
        // Give server a moment then request it stop and join the thread.
        std::thread::sleep(Duration::from_millis(200));

        // Receive the ServerHandle using a blocking call executed on a blocking thread so
        // we don't block the Tokio async runtime.
        let recv_res = std::thread::spawn({
            let rx = rx;
            move || rx.recv_timeout(Duration::from_secs(1))
        })
        .join()
        .map_err(|e| anyhow::anyhow!("failed to receive server handle: {:?}", e))?;

        // recv_res is Result<ServerHandle, RecvTimeoutError>
        if let Ok(handle) = recv_res {
            // Request server stop by running the stop future on a new thread's actix System
            // so we don't depend on the test's runtime.
            let handle_for_stop = handle;
            std::thread::spawn(move || {
                let sys = actix_web::rt::System::new();
                // block_on the stop future to request a graceful shutdown
                let _ = sys.block_on(handle_for_stop.stop(true));
            })
            .join()
            .ok();
        }

        // Join the server thread so the test waits for the server thread to exit.
        if let Err(e) = srv_thread.join() {
            return Err(anyhow::anyhow!("failed to join server thread: {:?}", e));
        }
        Ok(())
    }

    #[derive(serde::Deserialize)]
    struct SignBody {
        message: String,
    }

    #[derive(serde::Deserialize)]
    struct SignQuery {
        #[serde(default = "default_true")]
        pre_digest: bool,
    }

    fn default_true() -> bool {
        true
    }

    fn setup_server() -> anyhow::Result<(Receiver<ServerHandle>, std::thread::JoinHandle<()>)> {
        let signing_key_path = SERVER_KEY;

        // Load key bytes for handler to sign with
        let key_bytes = fs::read(signing_key_path)?;
        let key_bytes_arc = Arc::new(key_bytes);

        // Build OpenSSL acceptor (SslAcceptorBuilder)
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        builder.set_private_key_file(SERVER_KEY, SslFiletype::PEM)?;
        builder.set_certificate_chain_file(SERVER_CERT)?;

        let key_data_for_srv = key_bytes_arc.clone();
        // Run the Actix server on a dedicated thread to avoid dropping a runtime inside Tokio's async context.
        // Send a ServerHandle so the test can request a graceful stop later.
        let (tx, rx) = std::sync::mpsc::channel::<actix_web::dev::ServerHandle>();
        // Run the Actix server on a dedicated thread so it has its own Tokio/reactor
        // and does not interfere with the test's runtime.
        let data_clone = key_data_for_srv.clone();
        let srv_thread = std::thread::spawn(move || {
            let srv_addr = SERVER_ADDR.to_string();
            let data_clone = data_clone;
            let app = move || {
                let bytes = data_clone.clone();
                App::new().route(
                    "/v2/core/sign/ecdsa-sha384",
                    actix_web::web::post().to(move |query: web::Query<SignQuery>,
                                                    body: web::Json<SignBody>| {
                        let key_len = 48; // P-384 => 48 bytes
                        let key_bytes = bytes.clone();
                        async move {
                            let pre_digest = query.pre_digest;
                            let message_b64 = &body.message;
                            let payload = match general_purpose::STANDARD.decode(message_b64) {
                                Ok(p) => p,
                                Err(e) => {
                                    error!("base64 decode failed: {:?}", e);
                                    return HttpResponse::BadRequest().body("invalid base64");
                                }
                            };

                            let pkey = match PKey::private_key_from_pem(&key_bytes) {
                                Ok(k) => k,
                                Err(e) => {
                                    error!("failed parse pkey: {:?}", e);
                                    return HttpResponse::InternalServerError().body("key parse");
                                }
                            };

                            let ec_key = match pkey.ec_key() {
                                Ok(k) => k,
                                Err(e) => {
                                    error!("failed to extract ec_key: {:?}", e);
                                    return HttpResponse::InternalServerError().body("key parse");
                                }
                            };

                            eprintln!(
                                "sign/ecdsa-sha384 pre_digest={pre_digest} payload={}->{:?}",
                                payload.len(),
                                payload
                            );

                            let payload = match pre_digest {
                                true => {
                                    payload
                                }
                                false => {
                                    let md = MessageDigest::sha384();
                                    let digest = match openssl::hash::hash(md, payload.as_slice()) {
                                        Ok(d) => d,
                                        Err(e) => { panic!("Failed to compute digest for signing: {:?}", e); }
                                    };
                                    let payload = digest.as_ref().to_vec();
                                    eprintln!(
                                        "sign/ecdsa-sha384 pre_digest={pre_digest} payload={}->{:?}",
                                        payload.len(),
                                        payload
                                    );
                                    payload
                                }
                            };

                            let ecdsa_sig = match EcdsaSig::sign(&payload, &ec_key) {
                                Ok(s) => s,
                                Err(e) => {
                                    error!("ecdsa sign error: {:?}", e);
                                    return HttpResponse::InternalServerError().body("sign");
                                }
                            };
                            let raw_sig = convert_to_raw_sig(ecdsa_sig, key_len);
                            let sig_b64 = general_purpose::STANDARD.encode(raw_sig);
                            let resp = json!({ "signature": sig_b64 });
                            HttpResponse::Ok().json(resp)
                        }
                    }),
                )
            };

            let server = HttpServer::new(app)
                .bind_openssl(srv_addr.clone(), builder)
                .expect("failed to bind")
                .run();

            // Send the Server handle back so the creator can stop it later.
            let _ = tx.send(server.handle());

            // Run the actix system on this thread.
            let sys = actix_web::rt::System::new();
            if let Err(e) = sys.block_on(server) {
                error!("server error: {:?}", e);
            }
        });

        // Give server a brief moment to start
        std::thread::sleep(Duration::from_millis(300));
        Ok((rx, srv_thread))
    }

    fn convert_to_raw_sig(ecdsa_sig: EcdsaSig, key_len: usize) -> Vec<u8> {
        let r = ecdsa_sig.r().to_vec();
        let s = ecdsa_sig.s().to_vec();
        let mut raw_sig = vec![0u8; key_len * 2];
        let r_off = key_len.saturating_sub(r.len());
        raw_sig[r_off..r_off + r.len()].copy_from_slice(&r);
        let s_off = key_len + key_len.saturating_sub(s.len());
        raw_sig[s_off..s_off + s.len()].copy_from_slice(&s);
        raw_sig
    }
}
