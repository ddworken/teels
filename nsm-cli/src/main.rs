use serde_bytes::ByteBuf;
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_init as native_nsm_init, nsm_exit, nsm_process_request};
use std::env;

fn nsm_init() -> i32 {
    let nsm_fd = native_nsm_init();

    if nsm_fd == -1 {
        eprintln!("nsm-cli must be run inside Nitro Enclave");
        std::process::exit(1)
    }

    return nsm_fd;
}

fn error_exit(msg: &str, code: i32, nsm_fd: i32) {
    eprintln!("{}", msg);
    nsm_exit(nsm_fd);

    std::process::exit(code);
}

fn attest(public_key: Option<ByteBuf>, user_data: Option<ByteBuf>, nonce: Option<ByteBuf>) {
    let nsm_fd = nsm_init();

    let request = Request::Attestation {
        public_key,
        user_data,
        nonce,
    };

    let response = nsm_process_request(nsm_fd, request);
    
    match response {
        Response::Attestation{document} => {
            print!("{}", base64::encode(document));
        },
        Response::Error(err) => {
            error_exit(format!("{:?}", err).as_str(), 1, nsm_fd);
        },
        _ => {
            error_exit("Something went wrong", 1, nsm_fd);
        }
    }

    nsm_exit(nsm_fd);
}

fn get_byte_buf_from_env(var_name: &str) -> Option<ByteBuf> {
    env::var(var_name)
        .ok()
        .map(|value| ByteBuf::from(value.as_bytes()))
}

fn main() {
    let public_key = get_byte_buf_from_env("NSM_PUBLIC_KEY");
    let user_data = get_byte_buf_from_env("NSM_USER_DATA");
    let nonce = get_byte_buf_from_env("NSM_NONCE");

    attest(public_key, user_data, nonce);
}