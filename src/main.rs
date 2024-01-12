use std::collections::HashMap;
use std::{fs, io};

use hex;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, EcPointRef, PointConversionForm};
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{Private, Public};
use openssl::symm::{decrypt, encrypt, Cipher};

use lazy_static::lazy_static;
use std::io::{stdin, Write};
use std::sync::Mutex;

lazy_static! {
    static ref GLOBAL_TRANSACTIONS: Mutex<Vec<Pass2HeavenTransactionInfo>> = Mutex::new(Vec::new());
}
lazy_static! {
    static ref GLOBAL_CONTAINERS: Mutex<HashMap<String, Vec<u8>>> = Mutex::new(HashMap::new());
}
struct Container {}

impl Container {
    pub fn decrypt_bytes(bytes: &[u8], cipher: Cipher, key: &[u8; 16]) -> Vec<u8> {
        decrypt(cipher, key, None, &bytes).unwrap()
    }

    pub fn encrypt_bytes(bytes: &[u8], cipher: Cipher, key: &[u8; 16]) -> Vec<u8> {
        encrypt(cipher, key, None, bytes).unwrap()
    }

    const OPAD: [u8; 16] = [
        35, 213, 199, 175, 113, 235, 196, 210, 32, 160, 214, 225, 92, 143, 179, 181,
    ];
    const IPAD: [u8; 16] = [
        155, 77, 19, 182, 62, 253, 112, 61, 63, 42, 206, 116, 47, 13, 136, 201,
    ];
    pub fn calc_mac_codes(bytes: &[u8], key: &[u8; 16]) -> String {
        let mut key_xor_opad = [0; 16];
        let mut key_xor_ipad = [0; 16];
        for i in 0..16 {
            key_xor_opad[i] = key[i] ^ Self::OPAD[i];
            key_xor_ipad[i] = key[i] ^ Self::IPAD[i];
        }

        let hash_key_xor_ipad = hash(MessageDigest::sha3_256(), &key_xor_ipad)
            .unwrap()
            .to_vec();

        let mut key_xor_opad_hash_key_xor_ipad_m = key_xor_opad.to_vec();
        key_xor_opad_hash_key_xor_ipad_m.extend(hash_key_xor_ipad.iter());
        key_xor_opad_hash_key_xor_ipad_m.extend_from_slice(bytes);

        hex::encode(
            hash(MessageDigest::sha3_256(), &key_xor_opad_hash_key_xor_ipad_m)
                .unwrap()
                .to_vec(),
        )
    }
}

pub struct Pass2HeavenTransactionInfo {
    sender_public_key: String,
    R: String,
    stealth: String,
    container_id: String,
    mac_codes: String,
}

pub fn is_mine(my_private_key: &EcKey<Private>, transaction: &Pass2HeavenTransactionInfo) -> bool {
    let mut P1 = EcPoint::new(&EcGroup::from_curve_name(Nid::SECP256K1).unwrap()).unwrap();

    let mut ctx = BigNumContext::new().unwrap();
    P1.mul(
        &EcGroup::from_curve_name(Nid::SECP256K1).unwrap(),
        string_to_public_key(&transaction.R).as_ref(),
        &my_private_key.private_key(),
        &ctx,
    )
    .unwrap();

    hex::decode(&transaction.stealth).unwrap()
        == hash(
            MessageDigest::sha3_256(),
            &P1.to_bytes(
                &EcGroup::from_curve_name(Nid::SECP256K1).unwrap(),
                PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .unwrap(),
        )
        .unwrap()
        .to_vec()
}

pub fn key_from_public_key(public_key: &EcPoint) -> [u8; 16] {
    let mut ctx = BigNumContext::new().unwrap();

    let bytes = public_key
        .to_bytes(
            &EcGroup::from_curve_name(Nid::SECP256K1).unwrap(),
            PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .unwrap();

    let mut key = [0; 16];

    for i in 0..64 {
        key[i % 16] ^= bytes[i + 1];
    }

    key
}

pub fn send(data: &[u8], sender_private_key: &EcKey<Private>, receiver_public_key: &EcKey<Public>) {
    let mut ctx = BigNumContext::new().unwrap();

    let r = EcKey::generate(&EcGroup::from_curve_name(Nid::SECP256K1).unwrap()).unwrap();
    let R = r
        .public_key()
        .to_owned(&EcGroup::from_curve_name(Nid::SECP256K1).unwrap())
        .unwrap();

    let mut r_times_receiver_public_key =
        EcPoint::new(&EcGroup::from_curve_name(Nid::SECP256K1).unwrap()).unwrap();
    r_times_receiver_public_key
        .mul(
            &EcGroup::from_curve_name(Nid::SECP256K1).unwrap(),
            receiver_public_key.public_key(),
            r.private_key(),
            &ctx,
        )
        .unwrap();

    let stealth = hash(
        MessageDigest::sha3_256(),
        &r_times_receiver_public_key
            .to_bytes(
                &EcGroup::from_curve_name(Nid::SECP256K1).unwrap(),
                PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .unwrap(),
    )
    .unwrap()
    .to_vec();

    let mut sender_private_key_times_receiver_public_key =
        EcPoint::new(&EcGroup::from_curve_name(Nid::SECP256K1).unwrap()).unwrap();
    sender_private_key_times_receiver_public_key
        .mul(
            &EcGroup::from_curve_name(Nid::SECP256K1).unwrap(),
            receiver_public_key.public_key(),
            sender_private_key.private_key(),
            &ctx,
        )
        .unwrap();

    let cipher_key = key_from_public_key(&sender_private_key_times_receiver_public_key);
    let encrypted_data = Container::encrypt_bytes(data, Cipher::aes_128_cbc(), &cipher_key);

    let container_id = transferring_container(&encrypted_data);

    println!("Container send. ID: {:?}", container_id);

    let sender_public_key = sender_private_key
        .public_key()
        .to_owned(&EcGroup::from_curve_name(Nid::SECP256K1).unwrap())
        .unwrap();

    let tx_info = Pass2HeavenTransactionInfo {
        sender_public_key: public_key_to_string(&sender_public_key),
        R: public_key_to_string(&R),
        stealth: hex::encode(&stealth),
        container_id,
        mac_codes: Container::calc_mac_codes(&data, &cipher_key),
    };

    sending_transaction(tx_info);

    println!("Transaction send");
}

fn sending_transaction(info: Pass2HeavenTransactionInfo) {
    let mut transactions = GLOBAL_TRANSACTIONS.lock().unwrap();

    transactions.push(info);
}

fn transferring_container(container: &[u8]) -> String {
    let id = hex::encode(
        hash(MessageDigest::sha3_256(), &container)
            .unwrap()
            .to_vec(),
    );

    let mut containers = GLOBAL_CONTAINERS.lock().unwrap();
    containers.insert(id.clone(), container.to_vec());

    id
}

fn generate_key_pair() -> (EcKey<Private>, EcPoint) {
    let private_key = EcKey::generate(&*EcGroup::from_curve_name(Nid::SECP256K1).unwrap()).unwrap();

    let public_key = private_key
        .public_key()
        .to_owned(&*EcGroup::from_curve_name(Nid::SECP256K1).unwrap())
        .unwrap();

    (private_key, public_key)
}

fn main() {
    loop {
        println!("e - exit");
        println!("k - generate new key pair");
        println!("s - send file");
        println!("f - find file");

        let command = read_string();

        if command == "e" {
            break;
        } else if command == "k" {
            generate_new_key_pair_command();
        } else if command == "s" {
            send_file_command();
        } else if command == "f" {
            find_files_command();
        }
    }
}

fn find_files_command() {
    println!("Enter private key: ");
    let private_key = read_string();
    let private_key_num = BigNum::from_hex_str(&private_key).unwrap();

    let mut ctx = BigNumContext::new().unwrap();
    let mut public_key = EcPoint::new(&EcGroup::from_curve_name(Nid::SECP256K1).unwrap()).unwrap();
    public_key
        .mul_generator(
            &EcGroup::from_curve_name(Nid::SECP256K1).unwrap(),
            &private_key_num,
            &mut ctx,
        )
        .unwrap();
    let private_key = EcKey::from_private_components(
        &EcGroup::from_curve_name(Nid::SECP256K1).unwrap(),
        &private_key_num,
        &public_key,
    )
    .unwrap();

    let mut my_containers: HashMap<String, (String, String)> = HashMap::new();
    let transactions = GLOBAL_TRANSACTIONS.lock().unwrap();
    for transaction in transactions.iter() {
        if is_mine(&private_key, transaction) {
            let sender_public_key_string = transaction.sender_public_key.clone();
            my_containers.insert(
                transaction.container_id.clone(),
                (sender_public_key_string, transaction.mac_codes.clone()),
            );
        }
    }

    println!("Find {} containers", my_containers.len());

    if my_containers.len() != 0 {
        println!("ID:")
    }
    for (container_id, _) in my_containers.iter() {
        println!("{}", container_id);
    }

    loop {
        println!("Choose ID to download or type 'f' to finish");

        let id = read_string();

        if id == "f" {
            break;
        } else {
            let containers = GLOBAL_CONTAINERS.lock().unwrap();

            let encrypted_data = containers.get(&id).unwrap();

            let (sender_public_key_string, mac_codes) = my_containers.get(&id).unwrap();

            let sender_public_key = string_to_public_key(sender_public_key_string);

            let mut receiver_private_key_times_sender_public_key =
                EcPoint::new(&EcGroup::from_curve_name(Nid::SECP256K1).unwrap()).unwrap();
            receiver_private_key_times_sender_public_key
                .mul(
                    &EcGroup::from_curve_name(Nid::SECP256K1).unwrap(),
                    sender_public_key.as_ref(),
                    private_key.private_key(),
                    &ctx,
                )
                .unwrap();

            let cipher_key = key_from_public_key(&receiver_private_key_times_sender_public_key);
            let data = Container::decrypt_bytes(encrypted_data, Cipher::aes_128_cbc(), &cipher_key);

            if Container::calc_mac_codes(&data, &cipher_key) != mac_codes.clone() {
                println!("Wrong MAC codes");
                continue;
            }

            println!("MAC codes are equal");

            let name_len = data[0] as usize;
            let name = String::from_utf8(data[1..(name_len + 1)].to_vec()).unwrap();
            let file_bytes = data[(name_len + 1)..data.len()].to_vec();

            let mut new_name = String::from("receive_");
            new_name.push_str(&name);

            fs::write(new_name.clone(), file_bytes).expect("Cannot write bytes into file");
            io::stdout().flush().unwrap();

            println!("File created with name {}", new_name);
        }
    }
}

fn send_file_command() {
    println!("Enter filename: ");
    let filename = read_string();

    let name_len = Vec::from([filename.len() as u8]);
    let mut name = Vec::from(filename.as_bytes());
    let mut file_bytes = Vec::from(fs::read(filename).unwrap());

    let mut data = name_len;
    data.append(&mut name);
    data.append(&mut file_bytes);

    println!("Enter private key: ");
    let private_key = read_string();
    let private_key_num = BigNum::from_hex_str(&private_key).unwrap();

    let mut ctx = BigNumContext::new().unwrap();
    let mut public_key = EcPoint::new(&EcGroup::from_curve_name(Nid::SECP256K1).unwrap()).unwrap();
    public_key
        .mul_generator(
            &EcGroup::from_curve_name(Nid::SECP256K1).unwrap(),
            &private_key_num,
            &mut ctx,
        )
        .unwrap();
    let private_key = EcKey::from_private_components(
        &EcGroup::from_curve_name(Nid::SECP256K1).unwrap(),
        &private_key_num,
        &public_key,
    )
    .unwrap();

    println!("Enter receiver public key: ");
    let receiver_public_key = read_string();
    let receiver_public_key = string_to_public_key(&receiver_public_key);

    let receiver_public_key = EcKey::from_public_key(
        &EcGroup::from_curve_name(Nid::SECP256K1).unwrap(),
        &receiver_public_key,
    )
    .unwrap();

    send(&data, &private_key, &receiver_public_key);
}

fn generate_new_key_pair_command() {
    let (pr, pu) = generate_key_pair();
    println!("Private key: {}", hex::encode(pr.private_key().to_vec()));
    println!("Public key: {}", public_key_to_string(pu.as_ref()))
}

fn public_key_to_string(public_key: &EcPointRef) -> String {
    let mut ctx: BigNumContext = BigNumContext::new().unwrap();

    hex::encode(
        public_key
            .to_bytes(
                &*EcGroup::from_curve_name(Nid::SECP256K1).unwrap(),
                PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .unwrap(),
    )
}

fn string_to_public_key(public_key: &String) -> EcPoint {
    let mut ctx: BigNumContext = BigNumContext::new().unwrap();

    EcPoint::from_hex_str(
        &EcGroup::from_curve_name(Nid::SECP256K1).unwrap(),
        &public_key,
        &mut ctx,
    )
    .unwrap()
}

fn read_string() -> String {
    let mut s = String::new();
    stdin().read_line(&mut s).unwrap();
    if let Some('\n') = s.chars().next_back() {
        s.pop();
    }
    if let Some('\r') = s.chars().next_back() {
        s.pop();
    }
    s
}
