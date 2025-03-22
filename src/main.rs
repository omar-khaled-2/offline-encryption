use clap::{Parser, Subcommand};
use rand::Rng;
use std::{fs::File, io::{Read, Write}, path::Path};

use aes::Aes128;

use p12_keystore::{KeyStore,KeyStoreEntry, PrivateKeyChain,Certificate};
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::io::{BufReader, BufWriter};
use base64::prelude::*;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use sha2::{Sha256, Digest};
// use zeroize::Zeroize;

type AesCtr = Ctr128BE<Aes128>;

#[derive(Serialize, Deserialize)]
struct VideoMetadata {
    filename: String,           
    collection_id: String,    
    // duration: u64,         
    // format: String,             
    // resolution: (u32, u32),   
    // iv: [u8;16],         
    // created_at: u64
}

#[derive(Parser)]
#[command(name = "VideoCLI", version = "1.0", about = "Encrypt and secure video files")]
struct VideoCLI {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    GenerateCertificate {
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        output: String,
    },
    GenerateAccessKey {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        certificate: String,
        #[arg(short, long)]
        password: String,
    },
    EncryptVideo {
        #[arg(short, long)]
        certificate: String,
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        video: String,
        #[arg(short, long)]
        output: String,
    },
}


fn generate_aes_key() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let key: [u8; 16] = rng.gen();
    key
}



fn generate_certificate(password: &str, output: &str) {
    let key = generate_aes_key();




    let collection_id = Uuid::new_v4();

    
    let subject_alt_names = vec!["hello.world.example".to_string(),
	"localhost".to_string()];

    let CertifiedKey { cert, .. } = generate_simple_self_signed(subject_alt_names).unwrap();


    let cert = Certificate::from_der(&cert.der()).unwrap();
    
    let mut keystore = KeyStore::new();

    
    let private_key_chain: PrivateKeyChain = PrivateKeyChain::new(key,Uuid::new_v4().as_bytes().to_vec(),vec![cert]);

    let entry = KeyStoreEntry::PrivateKeyChain(private_key_chain);


    keystore.add_entry(&collection_id.to_string(), entry);


   
 

    let writer = keystore.writer(password);

    let pkcs_12 = writer.write().unwrap();

    let mut file = File::create(output).unwrap();
    file.write(&pkcs_12).unwrap();


        



}


fn load_aes_key_from_p12(path: &str, password: &str) -> (String, [u8;16]) {
    let mut certificate_file = File::open(path).unwrap();

    let mut pkcs12_data = vec![];
    let _ =certificate_file.read_to_end(& mut pkcs12_data);

    let keystore = KeyStore::from_pkcs12(&pkcs12_data, password).expect("Password is invalid");

    let entry = keystore.entries().next().unwrap();


    let collection_id = entry.0.to_string();

    let KeyStoreEntry::PrivateKeyChain(keystore) = entry.1 else { panic!("Unexpected variant!") };
    let key:[u8;16] = keystore.key().try_into().unwrap();


    (collection_id, key)
}

fn load_public_key(base64_key: &str) -> RsaPublicKey {
    let key_bytes = BASE64_STANDARD.decode(base64_key).unwrap();
    print!("{}",key_bytes.len());


    let key = RsaPublicKey::from_public_key_der(&key_bytes).unwrap();
    key
}


fn generate_access_key(public_key: &str, certificate: &str, password: &str) -> String {
    let (_, aes_key) = load_aes_key_from_p12(certificate, password);
    let rsa_key = load_public_key(public_key);
    let mut rng = rand::thread_rng(); 
    let encrypted_key: Vec<u8> = rsa_key.encrypt(&mut rng, Pkcs1v15Encrypt, &aes_key).unwrap();
    BASE64_STANDARD.encode(encrypted_key)
}

const BUFFER_SIZE: usize = 1 * 1024 * 1024; 
fn encrypt_video(video: &str, certificate: &str, password: &str, output: &str) {

    let (collection_id,key) = load_aes_key_from_p12(certificate, password);
    let iv = [0u8; 16];
    let mut cipher = AesCtr::new(&key.into(), &iv.into());


    let video_path = Path::new(video);
    
    let video_file = File::open(video_path).expect("Failed to open input file");
    let output_file = File::create(output).expect("Failed to create output file");

    let file_metadata = std::fs::metadata(video_path).unwrap();
    let file_size = file_metadata.len(); 

    let file_name = video_path.file_name()
    .expect("No file name found")
    .to_str()
    .expect("Invalid UTF-8 in file name")
    .to_string();

    let metadata = VideoMetadata { filename: file_name, collection_id };

    let metadata_json = serde_json::to_string(&metadata).unwrap();
    let mut reader = BufReader::new(video_file);
    let mut writer = BufWriter::new(output_file);

    let metadata_size = metadata_json.len();

    writer.write_all(b"EVMP").unwrap();
    writer.write_all(&[1, 0]).unwrap();
    writer.write_all(&(file_size as u32).to_le_bytes()).unwrap();
    writer.write_all(&(metadata_size as u32).to_le_bytes()).unwrap();
    let mut buffer = [0u8; BUFFER_SIZE];
    while let Ok(bytes_read) = reader.read(&mut buffer) {
        if bytes_read == 0 {
            break;
        }
        cipher.apply_keystream(&mut buffer[..bytes_read]); 
        writer.write_all(&buffer[..bytes_read]).expect("Failed to write to file");
    }





    writer.write_all(metadata_json.as_bytes()).unwrap();

    let mut hasher = Sha256::new();

    hasher.update(key);
    let hash_key = hasher.finalize();

    writer.write_all(&hash_key).unwrap();



}


fn main() {

    let cli = VideoCLI::parse();

    match cli.command {
        Commands::GenerateCertificate { password, output } => {
            generate_certificate(&password, &output);
            println!("Certificate generated successfully.");
        }
        Commands::GenerateAccessKey { key, certificate, password } => {
            let access_key = generate_access_key(&key, &certificate, &password);
            
            println!("\n\n{}", access_key);
        }
        Commands::EncryptVideo { certificate, password, video, output } => {
            encrypt_video(&video, &certificate, &password, &output);
            println!("Video encrypted successfully.");
        }
    }
}