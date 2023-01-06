extern crate openssl;
use base64::decode;
use colored::Colorize;
use csv;
use csv::StringRecord;
use openssl::rsa::{Padding, Rsa};
use serde_json::json;
use std::env;
use std::fs;
use std::io;
use wasm_bindgen::prelude::*;
// use std::process;

fn main() {
    println!("{}", format!("Enter private key path").red());
    let private_key_path = &read_input();

    println!("{} {}", format!("In file ").yellow(), private_key_path);
    match read_file(private_key_path) {
        Ok(private_key) => {
            println!("{}", format!("Enter encrypted data file path").red());
            let encrypted_file_path = &read_input();
            let csv_file =
                read_file(encrypted_file_path).expect("Unable to read encryted Key file");
            let mut updated_vector: Vec<String> = Vec::new();
            let v: Vec<StringRecord> = read_csv(csv_file).expect("Unable to parse csv file");
            for record in v {
                match decode(record[1].to_string()) {
                    Ok(data) => {
                        let json_obj = json!({
                            "merchant_id": record[0].to_string(),
                            "api_key":  decrypt(&private_key, &data, "dummy").expect("Error in decrypting").trim_end_matches(char::from(0))
                        });
                        updated_vector.push(json_obj.to_string());
                    }
                    Err(_) => {
                        let json_obj = json!({
                            "merchant_id": record[0].to_string(),
                            "apiKey": "Error in decoding data"
                        });
                        updated_vector.push(json_obj.to_string());
                    }
                }
            }
            write_to_file(updated_vector).expect("Error in writing to file")
        }
        Err(_) => {
            println!("{}", "Error in parsing Private key file");
            return ();
        }
    }
    return ();
}

fn read_input() -> String {
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("error: unable to read user input");
    return input;
}

fn read_file(filepath: &String) -> Result<String, io::Error> {
    return fs::read_to_string(filepath.trim());
}

fn decrypt(pk: &String, data: &[u8], pass: &str) -> Result<String, io::Error> {
    let rsa = Rsa::private_key_from_pem_passphrase(pk.as_bytes(), pass.as_bytes()).expect("err");
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    let _ = rsa.private_decrypt(data, &mut buf, Padding::PKCS1).unwrap();
    Ok(String::from_utf8(buf).expect("err").to_string())
}

fn read_csv(csv: String) -> Result<Vec<StringRecord>, io::Error> {
    let mut v: Vec<StringRecord> = Vec::new();
    let mut rdr = csv::Reader::from_reader(csv.as_bytes());
    for result in rdr.records() {
        let record = result?;
        v.push(record);
    }
    Ok(v)
}

fn write_to_file(records: Vec<String>) -> Result<(), io::Error> {
    let path = env::current_dir().expect("path not found");
    let path = path.join("decrypted-data.json");

    println!(
        "{} {}",
        format!("Saving the decrypted file at ->").red(),
        path.display()
    );
    fs::write(path, format!("{}{}{}", "[", records.join(",\n"), "]"))
        .expect("Error in writing to the file");
    Ok(())
}
