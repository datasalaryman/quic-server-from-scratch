use std::io::{Error, ErrorKind::InvalidData};

use bytes::{Buf, BytesMut};

use hkdf::Hkdf;
use sha2::Sha256;

pub struct ExchangeSecrets {
    pub client_key: [u8; 16],
    pub client_iv: [u8; 12],
    pub client_hp: [u8; 16],
    pub server_key: [u8; 16],
    pub server_iv: [u8; 12],
    pub server_hp: [u8; 16],
}

impl ExchangeSecrets {
    fn from(dcid_len: usize, buf: Vec<u8>) -> Self {
        // DCID starts at byte 6, ends at 6+dcid_len
        let dcid = &buf[6..6+dcid_len];

        println!("DCID: {}", hex::encode(&dcid));

        let init_hex = hex::decode("38762cf7f55934b34d179ae6a4c80cadccbb7f0a").unwrap();

        // let salt = Salt::new(HKDF_SHA256, init_hex.as_slice());

        // let prk = salt.extract(&dcid);

        let hk = Hkdf::<Sha256>::new(Some(&init_hex), dcid);

        let mut client_i_s = [0u8; 32];
        let mut server_i_s = [0u8; 32];
        let mut client_label = Vec::<u8>::new(); 
        let mut server_label = Vec::<u8>::new();

        let label_prefix = &(0 as u16).to_be_bytes(); 
        
        let client_label_body = [&b"tls13 "[..], &b"client in"[..]].concat();
        
        let server_label_body = [&b"tls13 "[..], &b"server in"[..]].concat();

        client_label.extend_from_slice(&(client_i_s.len() as u16).to_be_bytes());
        client_label.push(client_label_body.len() as u8);
        client_label.extend_from_slice(&client_label_body);
        client_label.push(0 as u8);        
        
        server_label.extend_from_slice(&(server_i_s.len() as u16).to_be_bytes());
        server_label.push(server_label_body.len() as u8);
        server_label.extend_from_slice(&server_label_body);
        server_label.push(0 as u8);        
       
        hk.expand(&client_label, &mut client_i_s).unwrap();
        hk.expand(&client_label, &mut server_i_s).unwrap();

        let client_prk = Hkdf::<Sha256>::from_prk(&client_i_s).unwrap();

        let server_prk = Hkdf::<Sha256>::from_prk(&server_i_s).unwrap();

        let mut client_key = [0u8; 16];
        let mut client_iv = [0u8; 12];
        let mut client_hp = [0u8; 16];

        let mut server_key = [0u8; 16];
        let mut server_iv = [0u8; 12];
        let mut server_hp = [0u8; 16];

        ExchangeSecrets {
            client_key,
            client_iv,
            client_hp,
            server_key,
            server_iv,
            server_hp,
        }
    }
}

pub struct ClientHello<'a> {
    pub bytes: &'a [u8],
    pub secrets: ExchangeSecrets,
    pub token_len: usize,
    pub payload_len: usize,
    pub packet_number_len: usize, 
    pub encrypted_payload: Vec<u8>, 
}

impl<'a> TryFrom<&'a Vec<u8>> for ClientHello<'a> {
    type Error = Error;

    fn try_from(buf: &'a Vec<u8>) -> Result<Self, Self::Error> {
        let mut pos = 0;
        let first_byte = buf[pos];
        pos += 1;
        let version = &buf[pos..pos + 4];
        pos += 4; 

        // Check this is Initial packet (0x00) with long header (bit 7 set)
        if (first_byte & 0x30) != 0 {
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid first byte for initial packet",
            ));
        }
        println!("Client Initial Packet Bytes: {:?}", &buf);

        let dcid_len = buf[pos] as usize;
        pos+= 1;

        let secrets = ExchangeSecrets::from(dcid_len, buf.to_vec());
        pos += dcid_len;

        let scid_len = buf[pos] as usize;
        pos += 1; 

        let scid = &buf[pos..pos + scid_len]; 
        pos += scid_len;

        let token_len_byte_len = 1 << (buf[pos] >> 6) as usize;

        let token_len = match token_len_byte_len {
            1 => (buf[0] & 0x3f) as u64,
            2 => {
                (((buf[0] & 0x3f) as u64) << 8) 
                    | (buf[1] as u64)
            },
            4 => {
                (((buf[0] & 0x3f) as u64) << 24) 
                    | ((buf[1] as u64) << 16) 
                    | ((buf[2] as u64) << 8)
                    | (buf[3] as u64)
            },
            _ => {
                (((buf[0] & 0x3f) as u64) << 56)
                    | ((buf[1] as u64) << 48)
                    | ((buf[2] as u64) << 40)
                    | ((buf[3] as u64) << 32)
                    | ((buf[4] as u64) << 24)
                    | ((buf[5] as u64) << 16)
                    | ((buf[6] as u64) << 8)
                    | (buf[7] as u64)
            },
        };

        pos += token_len_byte_len;

        let payload_len_byte_len = 1 << (buf[pos] >> 6) as usize;
        
        let payload_len = match payload_len_byte_len {
            1 => (buf[0] & 0x3f) as u64,
            2 => {
                (((buf[0] & 0x3f) as u64) << 8) 
                    | (buf[1] as u64)
            },
            4 => {
                (((buf[0] & 0x3f) as u64) << 24) 
                    | ((buf[1] as u64) << 16) 
                    | ((buf[2] as u64) << 8)
                    | (buf[3] as u64)
            },
            _ => {
                (((buf[0] & 0x3f) as u64) << 56)
                    | ((buf[1] as u64) << 48)
                    | ((buf[2] as u64) << 40)
                    | ((buf[3] as u64) << 32)
                    | ((buf[4] as u64) << 24)
                    | ((buf[5] as u64) << 16)
                    | ((buf[6] as u64) << 8)
                    | (buf[7] as u64)
            },
        };

        pos += payload_len_byte_len;

        let packet_number_len = ((first_byte & 0x03) +1) as usize;

        let encrypted_payload = buf[pos..].to_vec();

        Ok(ClientHello {
            bytes: &buf,
            secrets: secrets,
            token_len: token_len as usize,
            payload_len: payload_len as usize,
            packet_number_len: packet_number_len, 
            encrypted_payload, 
        })
    }
}
