use std::io::{Error, ErrorKind::InvalidData};

use bytes::{Buf, BytesMut};

use ring::hkdf::{HKDF_SHA256, KeyType, Prk, Salt};

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

        let salt = Salt::new(HKDF_SHA256, init_hex.as_slice());

        let prk = salt.extract(&dcid);

        let mut client_i_s = [0u8; 32];
        let mut server_i_s = [0u8; 32];

        prk.expand(&[b"client in"], HKDF_SHA256)
            .unwrap()
            .fill(&mut client_i_s)
            .unwrap();

        prk.expand(&[b"server in"], HKDF_SHA256)
            .unwrap()
            .fill(&mut server_i_s)
            .unwrap();

        let client_prk = Prk::new_less_safe(HKDF_SHA256, &client_i_s);

        struct pr_key_type;
        impl KeyType for pr_key_type {
            fn len(&self) -> usize {
                16
            }
        }

        struct iv_key_type;
        impl KeyType for iv_key_type {
            fn len(&self) -> usize {
                12
            }
        }

        struct hp_key_type;
        impl KeyType for hp_key_type {
            fn len(&self) -> usize {
                16
            }
        }

        let server_prk = Prk::new_less_safe(HKDF_SHA256, &server_i_s);

        let mut client_key = [0u8; 16];
        let mut client_iv = [0u8; 12];
        let mut client_hp = [0u8; 16];

        let mut server_key = [0u8; 16];
        let mut server_iv = [0u8; 12];
        let mut server_hp = [0u8; 16];

        client_prk
            .expand(&[b"quic key"], pr_key_type)
            .unwrap()
            .fill(&mut client_key)
            .unwrap();

        client_prk
            .expand(&[b"quic iv"], iv_key_type)
            .unwrap()
            .fill(&mut client_iv)
            .unwrap();

        client_prk
            .expand(&[b"quic hp"], hp_key_type)
            .unwrap()
            .fill(&mut client_hp)
            .unwrap();

        server_prk
            .expand(&[b"quic key"], pr_key_type)
            .unwrap()
            .fill(&mut server_key)
            .unwrap();

        server_prk
            .expand(&[b"quic iv"], iv_key_type)
            .unwrap()
            .fill(&mut server_iv)
            .unwrap();

        server_prk
            .expand(&[b"quic hp"], hp_key_type)
            .unwrap()
            .fill(&mut server_hp)
            .unwrap();

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
    pub packet_number_bytes: &'a [u8], 
    pub payload_bytes: &'a [u8],
    pub auth_bytes: &'a [u8]
}

impl<'a> TryFrom<&'a Vec<u8>> for ClientHello<'a> {
    type Error = Error;

    fn try_from(buf: &'a Vec<u8>) -> Result<Self, Self::Error> {
        let mut pos = 0;
        let is_long = &buf[pos];
        pos += 1;
        let version = &buf[pos..pos + 4];
        pos += 4; 

        // Check this is Initial packet (0x00) with long header (bit 7 set)
        if (is_long & 0x80) == 0 || (is_long & 0x30) != 0 {
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid first byte",
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

        let (token_byte_len, token_len_mask) = match buf[pos] >> 6 {
            0 => (1, 0x3f),
            1 => (2, 0x3f),
            2 => (4, 0x3f),
            _ => (8, 0x3f),
        };

        let mut token_len = (buf[pos] & token_len_mask) as u64;

        for i in 1..token_byte_len {
            token_len = (token_len << 8) | buf[pos + i] as u64;
            pos += 1;
        }
        pos += 1;

        let (payload_byte_len, payload_len_mask) = match buf[pos] >> 6
        {
            0 => (1, 0x3f),
            1 => (2, 0x3f),
            2 => (4, 0x3f),
            _ => (8, 0x3f),
        };

        let mut payload_len = (buf[pos] & payload_len_mask) as u64;

        for i in 1..payload_byte_len {
            payload_len = (payload_len << 8) | buf[pos + i] as u64;
            pos += 1;
        }
        pos += 1; 

        let content_bytes = &buf[pos..(pos + payload_len as usize)];

        pos = 0;

        let packet_number_byte_len = match ((content_bytes[pos] & 0x03) + 1) as u8 {
            0 => 1,
            1 => 2,
            2 => 3,
            _ => 4, 
        };

        let packet_number_bytes = &content_bytes[pos..pos+packet_number_byte_len];
        pos += packet_number_byte_len; 

        let auth_start = payload_len.saturating_sub(16) as usize;

        let payload_bytes = &content_bytes[pos..auth_start]; 

        let auth_bytes = &content_bytes[auth_start..payload_len as usize];

        // assert!(auth_bytes.len() == 16);
        
        // assert!(payload_bytes.len() == (content_bytes.len() - auth_bytes.len() - packet_number_byte_len)); 

        // assert_ne!(payload_bytes.last(), auth_bytes.first());

        Ok(ClientHello {
            bytes: &buf,
            secrets: secrets,
            token_len: token_len as usize,
            payload_len: payload_len as usize,
            packet_number_bytes: &packet_number_bytes, 
            payload_bytes: &payload_bytes,
            auth_bytes: &auth_bytes
        })
    }
}
