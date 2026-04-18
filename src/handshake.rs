use std::io::Error;

use bytes::{Buf, BytesMut};

use ring::hkdf::{KeyType, Prk, Salt, HKDF_SHA256};

pub fn get_secrets(
    buf: &[u8],
) -> Result<([u8; 16], [u8; 12], [u8; 16], [u8; 16], [u8; 12], [u8; 16]), Error> {
    let mut buf = BytesMut::from(buf);
    let is_long = buf.get_u8();
    let version = buf.get_u32();

    // Check this is Initial packet (0x00) with long header (bit 7 set)
    if (is_long & 0x80) == 0 || (is_long & 0x30) != 0 {
        println!("Wrong first byte");

        return Err(Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid first byte",
        ));
    }

    // DCIL + SCIL encoded in first byte (low 6 bits for version-specific)
    // Simplified: read DCID/SCID lengths and values
    let dcid_len = buf.get_u8() as usize;
    let dcid = buf.copy_to_bytes(dcid_len);
    let scid_len = buf.get_u8() as usize;
    let scid = buf.copy_to_bytes(scid_len);

    println!("DCID: {}", hex::encode(&dcid));
    println!("SCID: {}", hex::encode(&scid));

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

    println!("Client initial secret: {:?}", client_i_s);

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

    return Ok((
        client_key, client_iv, client_hp, server_key, server_iv, server_hp,
    ));
}
