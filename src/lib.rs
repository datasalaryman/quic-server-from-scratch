use std::{os::fd::AsFd, os::fd::AsRawFd, str::FromStr};

use nix::{
    poll::PollTimeout,
    sys::socket::{
        AddressFamily, SockFlag, SockType, SockaddrIn, bind, recvfrom, setsockopt, socket,
        sockopt::ReuseAddr,
    },
};

use nix::poll::{PollFd, PollFlags, poll};

use nix::fcntl::{FcntlArg, OFlag, fcntl};

mod hello;
use hello::*;

pub fn run() {
    let sock_addr = SockaddrIn::from_str("0.0.0.0:3000").unwrap();

    let fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .unwrap();

    let flags = OFlag::from_bits_truncate(fcntl(&fd, FcntlArg::F_GETFL).unwrap());

    let new_flags = flags | OFlag::O_NONBLOCK;

    fcntl(&fd, FcntlArg::F_SETFL(new_flags)).unwrap();

    bind(fd.as_raw_fd(), &sock_addr).unwrap();

    setsockopt(&fd, ReuseAddr, &true).unwrap();

    loop {
        println!("Polling socket address");

        let is_ready = poll(
            &mut [PollFd::new(fd.as_fd(), PollFlags::POLLIN)],
            PollTimeout::from(1000 as u16),
        )
        .unwrap();

        if is_ready >= 1 {
            println!("Connection made");

            let mut recv_buf = vec![0u8; 1200];
            let (n, addr) = recvfrom::<SockaddrIn>(fd.as_raw_fd(), &mut recv_buf).unwrap();

            // println!("Connection from {}", &addr.unwrap().to_string());

            recv_buf.truncate(n);

            // let (client_key, client_iv, client_hp, server_key, server_iv, server_hp) =
            //    get_secrets(&recv_buf).unwrap();
            let client_hello = ClientHello::try_from(&recv_buf).unwrap();

            // println!("Client Key: {:?}", secrets.client_key);
            // println!("Client IV: {:?}", secrets.client_iv);
            // println!("Client HP: {:?}", secrets.client_hp);
            // println!("Server Key: {:?}", secrets.server_key);
            // println!("Server IV: {:?}", secrets.server_iv);
            // println!("Server HP: {:?}", secrets.server_hp);
            break;
        };
    }
}
