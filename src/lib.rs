use std::{os::fd::AsFd, str::FromStr};

use nix::{poll::PollTimeout, sys::socket::{
    AddressFamily, SockFlag, SockType, SockaddrIn, bind, setsockopt, socket, sockopt::{Broadcast, RcvBuf, ReuseAddr, SndBuf}}};

use nix::poll::{poll, PollFd, PollFlags};

use std::os::fd::AsRawFd;

use nix::fcntl::{fcntl, FcntlArg, OFlag};


pub fn run () {

    let sock_addr = SockaddrIn::from_str("0.0.0.0:3000").unwrap(); 

    let fd = socket(
        AddressFamily::Inet, 
        SockType::Datagram, 
        SockFlag::empty(), 
        None, 
    ).unwrap();

    let flags = OFlag::from_bits_truncate(
        fcntl(
        &fd, 
        FcntlArg::F_GETFL
    ).unwrap());

    let new_flags = flags | OFlag::O_NONBLOCK;

    fcntl(&fd, FcntlArg::F_SETFL(new_flags)).unwrap();

    bind(fd.as_raw_fd(), &sock_addr).unwrap(); 

    setsockopt(&fd, ReuseAddr, &true).unwrap();

    loop {
        println!("Polling socket address");

        let is_ready = poll(&mut [PollFd::new(fd.as_fd(), PollFlags::POLLIN)], PollTimeout::from(1000 as u16)).unwrap(); 

        if is_ready >= 1 {
            println!("Connection made");
            break; 
        };
        
    }

}
