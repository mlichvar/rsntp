// Copyright (C) 2017  Miroslav Lichvar
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

extern crate byteorder;
extern crate getopts;
extern crate net2;
extern crate rand;
extern crate privdrop;

use std::thread;
use std::env;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::{UdpSocket, SocketAddr};
use std::time::{SystemTime, Duration};
use std::sync::{Arc, Mutex};

use byteorder::{BigEndian, ByteOrder};

use getopts::Options;

use net2::UdpBuilder;
use net2::unix::UnixUdpBuilderExt;

use rand::random;

#[derive(Debug, Copy, Clone)]
struct NtpTimestamp {
    ts: u64,
}

impl NtpTimestamp {
    fn now() -> NtpTimestamp {
        let now = SystemTime::now();
        let dur = now.duration_since(std::time::UNIX_EPOCH).unwrap();
        let secs = dur.as_secs() + 2208988800; // 1900 epoch
        let nanos = dur.subsec_nanos();

        NtpTimestamp{ts: (secs << 32) + (nanos as f64 * 4.294967296) as u64}
    }

    fn zero() -> NtpTimestamp {
        NtpTimestamp{ts: 0}
    }

    fn random() -> NtpTimestamp {
        NtpTimestamp{ts: random()}
    }

    fn diff_to_sec(&self, ts: &NtpTimestamp) -> f64 {
        (self.ts - ts.ts) as i64 as f64 / 4294967296.0
    }

    fn read(buf: &[u8]) -> NtpTimestamp {
        NtpTimestamp{ts: BigEndian::read_u64(buf)}
    }

    fn write(&self, buf: &mut [u8]) {
        BigEndian::write_u64(buf, self.ts);
    }
}

impl PartialEq for NtpTimestamp {
    fn eq(&self, other: &NtpTimestamp) -> bool {
        self.ts == other.ts
    }
}

#[derive(Debug, Copy, Clone)]
struct NtpFracValue {
    val: u32,
}

impl NtpFracValue {
    fn read(buf: &[u8]) -> NtpFracValue {
        NtpFracValue{val: BigEndian::read_u32(buf)}
    }

    fn write(&self, buf: &mut [u8]) {
        BigEndian::write_u32(buf, self.val);
    }

    fn zero() -> NtpFracValue {
        NtpFracValue{val: 0}
    }

    fn increment(&mut self) {
        self.val += 1;
    }
}

#[derive(Debug)]
struct NtpPacket {
    remote_addr: SocketAddr,
    local_ts: NtpTimestamp,

    leap: u8,
    version: u8,
    mode: u8,
    stratum: u8,
    poll: i8,
    precision: i8,
    delay: NtpFracValue,
    dispersion: NtpFracValue,
    ref_id: u32,
    ref_ts: NtpTimestamp,
    orig_ts: NtpTimestamp,
    rx_ts: NtpTimestamp,
    tx_ts: NtpTimestamp,
}

impl NtpPacket {
    fn receive(socket: &UdpSocket) -> io::Result<NtpPacket> {
        let mut buf = [0; 1024];

        let (len, addr) = socket.recv_from(&mut buf)?;

        let local_ts = NtpTimestamp::now();

        if len < 48 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Packet too short"));
        }

        let leap = buf[0] >> 6;
        let version = (buf[0] >> 3) & 0x7;
        let mode = buf[0] & 0x7;

        if version < 1 || version > 4 {
            return Err(Error::new(ErrorKind::Other, "Unsupported version"));
        }

        Ok(NtpPacket{
            remote_addr: addr,
            local_ts: local_ts,
            leap: leap,
            version: version,
            mode: mode,
            stratum: buf[1],
            poll: buf[2] as i8,
            precision: buf[3] as i8,
            delay: NtpFracValue::read(&buf[4..8]),
            dispersion: NtpFracValue::read(&buf[8..12]),
            ref_id: BigEndian::read_u32(&buf[12..16]),
            ref_ts: NtpTimestamp::read(&buf[16..24]),
            orig_ts: NtpTimestamp::read(&buf[24..32]),
            rx_ts: NtpTimestamp::read(&buf[32..40]),
            tx_ts: NtpTimestamp::read(&buf[40..48]),
        })
    }

    fn send(&self, socket: &UdpSocket) -> io::Result<usize> {
        let mut buf = [0; 48];

        buf[0] = self.leap << 6 | self.version << 3 | self.mode;
        buf[1] = self.stratum;
        buf[2] = self.poll as u8;
        buf[3] = self.precision as u8;
        self.delay.write(&mut buf[4..8]);
        self.dispersion.write(&mut buf[8..12]);
        BigEndian::write_u32(&mut buf[12..16], self.ref_id);
        self.ref_ts.write(&mut buf[16..24]);
        self.orig_ts.write(&mut buf[24..32]);
        self.rx_ts.write(&mut buf[32..40]);
        self.tx_ts.write(&mut buf[40..48]);

        socket.send_to(&buf, self.remote_addr)
    }

    fn is_request(&self) -> bool {
        self.mode == 1 || self.mode == 3 ||
            (self.mode == 0 && self.version == 1 && self.remote_addr.port() != 123)
    }

    fn make_response(&self, state: &NtpServerState) -> Option<NtpPacket> {
        if !self.is_request() {
            return None;
        }

        Some(NtpPacket{
            remote_addr: self.remote_addr,
            local_ts: NtpTimestamp::zero(),
            leap: state.leap,
            version: self.version,
            mode: if self.mode == 1 { 2 } else { 4 },
            stratum: state.stratum,
            poll: self.poll,
            precision: state.precision,
            delay: state.delay,
            dispersion: state.dispersion,
            ref_id: state.ref_id,
            ref_ts: state.ref_ts,
            orig_ts: self.tx_ts,
            rx_ts: self.local_ts,
            tx_ts: NtpTimestamp::now(),
        })
    }

    fn new_request(remote_addr: SocketAddr) -> NtpPacket {
        NtpPacket{
            remote_addr: remote_addr,
            local_ts: NtpTimestamp::now(),
            leap: 0,
            version: 4,
            mode: 3,
            stratum: 0,
            poll: 0,
            precision: 0,
            delay: NtpFracValue::zero(),
            dispersion: NtpFracValue::zero(),
            ref_id: 0,
            ref_ts: NtpTimestamp::zero(),
            orig_ts: NtpTimestamp::zero(),
            rx_ts: NtpTimestamp::zero(),
            tx_ts: NtpTimestamp::random(),
        }
    }

    fn is_valid_response(&self, request: &NtpPacket) -> bool {
        self.remote_addr == request.remote_addr &&
            self.mode == request.mode + 1 &&
            self.orig_ts == request.tx_ts
    }

    fn get_server_state(&self) -> NtpServerState {
        NtpServerState{
            leap: self.leap,
            stratum: self.stratum,
            precision: self.precision,
            ref_id: self.ref_id,
            ref_ts: self.ref_ts,
            dispersion: self.dispersion,
            delay: self.delay,
        }
    }
}

#[derive(Copy, Clone)]
struct NtpServerState {
    leap: u8,
    stratum: u8,
    precision: i8,
    ref_id: u32,
    ref_ts: NtpTimestamp,
    dispersion: NtpFracValue,
    delay: NtpFracValue,
}

struct NtpServer {
    state: Arc<Mutex<NtpServerState>>,
    sockets: Vec<UdpSocket>,
    server_addr: String,
    debug: bool,
}

impl NtpServer {
    fn new(local_addrs: Vec<String>, server_addr: String, debug: bool) -> NtpServer {
        let state = NtpServerState{
            leap: 0,
            stratum: 0,
            precision: 0,
            ref_id: 0,
            ref_ts: NtpTimestamp::zero(),
            dispersion: NtpFracValue::zero(),
            delay: NtpFracValue::zero(),
        };

        let mut sockets = vec![];

        for addr in local_addrs {
            let sockaddr = addr.parse().unwrap();

            let udp_builder = match sockaddr {
                SocketAddr::V4(_) => UdpBuilder::new_v4().unwrap(),
                SocketAddr::V6(_) => UdpBuilder::new_v6().unwrap(),
            };

            let udp_builder_ref = match sockaddr {
                SocketAddr::V4(_) => &udp_builder,
                SocketAddr::V6(_) => udp_builder.only_v6(true).unwrap(),
            };

            let socket = match udp_builder_ref.reuse_port(true).unwrap().bind(sockaddr) {
                Ok(s) => s,
                Err(e) => panic!("Couldn't bind socket: {}", e)
            };

            sockets.push(socket);
        }

        NtpServer{
            state: Arc::new(Mutex::new(state)),
            sockets: sockets,
            server_addr: server_addr,
            debug: debug,
        }
    }

    fn process_requests(thread_id: u32, debug: bool, socket: UdpSocket, state: Arc<Mutex<NtpServerState>>) {
        let mut last_update = NtpTimestamp::now();
        let mut cached_state: NtpServerState;
        cached_state = *state.lock().unwrap();

        println!("Server thread #{} started", thread_id);

        loop {
            match NtpPacket::receive(&socket) {
                Ok(request) => {
                    if debug {
                        println!("Thread #{} received {:?}", thread_id, request);
                    }

                    if request.local_ts.diff_to_sec(&last_update).abs() > 0.1 {
                        cached_state = *state.lock().unwrap();
                        last_update = request.local_ts;
                        if debug {
                            println!("Thread #{} updated its state", thread_id);
                        }
                    }

                    match request.make_response(&cached_state) {
                        Some(response) => {
                            match response.send(&socket) {
                                Ok(_) => {
                                    if debug {
                                        println!("Thread #{} sent {:?}", thread_id, response);
                                    }
                                },
                                Err(e) => println!("Thread #{} failed to send packet to {}: {}",
                                                   thread_id, response.remote_addr, e)
                            }
                        },
                        None => {}
                    }
                },
                Err(e) => {
                    println!("Thread #{} failed to receive packet: {}", thread_id, e);
                },
            }
        }
    }

    fn update_state(state: Arc<Mutex<NtpServerState>>, addr: SocketAddr, debug: bool) {
        let request = NtpPacket::new_request(addr);
        let mut new_state: Option<NtpServerState> = None;
        let socket = match addr {
            SocketAddr::V4(_) => UdpBuilder::new_v4().unwrap().bind("0.0.0.0:0").unwrap(),
            SocketAddr::V6(_) => UdpBuilder::new_v6().unwrap().bind("[::]:0").unwrap(),
        };

        socket.set_read_timeout(Some(Duration::new(1, 0))).unwrap();

        match request.send(&socket) {
            Ok(_) => {
                if debug {
                    println!("Client sent {:?}", request);
                }
            },
            Err(e) => {
                println!("Client failed to send packet: {}", e);
                return;
            }
        }

        loop {
            let response = match NtpPacket::receive(&socket) {
                Ok(packet) => {
                    if debug {
                        println!("Client received {:?}", packet);
                    }

                    if !packet.is_valid_response(&request) {
                        println!("Client received unexpected {:?}", packet);
                        continue;
                    }

                    packet
                },
                Err(e) => {
                    if debug {
                        println!("Client failed to receive packet: {}", e);
                    }
                    break;
                }
            };

            new_state = Some(response.get_server_state());
            break;
        }

        if let Ok(mut state) = state.lock() {
            if let Some(new_state) = new_state {
                *state = new_state;
            }

            state.dispersion.increment();
        }
    }

    fn run(&self) {
        let mut threads = vec![];
        let mut id = 0;
        let quit = false;

        for socket in &self.sockets {
            id = id + 1;
            let state = self.state.clone();
            let debug = self.debug;
            let cloned_socket = socket.try_clone().unwrap();

            threads.push(thread::spawn(move || {NtpServer::process_requests(id, debug, cloned_socket, state); }));
        }

        while ! quit {
            NtpServer::update_state(self.state.clone(), self.server_addr.parse().unwrap(), self.debug);

            thread::sleep(Duration::new(1, 0));
        }

        for thread in threads {
            let _ = thread.join();
        }
    }
}

fn print_usage(opts: Options) {
    let brief = format!("Usage: rsntp [OPTIONS]");
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut addrs = Vec::new();
    let mut opts = Options::new();

    opts.optopt("4", "ipv4-threads", "set number of IPv4 server threads (1)", "NUM");
    opts.optopt("6", "ipv6-threads", "set number of IPv6 server threads (1)", "NUM");
    opts.optopt("a", "ipv4-address", "set local address of IPv4 server sockets (0.0.0.0:123)", "ADDR:PORT");
    opts.optopt("b", "ipv6-address", "set local address of IPv6 server sockets ([::]:123)", "ADDR:PORT");
    opts.optopt("s", "server-address", "set server address (127.0.0.1:11123)", "ADDR:PORT");
    opts.optopt("u", "user", "run as USER", "USER");
    opts.optopt("r", "root", "change root directory", "DIR");
    opts.optflag("d", "debug", "Enable debug messages");
    opts.optflag("h", "help", "Print this help message");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            println!("{}", e);
            print_usage(opts);
            return;
        }
    };

    if matches.opt_present("h") {
        print_usage(opts);
        return;
    }

    let server_addr = matches.opt_str("s").unwrap_or("127.0.0.1:11123".to_string());
    let n4 = matches.opt_str("4").unwrap_or("1".to_string()).parse().unwrap_or(1);
    let n6 = matches.opt_str("6").unwrap_or("1".to_string()).parse().unwrap_or(1);
    let local_address4 = matches.opt_str("a").unwrap_or("0.0.0.0:123".to_string());
    let local_address6 = matches.opt_str("b").unwrap_or("[::]:123".to_string());

    for _ in 0..n4 {
        addrs.push(local_address4.clone());
    }

    for _ in 0..n6 {
        addrs.push(local_address6.clone());
    }

    let server = NtpServer::new(addrs, server_addr, matches.opt_present("d"));

    if matches.opts_present(&["r".to_string(), "u".to_string()]) {
        privdrop::PrivDrop::default()
            .chroot(matches.opt_str("r").unwrap_or("/".to_string()))
            .user(&matches.opt_str("u").unwrap_or("root".to_string()))
            .unwrap_or_else(|e| { panic!("Couldn't set user: {}", e) })
            .apply()
            .unwrap_or_else(|e| { panic!("Couldn't drop privileges: {}", e) });
    }

    server.run();
}
