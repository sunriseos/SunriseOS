use crate::net::VirtioNet;
use log::*;
use alloc::vec::Vec;
use sunrise_libuser::syscalls;
use sunrise_libuser::error::KernelError;
use sunrise_libuser::types::HandleRef;
use smoltcp::time::Duration;
use alloc::borrow::ToOwned;
use alloc::slice::SliceConcatExt;
use core::str;

pub fn ping(device: VirtioNet) {
    use smoltcp::time::{Duration, Instant};
    use smoltcp::phy::Device;
    //use smoltcp::phy::wait as phy_wait;
    use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr,
                        Ipv4Address, TcpRepr, TcpPacket};
    use smoltcp::iface::{NeighborCache, EthernetInterfaceBuilder, Routes};
    use smoltcp::socket::{SocketSet, TcpSocket, TcpSocketBuffer};
    use byteorder::{NetworkEndian, ByteOrder};
    use alloc::collections::BTreeMap;

    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let remote_addr = IpAddress::v4(10, 0, 2, 2);

    let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; 64]);
    let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; 128]);
    let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

    let ethernet_addr = EthernetAddress(device.mac());
    let src_ipv4 = IpCidr::new(IpAddress::v4(10, 0, 2, 15), 24);
    let ip_addrs = [src_ipv4];
    let default_v4_gw = Ipv4Address::new(10, 0, 2, 2);
    let mut routes_storage = [None; 1];
    let mut routes = Routes::new(&mut routes_storage[..]);
    routes.add_default_ipv4_route(default_v4_gw).unwrap();
    let mut iface = EthernetInterfaceBuilder::new(device)
            .ethernet_addr(ethernet_addr)
            .ip_addrs(ip_addrs)
            .routes(routes)
            .neighbor_cache(neighbor_cache)
            .finalize();

    let mut sockets = SocketSet::new(vec![]);
    let tcp_handle = sockets.add(tcp_socket);

    {
        let mut socket = sockets.get::<TcpSocket>(tcp_handle);
        socket.connect((remote_addr, 10000), 49500).unwrap();
    }
    let mut tcp_active = false;

    debug!("Starting loop:");
    loop {
        let timestamp = Instant::from_millis(syscalls::get_system_tick().wrapping_mul(12) as i64 / 625_000_000);
        match iface.poll(&mut sockets, timestamp) {
            Ok(_) => {},
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        {
            let mut socket = sockets.get::<TcpSocket>(tcp_handle);
            if socket.is_active() && !tcp_active {
                debug!("connected");
            } else if !socket.is_active() && tcp_active {
                debug!("disconnected");
                break;
            }
            tcp_active = socket.is_active();

            if socket.may_recv() {

                let data = socket.recv(|data| {
                    let mut data = data.to_owned();
                    if data.len() > 0 {
                        debug!("recv data: {:?}",
                               str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)"));
                        data = data.split(|&b| b == b'\n').collect::<Vec<_>>().concat();
                        data.reverse();
                        data.extend(b"\n");
                    }
                    (data.len(), data)
                }).unwrap();
                if socket.can_send() && data.len() > 0 {
                    debug!("send data: {:?}",
                           str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)"));
                    socket.send_slice(&data[..]).unwrap();
                }
            } else if socket.may_send() {
                socket.send_slice(b"Ohi!").unwrap();
            }
        }

        wait(iface.device().device.irq_event.0.as_ref(), iface.poll_delay(&sockets, timestamp));
    }
}

fn wait(handle: HandleRef<'_>, duration: Option<Duration>) -> Result<(), ()> {
    match syscalls::wait_synchronization(&[handle], duration.map(|v| v.millis() as usize * 1_000_000)) {
        Ok(_) => {
            debug!("Handle got signaled!");
            Ok(())
        },
        Err(KernelError::Timeout) => Ok(()),
        Err(err) => Err(()) 
    }
}