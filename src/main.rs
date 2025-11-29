use std::net::IpAddr;

use pnet::packet::{
	Packet,
	ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
};

use crate::caches::{CachableEvent, IpPair};

mod analyzers;
mod caches;

#[tokio::main]
async fn main() {
	// Load `.env` file in debug builds
	#[cfg(debug_assertions)]
	#[expect(unused_must_use)]
	dotenvy::dotenv();

	// Initialize tracing subscriber with a non-blocking writer
	let (non_blocking_writer, _guard) = tracing_appender::non_blocking(std::io::stderr());
	tracing_subscriber::fmt()
		.with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
		.with_writer(non_blocking_writer)
		.init();

	// Initiate interface capturing I/O threads
	let ifaces = pnet::datalink::interfaces();

	let mut config = pnet::datalink::Config::default();
	config.read_buffer_size = 4096;

	let mut iface_handlers_set = tokio::task::JoinSet::new();

	for iface in ifaces {
		if iface.is_up() {
			tracing::info!(
				name=iface.name,
				index=iface.index,
				description=iface.description,
				flags=iface.flags,
				mac=?iface.mac,
				"Attaching to network interface"
			);

			let iface_span = tracing::info_span!(parent: tracing::Span::current(), "Interface", name=iface.name);

			iface_handlers_set.spawn_blocking(move || iface_span.in_scope(|| iface_handler(iface, config)));
		}
	}

	//Initiate analysis threads
	rayon::spawn(move || {
		analyzers::uploaded_data_sizes_analyzer();
	});
	rayon::spawn(move || {
		analyzers::ports_activity_analyzer();
	});
	rayon::spawn(move || {
		analyzers::dns_analyzer();
	});

	// Join the capturing threads
	iface_handlers_set.join_all().await;
}

fn iface_handler(iface: pnet::datalink::NetworkInterface, config: pnet::datalink::Config) {
	let mut reciver = match pnet::datalink::channel(&iface, config) {
		Ok(pnet::datalink::Channel::Ethernet(_, reciver)) => reciver,
		_ => panic!("Unsupported data link channel for `{iface}`"),
	};

	loop {
		match reciver.next() {
			Ok(raw_packet_data) => match pnet::packet::ethernet::EthernetPacket::new(raw_packet_data) {
				Some(ethernet) => handel_layer3(ethernet.payload(), ethernet.get_ethertype()),
				None => {
					tracing::debug!("Failed to parse raw packet data as ethernet packet");
				}
			},
			Err(e) => {
				tracing::error!("Failed to reciver packet: {e}");
			}
		}
	}
}

fn handel_layer3(payload: &[u8], protocol: pnet::packet::ethernet::EtherType) {
	match protocol {
		pnet::packet::ethernet::EtherTypes::Ipv4 => {
			if let Some(ipv4) = pnet::packet::ipv4::Ipv4Packet::new(payload) {
				caches::cache_event(CachableEvent::IpSize(
					IpAddr::V4(ipv4.get_destination()),
					ipv4.get_total_length() as u32,
				));

				let ip_set = IpPair::new(IpAddr::V4(ipv4.get_source()), IpAddr::V4(ipv4.get_destination()));

				handel_layer4(ipv4.payload(), ipv4.get_next_level_protocol(), ip_set);
			} else {
				tracing::warn!(?protocol, "Broken packet, payload doesn't match protocol")
			}
		}
		pnet::packet::ethernet::EtherTypes::Ipv6 => {
			if let Some(ipv6) = pnet::packet::ipv6::Ipv6Packet::new(payload) {
				caches::cache_event(CachableEvent::IpSize(
					IpAddr::V6(ipv6.get_destination()),
					ipv6.get_payload_length() as u32,
				));

				let ip_set = IpPair::new(IpAddr::V6(ipv6.get_source()), IpAddr::V6(ipv6.get_destination()));

				handel_layer4(ipv6.payload(), ipv6.get_next_header(), ip_set);
			} else {
				tracing::warn!(?protocol, "Broken packet, payload doesn't match protocol")
			}
		}
		_ => {}
	}
}

fn handel_layer4(payload: &[u8], protocol: IpNextHeaderProtocol, ip_set: IpPair) {
	match protocol {
		IpNextHeaderProtocols::Tcp => {
			if let Some(tcp) = pnet::packet::tcp::TcpPacket::new(payload) {
				caches::cache_event(CachableEvent::Port(ip_set.clone(), tcp.get_destination()));

				handel_layer5(tcp.payload(), ip_set);
			} else {
				tracing::warn!(?protocol, "Broken packet, payload doesn't match protocol")
			}
		}
		IpNextHeaderProtocols::Udp => {
			if let Some(udp) = pnet::packet::udp::UdpPacket::new(payload) {
				caches::cache_event(CachableEvent::Port(ip_set.clone(), udp.get_destination()));

				handel_layer5(udp.payload(), ip_set);
			} else {
				tracing::warn!(?protocol, "Broken packet, payload doesn't match protocol")
			}
		}
		_ => {}
	}
}

fn handel_layer5(payload: &[u8], ip_set: IpPair) {
	// PERF: Parsers can consume CPU, so we may need to offload them to Rayon threads?

	// Detect and parse DNS packets
	rayon::spawn({
		let payload = payload.to_owned();
		let ip_set = ip_set.clone();
		move || {
			if let Ok(dns) = simple_dns::Packet::parse(payload.as_slice()) {
				for question in dns.questions {
					let qname = question.qname.to_string();

					caches::cache_event(CachableEvent::Dns(ip_set.src, qname));
				}
			}
		}
	});
}
