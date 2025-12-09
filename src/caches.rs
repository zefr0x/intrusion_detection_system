use std::{
	collections::{HashMap, HashSet},
	net::IpAddr,
	sync::{Arc, Condvar, LazyLock, Mutex},
	time::Duration,
};

use ttlhashmap::TtlHashMap;

use crate::config::CONFIG;

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct IpPair {
	pub src: IpAddr,
	pub dst: IpAddr,
}

impl IpPair {
	pub fn new(src: IpAddr, dst: IpAddr) -> Self {
		Self { src, dst }
	}
}

pub struct TotalDataSizeCache {
	pub map: TtlHashMap<IpAddr, u32>,
	pub dirty: HashSet<IpAddr>,
}

impl Default for TotalDataSizeCache {
	fn default() -> Self {
		let mut map = TtlHashMap::new(Duration::from_secs(CONFIG.cache.total_data_size.entiry_ttl));
		map.autoclean = ttlhashmap::AutoClean::Never;
		map.max_nodes = CONFIG.cache.total_data_size.max_size;

		Self {
			map,
			dirty: Default::default(),
		}
	}
}

pub static TOTAL_DATA_SIZE_CACHE: LazyLock<Arc<(Mutex<TotalDataSizeCache>, Condvar)>> =
	LazyLock::new(|| Arc::new((Mutex::new(TotalDataSizeCache::default()), Condvar::new())));

pub struct PortsTouchedCache {
	pub map: TtlHashMap<IpPair, HashSet<u16>>,
	pub dirty: HashSet<IpPair>,
}

impl Default for PortsTouchedCache {
	fn default() -> Self {
		let mut map = TtlHashMap::new(Duration::from_secs(CONFIG.cache.ports_touched.entiry_ttl));
		map.autoclean = ttlhashmap::AutoClean::Never;
		map.max_nodes = CONFIG.cache.ports_touched.max_size;

		Self {
			map,
			dirty: Default::default(),
		}
	}
}

pub static PORTS_TOUCHED_CACHE: LazyLock<Arc<(Mutex<PortsTouchedCache>, Condvar)>> =
	LazyLock::new(|| Arc::new((Mutex::new(PortsTouchedCache::default()), Condvar::new())));

#[derive(Default)]
pub struct DnsCache {
	pub map: HashMap<IpAddr, HashSet<String>>,
}

pub static DNS_CACHE: LazyLock<Arc<(Mutex<DnsCache>, Condvar)>> =
	LazyLock::new(|| Arc::new((Mutex::new(DnsCache::default()), Condvar::new())));

pub struct TcpSynFloodCache {
	pub map: TtlHashMap<IpAddr, u32>,
	pub dirty: HashSet<IpAddr>,
}

impl Default for TcpSynFloodCache {
	fn default() -> Self {
		let mut map = TtlHashMap::new(Duration::from_secs(CONFIG.cache.tcp_syn_flood.entiry_ttl));
		map.autoclean = ttlhashmap::AutoClean::Never;
		map.max_nodes = CONFIG.cache.tcp_syn_flood.max_size;

		Self {
			map,
			dirty: Default::default(),
		}
	}
}

pub static TCP_SYN_FLOOD_CACHE: LazyLock<Arc<(Mutex<TcpSynFloodCache>, Condvar)>> =
	LazyLock::new(|| Arc::new((Mutex::new(TcpSynFloodCache::default()), Condvar::new())));

#[derive(Debug)]
pub enum CachableEvent {
	IpSize(IpAddr, u32),
	Port(IpPair, u16),
	Dns(IpAddr, String),
	TcpSyn(IpAddr),
}

fn cache_event(event: CachableEvent) {
	tracing::trace!(?event, "Caching event");

	match event {
		CachableEvent::IpSize(ip, size) => {
			let mut guard = TOTAL_DATA_SIZE_CACHE.0.lock().unwrap();
			match guard.map.get_mut(&ip) {
				Some(value) => {
					*value += size;
				}
				None => {
					guard.map.insert(ip, size);
				}
			}

			guard.dirty.insert(ip);
			TOTAL_DATA_SIZE_CACHE.1.notify_all();
		}
		CachableEvent::Port(ip_set, port) => {
			let mut guard = PORTS_TOUCHED_CACHE.0.lock().unwrap();
			if guard.map.get_mut(&ip_set).is_none() {
				guard.map.insert(ip_set.clone(), Default::default());
			}
			guard.map.get_mut(&ip_set).unwrap().insert(port);
			guard.dirty.insert(ip_set.clone());
			PORTS_TOUCHED_CACHE.1.notify_all();
		}
		CachableEvent::Dns(ip, domain) => {
			let mut guard = DNS_CACHE.0.lock().unwrap();
			if guard.map.get_mut(&ip).is_none() {
				guard.map.insert(ip, Default::default());
			}
			guard.map.get_mut(&ip).unwrap().insert(domain);
			DNS_CACHE.1.notify_all();
		}
		CachableEvent::TcpSyn(ip) => {
			let mut guard = TCP_SYN_FLOOD_CACHE.0.lock().unwrap();
			match guard.map.get_mut(&ip) {
				Some(value) => {
					*value += 1;
				}
				None => {
					guard.map.insert(ip, 1);
				}
			}

			guard.dirty.insert(ip);
			TCP_SYN_FLOOD_CACHE.1.notify_all();
		}
	}
}

pub fn event_cacher(reciever: std::sync::mpsc::Receiver<CachableEvent>) {
	loop {
		cache_event(reciever.recv().unwrap());
	}
}
