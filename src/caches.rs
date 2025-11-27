use std::{
	collections::{HashMap, HashSet},
	net::IpAddr,
	sync::{Arc, Condvar, LazyLock, Mutex},
};

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

#[derive(Default)]
pub struct TotalDataSizeCache {
	pub map: HashMap<IpAddr, u32>,
	pub dirty: HashSet<IpAddr>,
}

pub static TOTAL_DATA_SIZE_CACHE: LazyLock<Arc<(Mutex<TotalDataSizeCache>, Condvar)>> =
	LazyLock::new(|| Arc::new((Mutex::new(TotalDataSizeCache::default()), Condvar::new())));

#[derive(Default)]
pub struct PortsTouchedCache {
	pub map: HashMap<IpPair, HashSet<u16>>,
	pub dirty: HashSet<IpPair>,
}

pub static PORTS_TOUCHED_CACHE: LazyLock<Arc<(Mutex<PortsTouchedCache>, Condvar)>> =
	LazyLock::new(|| Arc::new((Mutex::new(PortsTouchedCache::default()), Condvar::new())));

#[derive(Default)]
pub struct DnsCache {
	pub map: HashMap<IpAddr, HashSet<String>>,
	pub dirty: HashSet<IpAddr>,
}

pub static DNS_CACHE: LazyLock<Arc<(Mutex<DnsCache>, Condvar)>> =
	LazyLock::new(|| Arc::new((Mutex::new(DnsCache::default()), Condvar::new())));

pub enum CachableEvent {
	IpSize(IpAddr, u32),
	Port(IpPair, u16),
	Dns(IpAddr, String),
}

pub fn cache_event(event: CachableEvent) {
	match event {
		CachableEvent::IpSize(ip, size) => {
			let mut guard = TOTAL_DATA_SIZE_CACHE.0.lock().unwrap();
			*guard.map.entry(ip).or_insert(0) += size;
			guard.dirty.insert(ip);
			TOTAL_DATA_SIZE_CACHE.1.notify_all();
		}
		CachableEvent::Port(ip_set, port) => {
			let mut guard = PORTS_TOUCHED_CACHE.0.lock().unwrap();
			guard.map.entry(ip_set.clone()).or_default();
			guard.map.get_mut(&ip_set).unwrap().insert(port);
			guard.dirty.insert(ip_set.clone());
			PORTS_TOUCHED_CACHE.1.notify_all();
		}
		CachableEvent::Dns(ip, domain) => {
			let mut guard = DNS_CACHE.0.lock().unwrap();
			guard.map.entry(ip).or_default();
			guard.map.get_mut(&ip).unwrap().insert(domain);
			guard.dirty.insert(ip);
			DNS_CACHE.1.notify_all();
		}
	}
}

// TODO: Find a way to clean/cycle the cache when noting is detected.
