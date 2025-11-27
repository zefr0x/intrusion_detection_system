use crate::caches;

pub fn uploaded_data_sizes_analyzer() {
	loop {
		std::thread::sleep(std::time::Duration::from_secs(1));

		let guard = caches::TOTAL_DATA_SIZE_CACHE.0.lock().unwrap();

		let mut guard = caches::TOTAL_DATA_SIZE_CACHE.1.wait(guard).unwrap();

		let mut triggered_for = Vec::new();

		for ip in guard.dirty.iter() {
			let size = *guard.map.get(ip).unwrap();

			if size >= 5000000 {
				triggered_for.push(ip.to_owned());

				tracing::warn!(dst = ip.to_string(), size, "Data larger than 5MB uploaded");
			}
		}
		guard.dirty.clear();

		for ip in triggered_for {
			guard.map.remove(&ip);
		}
	}
}

pub fn ports_activity_analyzer() {
	loop {
		std::thread::sleep(std::time::Duration::from_secs(1));

		let guard = caches::PORTS_TOUCHED_CACHE.0.lock().unwrap();

		let mut guard = caches::PORTS_TOUCHED_CACHE.1.wait(guard).unwrap();

		let mut triggered_for = Vec::new();

		for ip_set in guard.dirty.iter() {
			let count = guard.map.get(ip_set).unwrap().len();
			if count >= 20 {
				triggered_for.push(ip_set.to_owned());

				tracing::warn!(
					src = ip_set.src.to_string(),
					dst = ip_set.dst.to_string(),
					count,
					"Touching more than 20 port"
				);
			}
		}
		guard.dirty.clear();

		for ip_set in triggered_for {
			guard.map.remove(&ip_set);
		}
	}
}

pub fn dns_analyzer() {
	loop {
		std::thread::sleep(std::time::Duration::from_secs(1));

		let guard = caches::DNS_CACHE.0.lock().unwrap();

		let mut guard = caches::DNS_CACHE.1.wait(guard).unwrap();

		let mut triggered_for = Vec::new();

		for ip in guard.dirty.iter() {
			let qnames = guard.map.get(ip).unwrap();

			let malicious_domains = ["google.com", "gmail.com"];

			for domain in malicious_domains {
				if qnames.contains(domain) {
					triggered_for.push(ip.to_owned());

					tracing::warn!(src = ip.to_string(), query_name = domain, "Malicious dns request");
				}
			}
		}
		guard.dirty.clear();

		for ip_set in triggered_for {
			guard.map.remove(&ip_set);
		}
	}
}
