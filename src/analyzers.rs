use crate::caches;
use crate::config::CONFIG;

pub fn uploaded_data_sizes_analyzer() {
	loop {
		std::thread::sleep(std::time::Duration::from_secs(
			CONFIG.analyzer.uploaded_data_sizes.cycle,
		));

		let guard = caches::TOTAL_DATA_SIZE_CACHE.0.lock().unwrap();

		let mut guard = caches::TOTAL_DATA_SIZE_CACHE.1.wait(guard).unwrap();

		tracing::trace!(elements = guard.map.len(), "Total data sizes cache");

		let mut triggered_for = Vec::new();

		for ip in guard.dirty.iter() {
			let size = *guard.map.get_raw(ip).unwrap();

			if size > CONFIG.analyzer.uploaded_data_sizes.trigger_size {
				triggered_for.push(ip.to_owned());

				tracing::warn!(
					dst = ip.to_string(),
					size,
					"Data larger than {} bytes uploaded",
					CONFIG.analyzer.uploaded_data_sizes.trigger_size
				);
			}
		}

		// Reset the dirty set
		guard.dirty.clear();

		// Remove cached data that already triggered an alert
		for ip in triggered_for {
			guard.map.remove(&ip);
		}

		// Clean outdated cached data and reduce size if the maximum size exceeded
		guard.map.cleanup();

		tracing::trace!(elements = guard.map.len(), "Total data sizes cache");
	}
}

pub fn ports_activity_analyzer() {
	loop {
		std::thread::sleep(std::time::Duration::from_secs(CONFIG.analyzer.ports_activity.cycle));

		let guard = caches::PORTS_TOUCHED_CACHE.0.lock().unwrap();

		let mut guard = caches::PORTS_TOUCHED_CACHE.1.wait(guard).unwrap();

		tracing::trace!(elements = guard.map.len(), "Ports touched cache");

		let mut triggered_for = Vec::new();

		for ip_set in guard.dirty.iter() {
			let count = guard.map.get_raw(ip_set).unwrap().len();
			if count > CONFIG.analyzer.ports_activity.trigger_count {
				triggered_for.push(ip_set.to_owned());

				tracing::warn!(
					src = ip_set.src.to_string(),
					dst = ip_set.dst.to_string(),
					count,
					"Touching more than {} ports",
					CONFIG.analyzer.ports_activity.trigger_count
				);
			}
		}

		// Reset the dirty set
		guard.dirty.clear();

		// Remove cached data that already triggered an alert
		for ip_set in triggered_for {
			guard.map.remove(&ip_set);
		}

		// Clean outdated cached data and reduce size if the maximum size exceeded
		guard.map.cleanup();

		tracing::trace!(elements = guard.map.len(), "Ports touched cache");
	}
}

pub fn dns_analyzer() {
	loop {
		std::thread::sleep(std::time::Duration::from_secs(CONFIG.analyzer.dns.cycle));

		let guard = caches::DNS_CACHE.0.lock().unwrap();

		let mut guard = caches::DNS_CACHE.1.wait(guard).unwrap();

		let mut triggered_for = Vec::new();

		for (ip, qnames) in guard.map.iter() {
			for domain in &CONFIG.analyzer.dns.malicious_domains {
				if qnames.contains(domain) {
					triggered_for.push(ip.to_owned());

					tracing::warn!(src = ip.to_string(), query_name = domain, "Malicious dns request");
				}
			}
		}

		// Reset the cache
		guard.map.clear();
	}
}
