use std::sync::LazyLock;

pub static CONFIG: LazyLock<Config> = LazyLock::new(|| {
	let file = std::env::args().nth(1).expect("Config file wasn't given as a cli arg");
	tracing::info!(file, "Reading config file");
	let config = toml::from_str(&std::fs::read_to_string(file).unwrap_or_default()).unwrap();
	tracing::info!(?config, "Loaded config");
	config
});

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct Config {
	pub interface: Interface,
	pub cache: Cache,
	pub analyzer: Analyzer,
}

#[derive(Debug, serde::Deserialize)]
#[serde(default)]
pub struct Interface {
	pub read_buffer_size: usize,
}

impl Default for Interface {
	fn default() -> Self {
		Self { read_buffer_size: 4096 }
	}
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct Cache {
	pub queue_channel_bound: usize,
	pub total_data_size: TotalDataSizeCacheConfig,
	pub ports_touched: PortsTouchedCacheConfig,
	pub tcp_syn_flood: TcpSynFloodCacheConfig,
}

#[derive(Debug, serde::Deserialize)]
pub struct TotalDataSizeCacheConfig {
	#[serde(default)]
	pub entiry_ttl: u64,
	pub max_size: Option<usize>,
}

impl Default for TotalDataSizeCacheConfig {
	fn default() -> Self {
		Self {
			entiry_ttl: 13,
			max_size: Some(30),
		}
	}
}

#[derive(Debug, serde::Deserialize)]
pub struct PortsTouchedCacheConfig {
	#[serde(default)]
	pub entiry_ttl: u64,
	pub max_size: Option<usize>,
}

impl Default for PortsTouchedCacheConfig {
	fn default() -> Self {
		Self {
			entiry_ttl: 13,
			max_size: Some(30),
		}
	}
}

#[derive(Debug, serde::Deserialize)]
pub struct TcpSynFloodCacheConfig {
	#[serde(default)]
	pub entiry_ttl: u64,
	pub max_size: Option<usize>,
}

impl Default for TcpSynFloodCacheConfig {
	fn default() -> Self {
		Self {
			entiry_ttl: 13,
			max_size: Some(30),
		}
	}
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct Analyzer {
	pub uploaded_data_sizes: UploadedDataSizesAnalyzerConfig,
	pub ports_activity: PortsActivityAnalyzerConfig,
	pub dns: DnsAnalyzerConfig,
	pub tcp_syn_flood: TcpSynFloodAnalyzerConfig,
}

#[derive(Debug, serde::Deserialize)]
pub struct UploadedDataSizesAnalyzerConfig {
	#[serde(default)]
	pub cycle: u64,
	pub trigger_size: u32,
}

impl Default for UploadedDataSizesAnalyzerConfig {
	fn default() -> Self {
		Self {
			cycle: 5,
			trigger_size: 5000000,
		}
	}
}

#[derive(Debug, serde::Deserialize)]
pub struct PortsActivityAnalyzerConfig {
	#[serde(default)]
	pub cycle: u64,
	pub trigger_count: usize,
}

impl Default for PortsActivityAnalyzerConfig {
	fn default() -> Self {
		Self {
			cycle: 5,
			trigger_count: 20,
		}
	}
}

#[derive(Debug, serde::Deserialize)]
pub struct DnsAnalyzerConfig {
	#[serde(default)]
	pub cycle: u64,
	pub malicious_domains: Vec<String>,
}

impl Default for DnsAnalyzerConfig {
	fn default() -> Self {
		Self {
			cycle: 1,
			malicious_domains: vec!["google.com".to_owned(), "gmail.com".to_owned()],
		}
	}
}

#[derive(Debug, serde::Deserialize)]
pub struct TcpSynFloodAnalyzerConfig {
	#[serde(default)]
	pub cycle: u64,
	pub trigger_count: u32,
}

impl Default for TcpSynFloodAnalyzerConfig {
	fn default() -> Self {
		Self {
			cycle: 5,
			trigger_count: 50,
		}
	}
}
