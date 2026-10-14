use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use sha2::{Digest, Sha256};
use usque_geo::{
    ALLOWED_HOSTS, ArtifactKind, ArtifactScope, CountryCode, FetchedBody, GeoDownloader, GeoError,
    GeoIpSet, HttpFetch, MAX_GEOIP_BYTES, MAX_GLOBAL_GEOIP_BYTES, ReqwestFetch, UpdateStatus,
    geoip_cache_path, global_geosite_cache_path, list_cached_countries,
};

const GEOIP_CN: &[u8] = include_bytes!("fixtures/geoip-cn.dat");
const GEOIP_CN_SUM: &str = include_str!("fixtures/geoip-cn.dat.sha256sum");

fn cn() -> CountryCode {
    CountryCode::parse("CN").unwrap()
}

fn us() -> CountryCode {
    CountryCode::parse("US").unwrap()
}

fn geoip_object(country: &str) -> String {
    if country.eq_ignore_ascii_case("cn") {
        format!("{country}.dat")
    } else {
        "geoip.dat".to_owned()
    }
}

fn geoip_dat(host: &str, country: &str) -> String {
    format!(
        "https://{host}/gh/v2fly/geoip@release/{}",
        geoip_object(country)
    )
}

fn geoip_sum(host: &str, country: &str) -> String {
    format!(
        "https://{host}/gh/v2fly/geoip@release/{}.sha256sum",
        geoip_object(country)
    )
}

fn geosite_dat_url(host: &str) -> String {
    format!("https://{host}/gh/v2fly/domain-list-community@release/dlc.dat")
}

fn geosite_sum_url(host: &str) -> String {
    format!("https://{host}/gh/v2fly/domain-list-community@release/dlc.dat.sha256sum")
}

fn append_field(message: &mut Vec<u8>, tag: u8, value: &[u8]) {
    message.push(tag);
    let mut length = value.len();
    while length >= 128 {
        message.push((length as u8 & 127) | 128);
        length >>= 7;
    }
    message.push(length as u8);
    message.extend_from_slice(value);
}

fn aggregate_fixture(us_cidrs: usize) -> Vec<u8> {
    let mut list = GEOIP_CN.to_vec();
    for (country, address, count) in [
        ("US", [203, 0, 113, 0], us_cidrs),
        ("JP", [192, 0, 2, 0], 1),
    ] {
        let mut cidr = Vec::new();
        append_field(&mut cidr, 0x0a, &address);
        cidr.extend_from_slice(&[0x10, 24]);
        let mut entry = Vec::new();
        append_field(&mut entry, 0x0a, country.as_bytes());
        for _ in 0..count {
            append_field(&mut entry, 0x12, &cidr);
        }
        append_field(&mut list, 0x0a, &entry);
    }
    list
}

fn checksum(bytes: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{digest}  geoip.dat\n").into_bytes()
}

fn geosite_fixture() -> Vec<u8> {
    let mut domain = vec![0x08, 0x02];
    append_field(&mut domain, 0x12, b"example.cn");
    let mut site = Vec::new();
    append_field(&mut site, 0x0a, b"geolocation-cn");
    append_field(&mut site, 0x12, &domain);
    let mut list = Vec::new();
    append_field(&mut list, 0x0a, &site);
    list
}

enum MockRoute {
    Ok(Vec<u8>),
    Status(u16),
    TooLarge,
}

struct MockFetch {
    routes: HashMap<String, MockRoute>,
    hits: Mutex<Vec<String>>,
}

impl MockFetch {
    fn new() -> Self {
        Self {
            routes: HashMap::new(),
            hits: Mutex::new(Vec::new()),
        }
    }

    fn with_cn_geoip(mut self) -> Self {
        for host in ALLOWED_HOSTS {
            self.routes
                .insert(geoip_dat(host, "cn"), MockRoute::Ok(GEOIP_CN.to_vec()));
            self.routes.insert(
                geoip_sum(host, "cn"),
                MockRoute::Ok(GEOIP_CN_SUM.as_bytes().to_vec()),
            );
        }
        self
    }

    fn with_aggregate(mut self, dat: &[u8]) -> Self {
        for host in ALLOWED_HOSTS {
            self.routes
                .insert(geoip_dat(host, "us"), MockRoute::Ok(dat.to_vec()));
            self.routes
                .insert(geoip_sum(host, "us"), MockRoute::Ok(checksum(dat)));
        }
        self
    }

    fn with_global_geosite(mut self) -> Self {
        let dat = geosite_fixture();
        let digest = Sha256::digest(&dat);
        let checksum = format!(
            "{}  dlc.dat\n",
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        for host in ALLOWED_HOSTS {
            self.routes
                .insert(geosite_dat_url(host), MockRoute::Ok(dat.clone()));
            self.routes.insert(
                geosite_sum_url(host),
                MockRoute::Ok(checksum.as_bytes().to_vec()),
            );
        }
        self
    }

    fn insert(&mut self, url: String, route: MockRoute) {
        self.routes.insert(url, route);
    }

    fn hits(&self) -> Vec<String> {
        self.hits.lock().expect("hits").clone()
    }

    fn serve(&self, url: &str, max_bytes: usize) -> Result<FetchedBody, GeoError> {
        self.hits.lock().expect("hits").push(url.to_owned());
        match self.routes.get(url) {
            Some(MockRoute::Ok(body)) => {
                if body.len() > max_bytes {
                    return Err(GeoError::PayloadTooLarge(max_bytes));
                }
                Ok(FetchedBody {
                    status: 200,
                    url: url.to_owned(),
                    body: Bytes::from(body.clone()),
                })
            }
            Some(MockRoute::Status(status)) => Ok(FetchedBody {
                status: *status,
                url: url.to_owned(),
                body: Bytes::new(),
            }),
            Some(MockRoute::TooLarge) => Err(GeoError::PayloadTooLarge(max_bytes)),
            None => Ok(FetchedBody {
                status: 404,
                url: url.to_owned(),
                body: Bytes::new(),
            }),
        }
    }
}

impl HttpFetch for MockFetch {
    async fn get_capped(&self, url: &str, max_bytes: usize) -> Result<FetchedBody, GeoError> {
        self.serve(url, max_bytes)
    }
}

struct SharedFetch(Arc<MockFetch>);

impl HttpFetch for SharedFetch {
    async fn get_capped(&self, url: &str, max_bytes: usize) -> Result<FetchedBody, GeoError> {
        tokio::task::yield_now().await;
        self.0.serve(url, max_bytes)
    }
}

#[tokio::test]
async fn downloads_verified_geoip_into_cache_layout() {
    let directory = tempfile::tempdir().unwrap();
    let downloader = GeoDownloader::new(MockFetch::new().with_cn_geoip(), directory.path());
    downloader.download_geoip(&cn()).await.unwrap();
    let cached = std::fs::read(geoip_cache_path(directory.path(), &cn())).unwrap();
    assert_eq!(cached, GEOIP_CN);
}

#[tokio::test]
async fn downloads_verified_global_geosite_catalog() {
    let directory = tempfile::tempdir().unwrap();
    let downloader = GeoDownloader::new(MockFetch::new().with_global_geosite(), directory.path());
    downloader.download_geosite().await.unwrap();
    let cached = std::fs::read(global_geosite_cache_path(directory.path())).unwrap();
    assert_eq!(cached, geosite_fixture());
}

#[tokio::test]
async fn checksum_mismatch_does_not_write() {
    let directory = tempfile::tempdir().unwrap();
    let mut fetch = MockFetch::new();
    for host in ALLOWED_HOSTS {
        fetch.insert(
            geoip_sum(host, "cn"),
            MockRoute::Ok(
                b"0000000000000000000000000000000000000000000000000000000000000000  cn.dat\n"
                    .to_vec(),
            ),
        );
        fetch.insert(geoip_dat(host, "cn"), MockRoute::Ok(GEOIP_CN.to_vec()));
    }
    let downloader = GeoDownloader::new(fetch, directory.path());
    let error = downloader.download_geoip(&cn()).await.unwrap_err();
    assert!(matches!(error, GeoError::ChecksumMismatch));
    assert!(!geoip_cache_path(directory.path(), &cn()).exists());
}

#[tokio::test]
async fn oversize_body_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let mut fetch = MockFetch::new().with_cn_geoip();
    for host in ALLOWED_HOSTS {
        fetch.insert(geoip_dat(host, "cn"), MockRoute::TooLarge);
    }
    let downloader = GeoDownloader::new(fetch, directory.path());
    let error = downloader.download_geoip(&cn()).await.unwrap_err();
    assert!(matches!(error, GeoError::PayloadTooLarge(MAX_GEOIP_BYTES)));
}

#[tokio::test]
async fn http_404_tries_fallbacks_then_fails() {
    let directory = tempfile::tempdir().unwrap();
    let downloader = GeoDownloader::new(MockFetch::new(), directory.path());
    let error = downloader.download_geoip(&cn()).await.unwrap_err();
    assert!(matches!(error, GeoError::GeoIpNotFound(_)));
}

#[tokio::test]
async fn missing_non_cn_geoip_is_a_clear_404() {
    let directory = tempfile::tempdir().unwrap();
    let downloader = GeoDownloader::new(MockFetch::new(), directory.path());
    let error = downloader.download_geoip(&us()).await.unwrap_err();
    assert!(matches!(error, GeoError::GeoIpNotFound(_)));
    assert!(error.to_string().contains("US"));
}

#[tokio::test]
async fn non_cn_download_verifies_extracts_and_reuses_the_aggregate() {
    let directory = tempfile::tempdir().unwrap();
    // A real country payload can exceed the old 2 MiB cap, without a global copy
    // being written into every country's cache file.
    let aggregate = aggregate_fixture(220_000);
    let fetch = Arc::new(MockFetch::new().with_aggregate(&aggregate));
    let downloader = GeoDownloader::new(SharedFetch(Arc::clone(&fetch)), directory.path());
    let us = us();
    let jp = CountryCode::parse("JP").unwrap();
    let (us_result, jp_result) = tokio::join!(
        downloader.download_geoip(&us),
        downloader.download_geoip(&jp),
    );
    us_result.unwrap();
    jp_result.unwrap();
    let selected = std::fs::read(geoip_cache_path(directory.path(), &us)).unwrap();
    assert!(selected.len() > 2 * 1024 * 1024);
    assert!(selected.len() < aggregate.len());
    let rules = GeoIpSet::from_v2ray_dat(&selected, &us).unwrap();
    assert!(rules.contains("203.0.113.1".parse().unwrap()));
    assert!(!rules.contains("1.2.3.1".parse().unwrap()));
    assert!(GeoIpSet::from_v2ray_dat(&selected, &cn()).is_err());
    assert_eq!(
        downloader.update_geoip(&us).await.status,
        UpdateStatus::UpToDate
    );
    let jp_bytes = std::fs::read(geoip_cache_path(directory.path(), &jp)).unwrap();
    assert!(
        GeoIpSet::from_v2ray_dat(&jp_bytes, &jp)
            .unwrap()
            .contains("192.0.2.1".parse().unwrap())
    );
    assert!(jp_bytes.len() < 128);
    assert_eq!(list_cached_countries(directory.path()).unwrap().len(), 2);
    let hits = fetch.hits();
    assert_eq!(
        hits.iter()
            .filter(|url| url.ends_with("/geoip.dat"))
            .count(),
        1
    );
    assert!(hits.iter().all(|url| !url.contains("/dat/")));
    assert!(hits.iter().any(|url| url.ends_with("/geoip.dat.sha256sum")));
}

#[tokio::test]
async fn aggregate_failure_preserves_last_good_country_and_catalog() {
    let aggregate = aggregate_fixture(1);
    for failure in [
        "checksum",
        "truncated",
        "missing_country",
        "oversize",
        "oversize_country",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = geoip_cache_path(directory.path(), &us());
        let good = GeoDownloader::new(
            MockFetch::new().with_aggregate(&aggregate),
            directory.path(),
        );
        good.download_geoip(&us()).await.unwrap();
        let previous = std::fs::read(&path).unwrap();
        let catalog_path = path.parent().unwrap().join("geoip.dat");
        let mut fetch = MockFetch::new();
        let payload = match failure {
            "truncated" => vec![0x0a, 0x10],
            "missing_country" => GEOIP_CN.to_vec(),
            "oversize_country" => aggregate_fixture(MAX_GEOIP_BYTES / 10 + 1),
            _ => aggregate_fixture(2),
        };
        for host in ALLOWED_HOSTS {
            fetch.insert(geoip_sum(host, "us"), MockRoute::Ok(checksum(&payload)));
            fetch.insert(
                geoip_dat(host, "us"),
                match failure {
                    "checksum" => MockRoute::Ok(b"tampered".to_vec()),
                    "oversize" => MockRoute::TooLarge,
                    _ => MockRoute::Ok(payload.clone()),
                },
            );
        }
        let downloader = GeoDownloader::new(fetch, directory.path());
        let error = downloader.download_geoip(&us()).await.unwrap_err();
        match failure {
            "checksum" => assert!(matches!(error, GeoError::ChecksumMismatch)),
            "oversize" => assert!(matches!(
                error,
                GeoError::PayloadTooLarge(MAX_GLOBAL_GEOIP_BYTES)
            )),
            "oversize_country" => {
                assert!(matches!(error, GeoError::PayloadTooLarge(MAX_GEOIP_BYTES)))
            }
            _ => assert!(matches!(error, GeoError::InvalidGeoIp)),
        }
        assert_eq!(std::fs::read(&path).unwrap(), previous, "{failure}");
        assert_eq!(
            std::fs::read(&catalog_path).unwrap(),
            aggregate,
            "{failure}"
        );
    }
}

#[tokio::test]
async fn aggregate_fallback_and_corrupt_cache_are_verified_before_reuse() {
    let directory = tempfile::tempdir().unwrap();
    let mut fetch = MockFetch::new().with_aggregate(&aggregate_fixture(1));
    fetch.insert(geoip_sum(ALLOWED_HOSTS[0], "us"), MockRoute::Status(404));
    fetch.insert(geoip_dat(ALLOWED_HOSTS[0], "us"), MockRoute::Status(503));
    let downloader = GeoDownloader::new(fetch, directory.path());
    downloader.download_geoip(&us()).await.unwrap();
    let path = geoip_cache_path(directory.path(), &us());
    let previous = std::fs::read(&path).unwrap();
    std::fs::write(path.parent().unwrap().join("geoip.dat"), b"corrupt").unwrap();
    let mut unavailable = MockFetch::new();
    for host in ALLOWED_HOSTS {
        unavailable.insert(
            geoip_sum(host, "us"),
            MockRoute::Ok(checksum(&aggregate_fixture(1))),
        );
    }
    let downloader = GeoDownloader::new(unavailable, directory.path());
    assert!(downloader.download_geoip(&us()).await.is_err());
    assert_eq!(std::fs::read(&path).unwrap(), previous);
}

#[tokio::test]
async fn sha256_match_skips_dat_download() {
    let directory = tempfile::tempdir().unwrap();
    let path = geoip_cache_path(directory.path(), &cn());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, GEOIP_CN).unwrap();
    let fetch = Arc::new(MockFetch::new().with_cn_geoip().with_global_geosite());
    let downloader = GeoDownloader::new(SharedFetch(Arc::clone(&fetch)), directory.path());
    let results = downloader.update_cached().await;
    assert_eq!(results.len(), 2);
    let geoip = results
        .iter()
        .find(|result| result.kind == ArtifactKind::GeoIp)
        .unwrap();
    assert_eq!(geoip.status, UpdateStatus::UpToDate);
    assert!(results.iter().any(|result| {
        result.scope == ArtifactScope::Global
            && result.kind == ArtifactKind::GeoSite
            && result.status == UpdateStatus::Updated
    }));
    let hits = fetch.hits();
    assert!(
        hits.iter().any(|url| url.ends_with("cn.dat.sha256sum")),
        "checksum must be fetched: {hits:?}"
    );
    assert!(
        hits.iter().all(|url| !url.ends_with("/cn.dat")),
        "dat must not be fetched when digest matches: {hits:?}"
    );
}

#[tokio::test]
async fn partial_update_failure_keeps_old_file() {
    let directory = tempfile::tempdir().unwrap();
    let cn_path = geoip_cache_path(directory.path(), &cn());
    let us_path = geoip_cache_path(directory.path(), &us());
    std::fs::create_dir_all(cn_path.parent().unwrap()).unwrap();
    std::fs::write(&cn_path, b"stale-cn").unwrap();
    std::fs::write(&us_path, b"stale-us").unwrap();

    let mut fetch = MockFetch::new().with_cn_geoip();
    for host in ALLOWED_HOSTS {
        fetch.insert(geoip_sum(host, "us"), MockRoute::Status(404));
        fetch.insert(geoip_dat(host, "us"), MockRoute::Status(404));
    }
    let downloader = GeoDownloader::new(fetch, directory.path());
    let results = downloader.update_cached().await;
    let cn_result = results
        .iter()
        .find(|result| {
            result.scope == ArtifactScope::Country(cn()) && result.kind == ArtifactKind::GeoIp
        })
        .unwrap();
    let us_result = results
        .iter()
        .find(|result| {
            result.scope == ArtifactScope::Country(us()) && result.kind == ArtifactKind::GeoIp
        })
        .unwrap();
    assert_eq!(cn_result.status, UpdateStatus::Updated);
    assert!(matches!(us_result.status, UpdateStatus::Failed { .. }));
    assert_eq!(std::fs::read(&cn_path).unwrap(), GEOIP_CN);
    assert_eq!(std::fs::read(&us_path).unwrap(), b"stale-us");
}

#[tokio::test]
async fn global_geosite_is_not_country_scoped() {
    let directory = tempfile::tempdir().unwrap();
    let downloader = GeoDownloader::new(MockFetch::new().with_global_geosite(), directory.path());
    downloader.download_geosite().await.unwrap();
    assert!(global_geosite_cache_path(directory.path()).is_file());
}

/// Optional safe live verification; isolated from the application's cache.
#[tokio::test]
#[ignore = "requires public upstream CDN access"]
async fn downloads_live_upstream_country_catalog() {
    let directory = tempfile::tempdir().unwrap();
    let downloader = GeoDownloader::new(ReqwestFetch::new().unwrap(), directory.path());
    for code in ["CN", "US", "JP"] {
        let country = CountryCode::parse(code).unwrap();
        downloader.download_geoip(&country).await.unwrap();
        let bytes = std::fs::read(geoip_cache_path(directory.path(), &country)).unwrap();
        GeoIpSet::from_v2ray_dat(&bytes, &country).unwrap();
        println!("UPSTREAM_GEOIP_OK={code}/{}", bytes.len());
    }
    assert_eq!(list_cached_countries(directory.path()).unwrap().len(), 3);
}
