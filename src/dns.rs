use std::net::SocketAddrV6;
use std::str::FromStr;
use trust_dns::client::{Client, SyncClient};
use trust_dns::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns::rr::dnssec::{Algorithm, KeyPair, Signer};
use trust_dns::rr::rdata::{
    caa::{CAA, KeyValue},
    key::KeyUsage,
    tlsa::{CertUsage, Matching, Selector, TLSA},
    txt::TXT,
};
use trust_dns::udp::UdpClientConnection;
use untrusted::Input;

type Result<T> = std::result::Result<T, Box<std::error::Error>>;

pub struct Zone {
    server: SocketAddrV6,
    zone: Name,
    keypair: Vec<u8>,
}

impl Zone {
    pub fn new(server: &str, origin: &str, keyfile: &str) -> Result<Zone> {
        println!("New DNS zone config");
        let server = server.parse().expect("DNS server address must be `[ipv6]:port`");
        let zone = Name::from_str(origin).unwrap();
        let keypair = std::fs::read(keyfile)?;

        Ok(Zone { server, zone, keypair })
    }
    fn client(&self) -> Result<SyncClient<UdpClientConnection>> {
        println!("New DNS client");
        let ed25519_key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(Input::from(&self.keypair))?;
        let key = KeyPair::from_ed25519(ed25519_key_pair);
        let sig0key = key.to_sig0key_with_usage(Algorithm::ED25519, KeyUsage::Host).unwrap();
        let signer = Signer::sig0(sig0key, key, self.zone.clone());
        let connection = match UdpClientConnection::new(self.server.into()) {
            Ok(v) => v,
            // the trait `std::error::Error` is not implemented for `trust_dns::error::client_error::Error`
            Err(e) => return Err(format!("{:?}", e).into()),
        };

        Ok(SyncClient::with_signer(connection, signer))
    }
    fn create(&self, record: Record) -> Result<()> {
        println!("Creating {}/{}", record.name(), record.record_type());
        match self.client()?.create(record, self.zone.clone())  {
            Ok(v) => println!("ResponseCode: {:?}", v.response_code()),
            Err(e) => return Err(format!("{:?}", e).into()),
        };
        Ok(())
    }
    fn append(&self, record: Record) -> Result<()> {
        println!("Appending {}/{}", record.name(), record.record_type());
        match self.client()?.append(record, self.zone.clone(), false)  {
            Ok(v) => println!("ResponseCode: {:?}", v.response_code()),
            Err(e) => return Err(format!("{:?}", e).into()),
        };
        Ok(())
    }
    fn delete_all(&self, name: Name) -> Result<()> {
        println!("Deleting {}", name.clone());
        match self.client()?.delete_all(name, self.zone.clone(), DNSClass::IN)  {
            Ok(v) => println!("ResponseCode: {:?}", v.response_code()),
            Err(e) => return Err(format!("{:?}", e).into()),
        };
        Ok(())
    }
    fn delete_by_rdata(&self, record: Record) -> Result<()> {
        println!("Deleting by RData {}/{}", record.name(), record.record_type());
        match self.client()?.delete_by_rdata(record, self.zone.clone())  {
            Ok(v) => println!("ResponseCode: {:?}", v.response_code()),
            Err(e) => return Err(format!("{:?}", e).into()),
        };
        Ok(())
    }
    pub fn set_default_caa(&self, domain: &str) -> Result<()> {
        let letsencrypt = Name::from_str("letsencrypt.org").unwrap();
        let name = Name::from_str(domain).unwrap();
        let mut record = Record::with(name, RecordType::CAA, 600);
        record.set_rdata(RData::CAA(
            CAA::new_issue(
                false,
                Some(letsencrypt),
                vec![KeyValue::new("validationmethods", "dns-01")]
            )
        ));
        self.create(record)
    }
    pub fn set_challenge(&self, domain: &str, challenge: &str) -> Result<()> {
        let name = Name::from_str("_acme-challenge").unwrap();
        let name = name.append_name(&Name::from_str(domain).unwrap());
        let mut record = Record::with(name, RecordType::TXT, 60);
        record.set_rdata(RData::TXT(
            TXT::new(vec![challenge.to_string()])
        ));
        self.append(record)
    }
    pub fn clear_challenges(&self, domain: &str) -> Result<()> {
        let name = Name::from_str("_acme-challenge").unwrap();
        let name = name.append_name(&Name::from_str(domain).unwrap());
        self.delete_all(name)
    }
    pub fn append_tlsa(&self, domain: &str, tcp: &[u16], udp: &[u16], tlsa: &[u8]) -> Result<()> {
        let rdata = RData::TLSA(TLSA::new(
            CertUsage::DomainIssued,
            Selector::Spki,
            Matching::Sha256,
            tlsa.to_vec()
        ));
        for port in tcp {
            let name = Name::from_str(&format!("_{}._tcp.{}", port, domain)).unwrap();
            let mut record = Record::with(name, RecordType::TLSA, 60);
            record.set_rdata(rdata.clone());
            self.append(record)?;
        }
        for port in udp {
            let name = Name::from_str(&format!("_{}._udp.{}", port, domain)).unwrap();
            let mut record = Record::with(name, RecordType::TLSA, 60);
            record.set_rdata(rdata.clone());
            self.append(record)?;
        }
        Ok(())
    }
    pub fn clear_tlsa(&self, domain: &str, tcp: &[u16], udp: &[u16]) -> Result<()> {
        for port in tcp {
            let name = Name::from_str(&format!("_{}._tcp.{}", port, domain)).unwrap();
            self.delete_all(name)?;
        }
        for port in udp {
            let name = Name::from_str(&format!("_{}._udp.{}", port, domain)).unwrap();
            self.delete_all(name)?;
        }
        Ok(())
    }
    pub fn delete_tlsa(&self, domain: &str, tcp: &[u16], udp: &[u16], tlsa: &[u8]) -> Result<()> {
        let rdata = RData::TLSA(TLSA::new(
            CertUsage::DomainIssued,
            Selector::Spki,
            Matching::Sha256,
            tlsa.to_vec()
        ));
        for port in tcp {
            let name = Name::from_str(&format!("_{}._tcp.{}", port, domain)).unwrap();
            let mut record = Record::with(name, RecordType::TLSA, 0);
            record.set_rdata(rdata.clone());
            self.delete_by_rdata(record)?;
        }
        for port in udp {
            let name = Name::from_str(&format!("_{}._udp.{}", port, domain)).unwrap();
            let mut record = Record::with(name, RecordType::TLSA, 0);
            record.set_rdata(rdata.clone());
            self.delete_by_rdata(record)?;
        }
        Ok(())
    }
}
