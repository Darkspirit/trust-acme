mod acme;
mod config;
mod csr;
mod dns;

fn main() -> Result<(), Box<std::error::Error>> {
    let config_path = match std::env::var("USER").unwrap().as_str() {
        "root" => "/etc/trust-acme",
        _ => "config",
    };

    let cfg = config::Config::from_file(&format!("{}/config.toml", &config_path))?;

    let dns = &cfg.trustdns.ok_or("config: missing trustdns section")?;
    let trustdns = &dns.get("default").ok_or("config: missing default trustdns")?;

    let ca = &cfg.ca.ok_or("config: missing ca section")?;
    let letsencrypt = &ca.get("letsencrypt").ok_or("config: missing letsencrypt within ca")?;

    let account_key = std::fs::read(&letsencrypt.account_key)?;

    if let Some(v) = cfg.cert {
        for cert in v.iter() {
            let zone = dns::Zone::new(&trustdns.server, &cert.zone, &trustdns.auth_key)?;

            let mut san = Vec::<&str>::new();
            for domain in cert.san.iter() {
                san.push(&domain.name);
                zone.set_default_caa(&domain.name);
            }
            println!("san: {:?}", san);

            let rng = ring::rand::SystemRandom::new();
            let keypair = &ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                &rng
            )?;
            let cert_key = keypair.as_ref();

            let (csr, tlsa) = csr::generate_csr(&cert_key, &san)?;

            let directory = acme::Directory::from_url(letsencrypt.directory())?;
            let account = directory.register(&account_key, &letsencrypt.account_email)?;

            let mut order = account.order(&san)?;
            let mut failed = false;

            for authorization in order.get_authorizations()?.iter_mut() {
                zone.set_challenge(&authorization.name(), &authorization.key_authorization()?)?;

                std::thread::sleep(std::time::Duration::from_secs(5));
                authorization.validate()?;

                let mut tries = 0;
                let mut done = false;
                while !done {
                    if tries < 6 {
                        tries += 1;
                        std::thread::sleep(std::time::Duration::from_secs(5));
                        done = authorization.poll_status()?;
                    } else {
                        done = true;
                        failed = true;
                    }
                }
                zone.clear_challenges(&authorization.name())?;
            }
            if !failed {
                let mut tries = 0;
                let mut done = false;
                while !done {
                    if tries < 6 {
                        tries += 1;
                        std::thread::sleep(std::time::Duration::from_secs(5));
                        done = order.poll_status()?;
                    } else {
                        done = true;
                        failed = true;
                    }
                }
            }
            if !failed {
                order.finalize(&csr)?;
                if let Some(certificate) = order.get_cert()? {
                    println!("{:?}", &certificate);

                    let cert_path = format!("{}/certs/{}.crt", &config_path, &cert.san[0].name);
                    std::fs::write(cert_path, certificate)?;

                    let key_path = format!("{}/certs/{}.pk8", &config_path, &cert.san[0].name);
                    std::fs::write(key_path, &cert_key)?;

                    if let Some(true) = cert.pem_key {
                        let b64 = base64::encode(&cert_key);
                        let pem: String = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----", b64);
                        let pem_key_path = format!("{}/certs/{}.key", &config_path, &cert.san[0].name);
                        std::fs::write(pem_key_path, pem)?;
                        println!("Saved your key additionally as a PEM file. Switch to Rustls soon!");
                    }

                    // kittens die iteratively
                    for domain in cert.san.iter() {
                        zone.clear_tlsa(&domain.name, domain.tcp(), domain.udp());
                        zone.append_tlsa(&domain.name, domain.tcp(), domain.udp(), &tlsa);
                    }
                    // Mischief managed

                    if let Some(reload) = &cert.reload {
                        for service in reload.iter() {
                            println!("Reloading service: {}", &service);
                            std::process::Command::new("sudo").args(&["systemctl", "reload", service]).output()?;
                        }
                    }
                } else {
                    println!("No cert for us.");
                }
            }
        }
    }
    Ok(())
}
