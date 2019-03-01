#![allow(non_snake_case)]

use reqwest::{Client, StatusCode, header::CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::to_string;

type Result<T> = std::result::Result<T, Box<std::error::Error>>;

pub fn base64url(bytes: &[u8]) -> String {
    base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize)]
struct AcmeMeta {
    termsOfService: Option<String>, // https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf
    website: Option<String>, // https://letsencrypt.org
    caaIdentities: Option<Vec<String>>, // letsencrypt.org
    externalAccountRequired: Option<bool>,
}

// GET https://acme-v02.api.letsencrypt.org/directory
#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize)]
struct AcmeDirectory {
    newNonce: String, // https://acme-v02.api.letsencrypt.org/acme/new-nonce
    newAccount: String, // https://acme-v02.api.letsencrypt.org/acme/new-acct
    newOrder: String, // https://acme-v02.api.letsencrypt.org/acme/new-order
    newAuthz: Option<String>, // https://example.com/acme/new-authz
    revokeCert: String, // https://acme-v02.api.letsencrypt.org/acme/revoke-cert
    keyChange: String, // https://acme-v02.api.letsencrypt.org/acme/key-change
    meta: Option<AcmeMeta>,
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize)]
struct AcmeAccount {
    status: String, // valid, deactivated, revoked
    contact: Option<Vec<String>>, // mailto:hostmaster@example.com
    termsOfServiceAgreed: Option<bool>, // true
    #[serde(skip_deserializing)]
    orders: String, // https://example.com/acme/acct/evOfKhNU60wg/orders
}

#[derive(Debug, Serialize, Deserialize)]
struct AcmeIdentifier {
    r#type: String, // dns
    value: String, // can be *.example.com within an Order, but is example.com within a wildcard Authorization.
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeError {
    r#type: String, // urn:ietf:params:acme:error:dns
    detail: String, // DNS problem: SERVFAIL looking up CAA for www2.example.com
    status: u16, // 400
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize)]
struct AcmeOrder {
    status: String, // pending, ready, processing, valid, invalid
    expires: Option<String>, // 2015-03-01T14:09:07.99Z, RFC 3339 format, required for status "pending" and "valid"
    identifiers: Vec<AcmeIdentifier>,
    notBefore: Option<String>, // 2016-01-01T00:00:00Z, RFC 3339 format
    notAfter: Option<String>, // 2016-01-08T00:00:00Z, RFC 3339 format
    error: Option<AcmeError>, // problem document: RFC 7807
    authorizations: Vec<String>, // https://example.com/acme/authz/PAniVnsZcis
    finalize: String, // https://example.com/acme/order/TOlocE8rfgo/finalize
    certificate: Option<String>, // https://example.com/acme/cert/jWCdfHVGY2M
}

#[derive(Debug, Serialize, Deserialize)]
struct AcmeChallenge {
    url: String, // https://example.com/acme/chall/prV_B7yEyA4
    r#type: String, // dns-01, http-01
    status: String, // pending, processing, valid, invalid
    validated: Option<String>, // 2014-12-01T12:05:58.16Z, RFC 3339 format
    error: Option<AcmeError>, // problem document: RFC 7807
    token: String, // at least 128 bits of entropy, randomness RFC 4086, as base64url, but without base64 padding characters ("=")
}

#[derive(Debug, Serialize, Deserialize)]
struct AcmeAuthorization {
    identifier: AcmeIdentifier,
    status: String, // pending, valid, invalid, deactivated, expired, revoked
    expires: Option<String>, // 2015-03-01T14:09:07.99Z, RFC 3339 format, required for status "valid"
    challenges: Vec<AcmeChallenge>,
    wildcard: Option<bool>, // true, if identifier.value counts as wildcard domain "example.com"
}

// alphabetical order is required for jwk thumbprint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub crv: String, // P-384
    pub kty: String, // EC
    pub x: String, // base64url(x)
    pub y: String, // base64url(y)
}
impl Jwk {
    pub fn from_key(ring_ecdsa_p384_keypair: &[u8]) -> Result<Jwk> {
        let mut k = ring_ecdsa_p384_keypair.to_vec();
        if k.len() < 96 { return Err("Jwk: Congratulation. Key is horribly malformed".into()); }
        let mut y = k.split_off(k.len()-48);
        let mut x = k.split_off(k.len()-48);
        while x[0] == 0 { x.remove(0); }
        while y[0] == 0 { y.remove(0); }

        Ok(Jwk {
            crv: "P-384".to_owned(),
            kty: "EC".to_owned(),
            x: base64url(&x),
            y: base64url(&y),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JwsHeader {
    // for newAccount, and revokeCert by cert key
    Jwk {
        alg: String, // ES384
        jwk: Jwk,
        nonce: String,
        url: String, // https://acme-v02.api.letsencrypt.org/acme/new-acct or revoke-cert
    },
    // for everything else, and revokeCert by account url
    Kid {
        alg: String, // ES384
        kid: String, // Account URL
        nonce: String,
        url: String,
    },
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum JwsPayload {
    NewAccount {
        #[serde(skip_serializing_if = "Option::is_none")]
        contact: Option<Vec<String>>, // mailto:hostmaster@example.com
        #[serde(skip_serializing_if = "Option::is_none")]
        termsOfServiceAgreed: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        onlyReturnExisting: Option<bool>, // if true, the server won't create new account if one does not already exist.  This allows a client to look up an account URL based on an account key
        #[serde(skip_serializing_if = "Option::is_none")]
        externalAccountBinding: Option<String>,
    },
    KeyChange(Jws),
    KeyChangeInner {
        account: String, // Account url
        oldKey: Jwk,
    },
    // deactiviate Account or Authorization
    Deactivate {
        status: String, // deactivated
    },
    NewOrder {
        identifiers: Vec<AcmeIdentifier>,
        #[serde(skip_serializing_if = "Option::is_none")]
        notBefore: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        notAfter: Option<String>,
    },
    Finalize {
        csr: String,
    },
    NewAuthz {
        identifier: AcmeIdentifier,
    },
    RevokeCert {
        certificate: String, // base64url-encoded version of cert in DER format.
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<u8>, // reasonCode from https://tools.ietf.org/html/rfc5280#section-5.3.1
    },
    EmptyJSON,
    None,
}

#[derive(Debug, Serialize, Deserialize)]
struct Jws {
    protected: String, // base64url(JwsHeader)
    payload: String, // base64url(JwsPayload)
    signature: String, // base64url(signature(format!("{}.{}", protected, payload)))
}
impl Jws {
    fn create(h: JwsHeader, p: JwsPayload, key: &[u8]) -> Result<Jws> {
        let protected = base64url(&to_string(&h)?.into_bytes());
        let payload = match p {
            JwsPayload::None => "".to_owned(),
            _ => base64url(&to_string(&p)?.into_bytes()),
        };
        let signature = {
            let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
                &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                untrusted::Input::from(key)
            )?;
            let content = &format!("{}.{}", protected, payload).into_bytes();
            let rng = ring::rand::SystemRandom::new();
            let sig = key_pair.sign(&rng, untrusted::Input::from(&content))?;

            base64url(sig.as_ref())
        };

        Ok(Jws { protected, payload, signature })
    }
}

pub struct Directory {
    inner: AcmeDirectory,
    url: String,
}

pub struct Account<'a> {
    inner: AcmeAccount,
    directory: Directory,
    key: &'a [u8],
    jwk: Jwk,
    url: String,
}

pub struct Order<'a> {
    inner: AcmeOrder,
    account: &'a Account<'a>,
    url: String,
}

pub struct Authorization<'a> {
    inner: AcmeAuthorization,
    order: &'a Order<'a>,
    url: String,
    challenge_url: String,
    challenge_token: String,
}

impl Directory {
    pub fn from_url(url: &str) -> Result<Directory> {
        let mut res = Client::new().get(url).send()?;
        if res.status() == StatusCode::OK {
            let directory: AcmeDirectory = res.json()?;

            Ok(Directory {
                inner: directory,
                url: url.to_owned(),
            })
        } else {
            Err("Not a functional ACMEv2 directory".into())
        }
    }
    fn get_nonce(&self) -> Result<String> {
        let res = Client::new().head(&self.inner.newNonce).send()?;
        let string: Result<String> = res.headers()
            .get("Replay-Nonce")
            .ok_or("Replay-Nonce header not found".into())
            .and_then(|nonce| nonce.to_str().map(|s| s.to_string()).map_err(|e| e.into()));

        Ok(string?)
    }
    pub fn register<'a>(self, key: &'a [u8], email: &str) -> Result<Account<'a>> {
        println!("Registering account");
        let jwk = Jwk::from_key(&key)?;
        let jws = Jws::create(
            JwsHeader::Jwk {
                alg: "ES384".to_owned(),
                jwk: jwk.clone(),
                nonce: self.get_nonce()?,
                url: self.inner.newAccount.clone(),
            },
            JwsPayload::NewAccount {
                contact: Some(vec![format!("mailto:{}", email)]),
                termsOfServiceAgreed: Some(true),
                onlyReturnExisting: None,
                externalAccountBinding: None,
            },
            &key,
        )?;
        let mut res = Client::new()
            .post(&self.inner.newAccount)
            .json(&jws)
            .header(CONTENT_TYPE, "application/jose+json")
            .send()?;

        match res.status() {
            StatusCode::CREATED | StatusCode::OK => {
                let location: Result<String> = res.headers()
                    .get("Location")
                    .ok_or("account location header not found".into())
                    .and_then(|location| location.to_str().map(|s| s.to_string()).map_err(|e| e.into()));
                let url = location?;
                let account: AcmeAccount = res.json()?;

                Ok(Account { inner: account, directory: self, key, jwk, url})
            },
            _ => {
                Err(AcmeErr(res.json()?).into())
            },
        }
    }
}

impl<'a> Account<'a> {
    pub fn order(&'a self, domains: &[&str]) -> Result<Order<'a>> {
        println!("New order");
        let mut identifiers = Vec::<AcmeIdentifier>::new();
        for domain in domains.iter() {
            identifiers.push(AcmeIdentifier { r#type: "dns".to_owned(), value: domain.to_string(), });
        }
        let jws = Jws::create(
            JwsHeader::Kid {
                alg: "ES384".to_owned(),
                kid: self.url.to_owned(),
                nonce: self.directory.get_nonce()?.to_owned(),
                url: self.directory.inner.newOrder.clone(),
            },
            JwsPayload::NewOrder {
                identifiers,
                notBefore: None,
                notAfter: None,
            },
            &self.key,
        )?;
        let mut res = Client::new()
            .post(&self.directory.inner.newOrder)
            .json(&jws)
            .header(CONTENT_TYPE, "application/jose+json")
            .send()?;

        if res.status() == StatusCode::CREATED {
            let location: Result<String> = res.headers()
                .get("Location")
                .ok_or("order location header not found".into())
                .and_then(|location| location.to_str().map(|s| s.to_string()).map_err(|e| e.into()));
            let url = location?;
            let order: AcmeOrder = res.json()?;
            println!("order: {:?}", &order);
            Ok(Order { inner: order, account: self, url })
        } else {
            Err(AcmeErr(res.json()?).into())
        }
    }
}

impl<'a> Order<'a> {
    pub fn get_authorizations(&self) -> Result<Vec<Authorization>> {
        println!("get authorizations");
        let mut authorizations = Vec::<Authorization>::new();
        for url in self.inner.authorizations.iter() {
            let jws = Jws::create(
                JwsHeader::Kid {
                    alg: "ES384".to_owned(),
                    kid: self.account.url.to_owned(),
                    nonce: self.account.directory.get_nonce()?.to_owned(),
                    url: url.clone(),
                },
                JwsPayload::None,
                &self.account.key,
            )?;
            let mut res = Client::new()
                .post(url)
                .json(&jws)
                .header(CONTENT_TYPE, "application/jose+json")
                .send()?;

            if res.status() == StatusCode::OK {
                let authz: AcmeAuthorization = res.json()?;
                let mut challenge_url = "".to_owned();
                let mut challenge_token = "".to_owned();
                for chall in authz.challenges.iter() {
                    if chall.r#type == "dns-01".to_owned() {
                        println!("dns challenge: {:?}", &chall);
                        challenge_url = chall.url.clone();
                        challenge_token = chall.token.clone();
                    }
                };
                authorizations.push(Authorization { inner: authz, order: self, url: url.to_owned(), challenge_url, challenge_token });
            } else {
                return Err(AcmeErr(res.json()?).into());
            }
        }
        Ok(authorizations)
    }
    pub fn poll_status(&mut self) -> Result<bool> {
        println!("poll order status");
        let jws = Jws::create(
            JwsHeader::Kid {
                alg: "ES384".to_owned(),
                kid: self.account.url.to_owned(),
                nonce: self.account.directory.get_nonce()?.to_owned(),
                url: self.url.clone(),
            },
            JwsPayload::None,
            &self.account.key,
        )?;
        let mut res = Client::new()
            .post(&self.url)
            .json(&jws)
            .header(CONTENT_TYPE, "application/jose+json")
            .send()?;

        if res.status() == StatusCode::OK {
            let order: AcmeOrder = res.json()?;
            self.inner = order;
            match self.inner.status.as_ref() {
                "pending" => Ok(false),
                "processing" => Ok(false),
                "invalid" => {
                    Err(AcmeErr(res.json()?).into())
                },
                "valid" => Ok(false),
                "ready" => Ok(true),
                _ => Err("Unrecognized order status".into()),
            }
        } else {
            Err(AcmeErr(res.json()?).into())
        }
    }
    pub fn finalize(&mut self, csr: &[u8]) -> Result<()> {
        println!("finalize");
        let jws = Jws::create(
            JwsHeader::Kid {
                alg: "ES384".to_owned(),
                kid: self.account.url.to_owned(),
                nonce: self.account.directory.get_nonce()?.to_owned(),
                url: self.inner.finalize.clone(),
            },
            JwsPayload::Finalize {
                csr: base64url(csr),
            },
            &self.account.key,
        )?;
        let mut res = Client::new()
            .post(&self.inner.finalize)
            .json(&jws)
            .header(CONTENT_TYPE, "application/jose+json")
            .send()?;

        if res.status() == StatusCode::OK {
            let order: AcmeOrder = res.json()?;
            self.inner = order;
            Ok(())
        } else {
            Err(AcmeErr(res.json()?).into())
        }
    }
    pub fn get_cert(&self) -> Result<Option<String>> {
        println!("get cert");
        if self.inner.status == "valid".to_owned() {
            if let Some(cert_url) = &self.inner.certificate {
                let jws = Jws::create(
                    JwsHeader::Kid {
                        alg: "ES384".to_owned(),
                        kid: self.account.url.to_owned(),
                        nonce: self.account.directory.get_nonce()?.to_owned(),
                        url: cert_url.clone(),
                    },
                    JwsPayload::None,
                    &self.account.key,
                )?;
                let mut res = Client::new()
                    .post(&cert_url.to_string())
                    .json(&jws)
                    .header(CONTENT_TYPE, "application/jose+json")
                    .send()?;
                if res.status() == StatusCode::OK {
                    let cert = res.text()?;
                    Ok(Some(cert))
                } else {
                    Err("Problem downloading certificate".into())
                }
            } else {
                Err("Order is valid, but there is no certificate url".into())
            }
        } else {
            Ok(None)
        }
    }
}

impl<'a> Authorization<'a> {
    pub fn name(&self) -> String {
        self.inner.identifier.value.clone()
    }
    pub fn key_authorization(&self) -> Result<String> {
        let token = self.challenge_token.to_owned();
        let jwk_thumbprint = base64url(
            ring::digest::digest(&ring::digest::SHA256, &to_string(&self.order.account.jwk.clone())?.as_bytes()).as_ref()
        );
        let key_authorization = format!("{}.{}", token, jwk_thumbprint);
        println!("key_authorization: {:?}", &key_authorization);
        let dns_key_authorization = base64url(
            ring::digest::digest(&ring::digest::SHA256, key_authorization.as_bytes()).as_ref()
        );
        println!("dns_key_authorization: {:?}", &dns_key_authorization);
        Ok(dns_key_authorization)
    }
    pub fn validate(&self) -> Result<()> {
        println!("validating authorization");

        let jws = Jws::create(
            JwsHeader::Kid {
                alg: "ES384".to_owned(),
                kid: self.order.account.url.to_owned(),
                nonce: self.order.account.directory.get_nonce()?.to_owned(),
                url: self.challenge_url.clone(),
            },
            JwsPayload::EmptyJSON,
            &self.order.account.key,
        )?;
        let mut res = Client::new()
            .post(&self.challenge_url)
            .json(&jws)
            .header(CONTENT_TYPE, "application/jose+json")
            .send()?;

        if res.status() == StatusCode::OK {
            let challenge: AcmeChallenge = res.json()?;
            println!("{:?}", challenge);
            Ok(())
        } else {
            Err(AcmeErr(res.json()?).into())
        }
    }
    pub fn poll_status(&mut self) -> Result<bool> {
        println!("poll authz status");

        let jws = Jws::create(
            JwsHeader::Kid {
                alg: "ES384".to_owned(),
                kid: self.order.account.url.to_owned(),
                nonce: self.order.account.directory.get_nonce()?.to_owned(),
                url: self.url.clone(),
            },
            JwsPayload::None,
            &self.order.account.key,
        )?;
        let mut res = Client::new()
            .post(&self.url)
            .json(&jws)
            .header(CONTENT_TYPE, "application/jose+json")
            .send()?;

        if res.status() == StatusCode::OK {
            let authz: AcmeAuthorization = res.json()?;
            println!("poll authz response: {:?}", &authz);
            match authz.status.as_ref() {
                "pending" => Ok(false),
                "processing" => Ok(false),
                "invalid" => {
                    Err("Invalid challenge".into())
                },
                "valid" => Ok(true),
                _ => Err("Unrecognized challenge status".into()),
            }
        } else {
            Err(AcmeErr(res.json()?).into())
        }
    }
}

#[derive(Debug)]
struct AcmeErr(AcmeError);
impl std::fmt::Display for AcmeErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(std::error::Error::description(self))
    }
}
// For example, if we used ASN1 instead of FIXED signing:
// Error: AcmeErr(AcmeError { type: "urn:ietf:params:acme:error:malformed", detail: "JWS verification error", status: 400 })
impl std::error::Error for AcmeErr {}
