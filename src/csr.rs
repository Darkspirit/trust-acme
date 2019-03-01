use bcder::{BitString, Ia5String, Mode, OctetString, Oid, Tag, Utf8String};
use bcder::encode::{Constructed, PrimitiveContent, sequence, set, Values};
use bytes::Bytes;
use ring::signature::KeyPair;
use std::str::FromStr;

pub fn generate_csr(key: &[u8], domains: &[&str]) -> Result<(Vec<u8>, Vec<u8>), Box<std::error::Error>> {
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        untrusted::Input::from(key)
    )?;

    let pubkey = key_pair.public_key().as_ref();

    let ecpublickey = oid(&[1, 2, 840, 10045, 2, 1]);
    let secp384r1 = oid(&[1, 3, 132, 0, 34]);
    let ecdsa_with_sha384 = oid(&[1, 2, 840, 10045, 4, 3, 3]);
    let commonname = oid(&[2, 5, 4, 3]);
    let extension_request = oid(&[1, 2, 840, 113549, 1, 9, 14]);
    let subject_alt_name = oid(&[2, 5, 29, 17]);

    let cn = Utf8String::from_str(domains[0]).unwrap();

    let mut san = Vec::new();
    for domain in domains.iter() {
        let dnsname = Ia5String::from_str(domain).unwrap();
        san.push(dnsname.encode_as(Tag::CTX_2));
    }

    let spki = sequence((
        sequence((
            ecpublickey.encode(),
            secp384r1.encode(),
        )),
        BitString::new(0, Bytes::from(pubkey)).encode(),
    ));

    let csrinfo = sequence((
        0_u8.encode(),
        sequence((
            set((
                sequence((
                    commonname.encode(),
                    cn.encode(),
                )),
            )),
        )),
        &spki,
        Constructed::new(Tag::CTX_0, (
            sequence((
                extension_request.encode(),
                set((
                    sequence((
                        sequence((
                            subject_alt_name.encode(),
                            OctetString::encode_wrapped(Mode::Der, (
                                sequence(san),
                            )),
                        )),
                    )),
                )),
            )),
        )),
    ));

    let mut csrinfo_encoded = Vec::new();
    &csrinfo.write_encoded(Mode::Der, &mut csrinfo_encoded)?;
    let rng = ring::rand::SystemRandom::new();
    let signature = key_pair.sign(&rng, untrusted::Input::from(&csrinfo_encoded))?;

    let csr = sequence((
        &csrinfo,
        sequence((
            ecdsa_with_sha384.encode(),
        )),
        BitString::new(0, Bytes::from(signature.as_ref())).encode(),
    ));
    let mut csr_encoded = Vec::new();
    csr.write_encoded(Mode::Der, &mut csr_encoded)?;

    let mut spki_encoded = Vec::new();
    &spki.write_encoded(Mode::Der, &mut spki_encoded)?;
    let tlsa = ring::digest::digest(&ring::digest::SHA256, &spki_encoded).as_ref().to_vec();

    Ok((csr_encoded, tlsa))
}

fn oid(oid: &[u32]) -> Oid<Bytes> {
    let mut bytes = Vec::<u8>::new();
    let mut v = oid.to_vec();
    // learned from https://github.com/alex/rust-asn1
    v[0] = 40 * v[0] + v[1];
    v.remove(1);
    for n in v.iter() {
        if *n == 0 {
            bytes.push(0);
        } else {
            let mut l = 0;
            let mut i = *n;
            while i > 0 {
                l += 1;
                i >>= 7;
            }
            for i in (0..l).rev() {
                let mut b = (*n >> (i * 7)) as u8;
                b &= 0x7f;
                if i != 0 {
                    b |= 0x80;
                }
                bytes.push(b);
            }
        }
    }

    Oid(Bytes::from(bytes))
}
