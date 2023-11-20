use criterion::{criterion_group, criterion_main, Criterion};
use libsignal_protocol::skem::{self, KeyType};
use std::hint::black_box;

fn bench_skem(c: &mut Criterion) {
    for key_type in [KeyType::Frodokexp] {
        for store_matrix in [true, false] {
            c.bench_function(
                format!(
                    "{key_type:?}, store_matrix = {store_matrix:?}: Generate Public Parameters"
                )
                .as_str(),
                |b| {
                    b.iter(|| {
                        black_box(skem::PublicParameters::generate(key_type, store_matrix));
                    });
                },
            );

            let pp = skem::PublicParameters::generate(key_type, store_matrix);
            c.bench_function(
                format!("{key_type:?}, store_matrix = {store_matrix:?}: Generate a/encapsulator")
                    .as_str(),
                |b| {
                    b.iter(|| {
                        black_box(skem::Encapsulator::generate_key_pair(key_type, &pp));
                    });
                },
            );
            c.bench_function(
                format!("{key_type:?}, store_matrix = {store_matrix:?}: Generate b/decapsulator")
                    .as_str(),
                |b| {
                    b.iter(|| {
                        black_box(skem::Decapsulator::generate_key_pair(key_type, &pp));
                    });
                },
            );

            let keys_encapsulator: Vec<_> =
                std::iter::from_fn(|| Some(skem::Encapsulator::generate_key_pair(key_type, &pp)))
                    .take(10)
                    .collect();
            let keys_decapsulator: Vec<_> =
                std::iter::from_fn(|| Some(skem::Decapsulator::generate_key_pair(key_type, &pp)))
                    .take(10)
                    .collect();
            let mut public_keys = keys_decapsulator
                .iter()
                .map(|kp| &kp.public_key_mat)
                .cycle();
            let mut encap_pub_keys = keys_encapsulator
                .iter()
                .map(|kp| &kp.public_key_mat)
                .cycle();
            let mut encap_sec_keys = keys_encapsulator
                .iter()
                .map(|kp| &kp.secret_key_mat)
                .cycle();
            c.bench_function(
                format!("{key_type:?}, store_matrix = {store_matrix:?}: Encapsulate").as_str(),
                |b| {
                    b.iter(|| {
                        black_box(public_keys.next().unwrap().encapsulate(
                            encap_pub_keys.next().unwrap(),
                            encap_sec_keys.next().unwrap(),
                        ));
                    });
                },
            );

            // Prepare for decapsulation -> get encaps data again
            let public_keys = keys_decapsulator
                .iter()
                .map(|kp| &kp.public_key_mat)
                .cycle();
            let mut encap_pub_keys = keys_encapsulator
                .iter()
                .map(|kp| &kp.public_key_mat)
                .cycle();
            let mut encap_sec_keys = keys_encapsulator
                .iter()
                .map(|kp| &kp.secret_key_mat)
                .cycle();
            let mut ct_tag_tuples = public_keys.map(|pk| {
                let (_ss, ct, tag) = pk.encapsulate(
                    encap_pub_keys.next().unwrap(),
                    encap_sec_keys.next().unwrap(),
                );
                (ct, tag)
            });

            let mut my_sec_keys = keys_decapsulator
                .iter()
                .map(|kp| &kp.secret_key_mat)
                .cycle();
            let mut my_pub_keys = keys_decapsulator
                .iter()
                .map(|kp| &kp.public_key_mat)
                .cycle();
            let mut encap_pub_keys = keys_encapsulator
                .iter()
                .map(|kp| &kp.public_key_mat)
                .cycle();

            c.bench_function(
                format!("{key_type:?}, store_matrix = {store_matrix:?}: Decapsulate").as_str(),
                |b| {
                    b.iter(|| {
                        let (ct, tag) = ct_tag_tuples.next().unwrap();
                        black_box(
                            my_sec_keys
                                .next()
                                .unwrap()
                                .decapsulate(
                                    my_pub_keys.next().unwrap(),
                                    encap_pub_keys.next().unwrap(),
                                    &ct,
                                    &tag,
                                )
                                .expect("Decapulation should work in bench"),
                        );
                    });
                },
            );
        }
    }
}

criterion_group!(benches, bench_skem);
criterion_main!(benches);
