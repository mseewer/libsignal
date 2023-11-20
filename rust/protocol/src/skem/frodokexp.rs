extern crate pqcrypto_frodokexp;

use super::{
    FSecretKey, KeyMaterial, KeyType, PublicKey, PublicKeyMaterial, PublicParameters, SecretKey,
    SecretKeyMaterial, SharedSecret,
};

use pqcrypto_frodokexp::ffi::{
    CIPHERTEXT_SIZE_BYTES, PUBLIC_KEY_P_MATRIX_ELEMENTS, PUBLIC_KEY_P_MATRIX_SIZE_BYTES,
    PUBLIC_PARAMETER_MATRIX_ELEMENTS, PUBLIC_PARAMETER_MATRIX_SIZE_BYTES,
    SECRET_KEY_F_MATRIX_ELEMENTS, SECRET_KEY_F_SIZE_BYTES, SECRET_KEY_S_MATRIX_ELEMENTS,
    SECRET_KEY_S_MATRIX_SIZE_BYTES, SEED_SIZE_BYTES, SHARED_SECRET_SIZE_BYTES, TAG_SIZE_BYTES,
};

pub(crate) struct Parameters;

impl super::Parameters for Parameters {
    const PUBLIC_PARAMETER_MATRIX_SIZE_BYTES: usize = PUBLIC_PARAMETER_MATRIX_SIZE_BYTES;
    const PUBLIC_KEY_P_MATRIX_SIZE_BYTES: usize = PUBLIC_KEY_P_MATRIX_SIZE_BYTES;
    const SECRET_KEY_S_MATRIX_SIZE_BYTES: usize = SECRET_KEY_S_MATRIX_SIZE_BYTES;
    const SECRET_KEY_F_SIZE_BYTES: usize = SECRET_KEY_F_SIZE_BYTES;
    const SHARED_SECRET_SIZE_BYTES: usize = SHARED_SECRET_SIZE_BYTES;
    const CIPHERTEXT_SIZE_BYTES: usize = CIPHERTEXT_SIZE_BYTES;
    const TAG_SIZE_BYTES: usize = TAG_SIZE_BYTES;
    const SEED_SIZE_BYTES: usize = SEED_SIZE_BYTES;

    fn generate_public_parameters(store_matrix: bool) -> PublicParameters {
        let mut seed = Box::new([0; SEED_SIZE_BYTES]);
        let my_public_matrix: Option<Box<[i32]>>;
        let my_public_matrix_transpose: Option<Box<[i32]>>;

        if store_matrix {
            let mut matrix_a = vec![0; PUBLIC_PARAMETER_MATRIX_ELEMENTS];
            let mut matrix_a_transpose = vec![0; PUBLIC_PARAMETER_MATRIX_ELEMENTS];
            pqcrypto_frodokexp::frodokexp::frodokexp_gen_pp_store(
                seed.as_mut_ptr(),
                matrix_a.as_mut_ptr(),
                matrix_a_transpose.as_mut_ptr(),
            );
            my_public_matrix = Some(matrix_a.into_boxed_slice());
            my_public_matrix_transpose = Some(matrix_a_transpose.into_boxed_slice());
        } else {
            pqcrypto_frodokexp::frodokexp::frodokexp_gen_pp(seed.as_mut_ptr());
            my_public_matrix = None;
            my_public_matrix_transpose = None;
        }
        PublicParameters {
            seed: seed,
            store_matrix: store_matrix,
            public_matrix: my_public_matrix,
            public_matrix_transpose: my_public_matrix_transpose,
        }
    }

    fn generate_encapsulator(pp: &PublicParameters) -> (PublicKeyMaterial, SecretKeyMaterial) {
        let mut sk_out = Box::new([0; SECRET_KEY_S_MATRIX_ELEMENTS]);
        let mut f_out = Box::new([0; SECRET_KEY_F_MATRIX_ELEMENTS]);
        let mut pk_out = Box::new([0; PUBLIC_KEY_P_MATRIX_ELEMENTS]);

        if pp.store_matrix {
            pqcrypto_frodokexp::frodokexp::frodokexp_gen_b_store(
                pp.public_matrix_transpose.as_ref().unwrap().as_ptr(),
                sk_out.as_mut_ptr(),
                f_out.as_mut_ptr(),
                pk_out.as_mut_ptr(),
            );
        } else {
            pqcrypto_frodokexp::frodokexp::frodokexp_gen_b(
                pp.seed.as_ptr(),
                sk_out.as_mut_ptr(),
                f_out.as_mut_ptr(),
                pk_out.as_mut_ptr(),
            );
        }
        let pub_key_material = PublicKeyMaterial {
            key_type: KeyType::Frodokexp,
            b_mat: PublicKey {
                key_type: KeyType::Frodokexp,
                key_data: KeyMaterial::new_from_integers(pk_out),
            },
        };
        let sec_key_material = SecretKeyMaterial {
            key_type: KeyType::Frodokexp,
            s_mat: SecretKey {
                key_type: KeyType::Frodokexp,
                key_data: KeyMaterial::new_from_integers(sk_out),
            },
            f_mat: FSecretKey {
                key_type: KeyType::Frodokexp,
                key_data: KeyMaterial::new_from_integers(f_out),
            },
        };
        (pub_key_material, sec_key_material)
    }

    fn generate_decapsulator(pp: &PublicParameters) -> (PublicKeyMaterial, SecretKeyMaterial) {
        let mut sk_out = Box::new([0; SECRET_KEY_S_MATRIX_ELEMENTS]);
        let mut f_out = Box::new([0; SECRET_KEY_F_MATRIX_ELEMENTS]);
        let mut pk_out = Box::new([0; PUBLIC_KEY_P_MATRIX_ELEMENTS]);

        if pp.store_matrix {
            pqcrypto_frodokexp::frodokexp::frodokexp_gen_a_store(
                pp.public_matrix.as_ref().unwrap().as_ptr(),
                sk_out.as_mut_ptr(),
                f_out.as_mut_ptr(),
                pk_out.as_mut_ptr(),
            );
        } else {
            pqcrypto_frodokexp::frodokexp::frodokexp_gen_a(
                pp.seed.as_ptr(),
                sk_out.as_mut_ptr(),
                f_out.as_mut_ptr(),
                pk_out.as_mut_ptr(),
            );
        }
        let pub_key_material = PublicKeyMaterial {
            key_type: KeyType::Frodokexp,
            b_mat: PublicKey {
                key_type: KeyType::Frodokexp,
                key_data: KeyMaterial::new_from_integers(pk_out),
            },
        };
        let sec_key_material = SecretKeyMaterial {
            key_type: KeyType::Frodokexp,
            s_mat: SecretKey {
                key_type: KeyType::Frodokexp,
                key_data: KeyMaterial::new_from_integers(sk_out),
            },
            f_mat: FSecretKey {
                key_type: KeyType::Frodokexp,
                key_data: KeyMaterial::new_from_integers(f_out),
            },
        };
        (pub_key_material, sec_key_material)
    }

    fn encapsulate(
        my_sec_key: &SecretKeyMaterial,
        my_pub_key: &PublicKeyMaterial,
        other_pub_key: &PublicKeyMaterial,
    ) -> (super::SharedSecret, super::RawCiphertext, super::RawTag) {
        let mut key_out: Box<[u8]> = Box::new([0; Self::SHARED_SECRET_SIZE_BYTES]);
        let mut ct_out: Box<[u8]> = Box::new([0; Self::CIPHERTEXT_SIZE_BYTES]);
        let mut tag_out: Box<[u8]> = Box::new([0; Self::TAG_SIZE_BYTES]);
        pqcrypto_frodokexp::frodokexp::frodokexp_encaps(
            other_pub_key.b_mat.key_data.as_ptr(),
            my_pub_key.b_mat.key_data.as_ptr(),
            my_sec_key.s_mat.key_data.as_ptr(),
            ct_out.as_mut_ptr(),
            tag_out.as_mut_ptr(),
            key_out.as_mut_ptr(),
        );
        (key_out, ct_out, tag_out)
    }

    fn decapsulate(
        my_sec_key: &SecretKeyMaterial,
        my_pub_key: &PublicKeyMaterial,
        other_pub_key: &PublicKeyMaterial,
        ciphertext: &[u8],
        tag: &[u8],
    ) -> crate::error::Result<SharedSecret> {
        let mut key_out: Box<[u8]> = Box::new([0; Self::SHARED_SECRET_SIZE_BYTES]);
        let result = pqcrypto_frodokexp::frodokexp::frodokexp_decaps(
            other_pub_key.b_mat.key_data.as_ptr(),
            my_pub_key.b_mat.key_data.as_ptr(),
            my_sec_key.s_mat.key_data.as_ptr(),
            my_sec_key.f_mat.key_data.as_ptr(),
            ciphertext.as_ptr(),
            tag.as_ptr(),
            key_out.as_mut_ptr(),
        );
        // check if decapsulation was successful
        if result.is_err() {
            return Err(crate::error::SignalProtocolError::SKEMDecapsulationError);
        }
        Ok(key_out)
    }
}
