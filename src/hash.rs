#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use digest::{Digest, OutputSizeUser};
use rustls::crypto::{self, hash};
use sha2::{Sha256, Sha384};

macro_rules! impl_hash {
    ($name:ident, $ty:ty, $hash:ident, $context:ident, $algo:expr) => {
        #[allow(non_camel_case_types)]
        struct $hash;

        impl hash::Hash for $hash {
            fn start(&self) -> Box<dyn hash::Context> {
                Box::new($context(<$ty>::new()))
            }

            fn hash(&self, data: &[u8]) -> hash::Output {
                hash::Output::new(&<$ty>::digest(data)[..])
            }

            fn output_len(&self) -> usize {
                <$ty as OutputSizeUser>::output_size()
            }

            fn algorithm(&self) -> hash::HashAlgorithm {
                $algo
            }
        }

        #[allow(non_camel_case_types)]
        struct $context($ty);

        impl hash::Context for $context {
            fn fork_finish(&self) -> hash::Output {
                hash::Output::new(&self.0.clone().finalize()[..])
            }

            fn fork(&self) -> Box<dyn hash::Context> {
                Box::new($context(self.0.clone()))
            }

            fn finish(self: Box<Self>) -> hash::Output {
                hash::Output::new(&self.0.finalize()[..])
            }

            fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }
        }

        pub const $name: &dyn crypto::hash::Hash = &$hash;
    };
}

// impl_hash! {SHA224, Sha224, Hash_Sha224, HashContent_Sha224, hash::HashAlgorithm::SHA224}
impl_hash! {SHA256, Sha256, Hash_Sha256, HashContent_Sha256, hash::HashAlgorithm::SHA256}
impl_hash! {SHA384, Sha384, Hash_Sha384, HashContent_Sha384, hash::HashAlgorithm::SHA384}
// impl_hash! {SHA512, Sha512, Hash_Sha512, HashContent_Sha512, hash::HashAlgorithm::SHA512}
