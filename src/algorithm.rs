use crate::error::CborCertError;

pub enum Algorithm {
    Ed25519,
    //C25519,
}

impl Algorithm {
    pub fn alg_from_string(in_str: &str) -> Result<Algorithm, CborCertError> {
        match in_str {
            "ed25519" => Ok(Algorithm::Ed25519),
            //"c25519" => algorithm = Algorithm::C25519,
            _ => return Err(CborCertError::UnsupportedAlgorithm),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alg_from_string_test() {
        let correct_algorithm: &str = "ed25519";
        let wrong_algorithm: &str = "wrong_algorithm";

        assert!(matches!(
            Algorithm::alg_from_string(correct_algorithm),
            Ok(Algorithm::Ed25519)
        ));

        assert!(matches!(
            Algorithm::alg_from_string(wrong_algorithm),
            Err(CborCertError::UnsupportedAlgorithm)
        ));
    }
}
