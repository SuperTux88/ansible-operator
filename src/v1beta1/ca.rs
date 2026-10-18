use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ssh_key::{Algorithm, PrivateKey, PublicKey, certificate, rand_core::OsRng};

#[derive(thiserror::Error, Debug)]
pub enum CaError {
    #[error(transparent)]
    SshKey(#[from] ssh_key::Error),

    #[error("system clock is set before the Unix epoch")]
    ClockError,
}

/// The operator's own SSH certificate authority. Ephemeral and in-memory only — a fresh keypair
/// is generated at every operator startup and is never serialized or persisted. The CA private
/// key therefore never touches the cluster, and an operator restart rotates the CA (invalidating
/// every previously signed host/client cert). No auto-rotation within a single process lifetime.
pub struct CertificateAuthority {
    key: PrivateKey,
}

impl CertificateAuthority {
    /// Generates a brand-new in-memory CA keypair. The private key lives only for the lifetime of
    /// the operator process — it is never written out, so nothing can reload the same CA later.
    pub fn generate() -> Result<Self, CaError> {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
        Ok(Self { key })
    }

    /// The CA's public key in OpenSSH wire format — goes into a proxy pod's
    /// `TrustedUserCAKeys`/a client's `@cert-authority` known_hosts line. Never the private key.
    pub fn public_key_openssh(&self) -> Result<String, CaError> {
        Ok(self.key.public_key().to_openssh()?)
    }

    /// Signs a fresh host certificate for `subject_public_key`, valid as `principal` (the
    /// hostname proxied) for `validity` from now.
    pub fn sign_host_cert(
        &self,
        subject_public_key: &PublicKey,
        principal: &str,
        validity: Duration,
    ) -> Result<String, CaError> {
        self.sign(
            subject_public_key,
            &[principal],
            certificate::CertType::Host,
            validity,
        )
    }

    /// Signs a fresh client certificate valid for every principal in `principals`, for
    /// `validity` from now. One client cert per run, trusted by every proxy pod via the
    /// shared CA — no per-pod `authorized_keys` management needed.
    ///
    /// `principals` must include the login username the proxy pods are dialed as (e.g. `"root"`,
    /// matching `PermitRootLogin yes` in `managed_ssh.rs`), since sshd's default certificate check
    /// requires that username to be in the principal list.
    pub fn sign_client_cert(
        &self,
        subject_public_key: &PublicKey,
        principals: &[&str],
        validity: Duration,
    ) -> Result<String, CaError> {
        self.sign(
            subject_public_key,
            principals,
            certificate::CertType::User,
            validity,
        )
    }

    fn sign(
        &self,
        subject_public_key: &PublicKey,
        principals: &[&str],
        cert_type: certificate::CertType,
        validity: Duration,
    ) -> Result<String, CaError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CaError::ClockError)?
            .as_secs();
        let valid_before = now + validity.as_secs();

        let mut builder = certificate::Builder::new_with_random_nonce(
            &mut OsRng,
            subject_public_key,
            now,
            valid_before,
        )?;
        builder.cert_type(cert_type)?;
        for principal in principals {
            builder.valid_principal(*principal)?;
        }

        let cert = builder.sign(&self.key)?;
        Ok(cert.to_openssh()?)
    }
}

/// Generates a brand-new ephemeral ed25519 keypair (a proxy pod's host identity, or a run's
/// client identity). The operator always generates these itself — never the pod — so it never
/// has to wait for the pod to report a key back before rendering the workspace secret.
pub fn generate_ephemeral_keypair() -> Result<PrivateKey, CaError> {
    Ok(PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT_VALIDITY: Duration = Duration::from_secs(2 * 60 * 60);

    #[test]
    fn sign_and_verify_host_cert() {
        let ca = CertificateAuthority::generate().unwrap();
        let host_key = generate_ephemeral_keypair().unwrap();

        let cert_openssh = ca
            .sign_host_cert(host_key.public_key(), "worker-1", CERT_VALIDITY)
            .unwrap();

        let cert = ssh_key::Certificate::from_openssh(&cert_openssh).unwrap();
        assert_eq!(cert.cert_type(), certificate::CertType::Host);
        assert_eq!(cert.valid_principals(), &["worker-1".to_string()]);
        cert.verify_signature().unwrap();

        let ca_fingerprint = ca.key.fingerprint(ssh_key::HashAlg::Sha256);
        cert.validate([&ca_fingerprint]).unwrap();
    }

    #[test]
    fn sign_and_verify_client_cert() {
        let ca = CertificateAuthority::generate().unwrap();
        let client_key = generate_ephemeral_keypair().unwrap();

        let cert_openssh = ca
            .sign_client_cert(
                client_key.public_key(),
                &["root", "run-deadbeef"],
                CERT_VALIDITY,
            )
            .unwrap();

        let cert = ssh_key::Certificate::from_openssh(&cert_openssh).unwrap();
        assert_eq!(cert.cert_type(), certificate::CertType::User);
        assert_eq!(
            cert.valid_principals(),
            &["root".to_string(), "run-deadbeef".to_string()]
        );
        cert.verify_signature().unwrap();
    }

    /// A run's certificates have to last as long as the run may, which its deadline decides.
    #[test]
    fn a_cert_is_valid_for_exactly_the_requested_window() {
        let ca = CertificateAuthority::generate().unwrap();
        let key = generate_ephemeral_keypair().unwrap();
        let validity = Duration::from_secs(5 * 60 * 60);

        let host = ca
            .sign_host_cert(key.public_key(), "worker-1", validity)
            .unwrap();
        let client = ca
            .sign_client_cert(key.public_key(), &["root"], validity)
            .unwrap();

        for cert in [host, client] {
            let cert = ssh_key::Certificate::from_openssh(&cert).unwrap();
            assert_eq!(cert.valid_before() - cert.valid_after(), validity.as_secs());
        }
    }

    #[test]
    fn cert_signed_by_a_different_ca_fails_validation() {
        let ca = CertificateAuthority::generate().unwrap();
        let other_ca = CertificateAuthority::generate().unwrap();
        let host_key = generate_ephemeral_keypair().unwrap();

        let cert_openssh = ca
            .sign_host_cert(host_key.public_key(), "worker-1", CERT_VALIDITY)
            .unwrap();
        let cert = ssh_key::Certificate::from_openssh(&cert_openssh).unwrap();

        let other_fingerprint = other_ca.key.fingerprint(ssh_key::HashAlg::Sha256);
        assert!(cert.validate([&other_fingerprint]).is_err());
    }
}
