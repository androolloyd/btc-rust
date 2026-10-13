//! Per-start HTTP RPC credentials. No credential is placed in argv or logs.
use btc_rpc::server::HttpAuth;
use secp256k1::rand::RngCore;
use std::{
    io::Write,
    path::{Path, PathBuf},
};

pub(crate) struct RpcCookie {
    path: PathBuf,
    credential: String,
    auth: HttpAuth,
}

impl RpcCookie {
    pub(crate) fn create(datadir: &Path) -> eyre::Result<Self> {
        let mut random = [0u8; 40];
        secp256k1::rand::rngs::OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| eyre::eyre!("RPC cookie OS entropy unavailable"))?;
        let credential = format!("__cookie__:{}", hex::encode(&random[..32]));
        let auth = HttpAuth::from_cookie(&credential)?;
        let path = datadir.join(".cookie");
        // The temporary suffix is independent of the password. create_new
        // refuses symlinks/collisions, and rename never follows an old cookie.
        let temporary = datadir.join(format!(
            ".cookie.tmp-{}-{}",
            std::process::id(),
            hex::encode(&random[32..])
        ));
        let owned = Self {
            path,
            credential,
            auth,
        };
        let mut temporary_created = false;
        let result = (|| -> eyre::Result<()> {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            temporary_created = true;
            writeln!(file, "{}", owned.credential)?;
            file.sync_all()?;
            drop(file);
            #[cfg(windows)]
            {
                // No listener is started yet. std's Windows rename cannot
                // replace a stale destination; removal does not follow it.
                match std::fs::remove_file(&owned.path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            std::fs::rename(&temporary, &owned.path)?;
            #[cfg(unix)]
            std::fs::File::open(datadir)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() && temporary_created {
            let _ = std::fs::remove_file(&temporary);
        }
        result?;
        Ok(owned)
    }
    pub(crate) fn auth(&self) -> HttpAuth {
        self.auth.clone()
    }
}

impl Drop for RpcCookie {
    fn drop(&mut self) {
        // Don't remove a credential rotated/replaced by another owner.
        use std::io::Read;
        let expected = format!("{}\n", self.credential);
        let mut actual = Vec::new();
        let owned = std::fs::File::open(&self.path).ok().is_some_and(|file| {
            file.take(257).read_to_end(&mut actual).is_ok() && actual == expected.as_bytes()
        });
        if owned && std::fs::remove_file(&self.path).is_err() {
            tracing::warn!("could not remove owned RPC cookie");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_rotate_and_cleanup_only_the_owned_file() {
        let dir = tempfile::tempdir().unwrap();
        let first = RpcCookie::create(dir.path()).unwrap();
        let path = dir.path().join(".cookie");
        let old = std::fs::read_to_string(&path).unwrap();
        assert!(old.starts_with("__cookie__:"));
        assert_eq!(old.len(), 76);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let second = RpcCookie::create(dir.path()).unwrap();
        assert_ne!(std::fs::read_to_string(&path).unwrap(), old);
        drop(first);
        assert!(path.exists());
        drop(second);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn stale_cookie_symlinks_do_not_overwrite_their_target() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("preserved");
        std::fs::write(&victim, b"preserve me").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join(".cookie")).unwrap();
        let cookie = RpcCookie::create(dir.path()).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"preserve me");
        assert!(!dir
            .path()
            .join(".cookie")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        drop(cookie);
        assert_eq!(std::fs::read(&victim).unwrap(), b"preserve me");
    }
}
