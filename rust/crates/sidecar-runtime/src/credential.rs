use std::{
    collections::HashMap,
    fmt,
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Deserializer, de::MapAccess, de::Visitor};
use zeroize::Zeroizing;

const CREDENTIAL_FILE_VERSION: u16 = 1;
const MAX_CREDENTIAL_FILE_SIZE: usize = 1 << 20;
const MAX_CREDENTIAL_COUNT: usize = 1024;
const MAX_CREDENTIAL_ID_SIZE: usize = 128;
const MAX_CREDENTIAL_SIZE: usize = 512;

/// Resolves an opaque credential reference inside the Provider process.
///
/// Implementations must not log credential values or return them through RPC.
pub trait CredentialResolver: fmt::Debug + Send + Sync {
    /// Returns a fresh zeroizing copy of the credential, if the reference exists.
    fn resolve(&self, credential_id: &str) -> Option<Zeroizing<Vec<u8>>>;
}

#[derive(Debug)]
pub(crate) struct EmptyCredentialResolver;

impl CredentialResolver for EmptyCredentialResolver {
    fn resolve(&self, _credential_id: &str) -> Option<Zeroizing<Vec<u8>>> {
        None
    }
}

/// Immutable credentials loaded from a protected Provider-local JSON file.
pub struct FileCredentialResolver {
    credentials: HashMap<String, Zeroizing<Vec<u8>>>,
}

impl FileCredentialResolver {
    /// Loads credentials from a non-symlink regular file with no group or other access.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, CredentialStoreError> {
        let path = path.as_ref();
        let path_metadata = std::fs::symlink_metadata(path)?;
        if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
            return Err(CredentialStoreError::NotRegularFile);
        }
        if path_metadata.permissions().mode() & 0o077 != 0 {
            return Err(CredentialStoreError::InsecurePermissions);
        }
        if path_metadata.len() > MAX_CREDENTIAL_FILE_SIZE as u64 {
            return Err(CredentialStoreError::TooLarge);
        }

        let mut file = File::open(path)?;
        let opened_metadata = file.metadata()?;
        if opened_metadata.dev() != path_metadata.dev()
            || opened_metadata.ino() != path_metadata.ino()
            || !opened_metadata.file_type().is_file()
        {
            return Err(CredentialStoreError::FileChanged);
        }
        if opened_metadata.permissions().mode() & 0o077 != 0 {
            return Err(CredentialStoreError::InsecurePermissions);
        }
        let mut encoded = Zeroizing::new(Vec::with_capacity(path_metadata.len() as usize));
        file.by_ref()
            .take((MAX_CREDENTIAL_FILE_SIZE + 1) as u64)
            .read_to_end(&mut encoded)?;
        if encoded.len() > MAX_CREDENTIAL_FILE_SIZE {
            return Err(CredentialStoreError::TooLarge);
        }
        let final_path_metadata = std::fs::symlink_metadata(path)?;
        let final_file_metadata = file.metadata()?;
        if final_path_metadata.file_type().is_symlink()
            || final_path_metadata.dev() != opened_metadata.dev()
            || final_path_metadata.ino() != opened_metadata.ino()
            || final_file_metadata.len() != encoded.len() as u64
            || final_file_metadata.mtime() != opened_metadata.mtime()
            || final_file_metadata.mtime_nsec() != opened_metadata.mtime_nsec()
            || final_file_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(CredentialStoreError::FileChanged);
        }

        let parsed: CredentialFile =
            serde_json::from_slice(&encoded).map_err(|_| CredentialStoreError::InvalidFormat)?;
        if parsed.version != CREDENTIAL_FILE_VERSION {
            return Err(CredentialStoreError::UnsupportedVersion);
        }
        if parsed.credentials.0.len() > MAX_CREDENTIAL_COUNT {
            return Err(CredentialStoreError::TooManyCredentials);
        }

        let mut credentials = HashMap::with_capacity(parsed.credentials.0.len());
        for (credential_id, credential) in parsed.credentials.0 {
            if !valid_credential_id(&credential_id) {
                return Err(CredentialStoreError::InvalidCredentialId);
            }
            let bytes = credential.0.as_bytes();
            if bytes.is_empty()
                || bytes.len() > MAX_CREDENTIAL_SIZE
                || !bytes.iter().all(|byte| matches!(byte, 0x21..=0x7e))
            {
                return Err(CredentialStoreError::InvalidCredential);
            }
            credentials.insert(credential_id, Zeroizing::new(bytes.to_vec()));
        }

        Ok(Self { credentials })
    }
}

impl fmt::Debug for FileCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileCredentialResolver")
            .field("credential_count", &self.credentials.len())
            .finish()
    }
}

impl CredentialResolver for FileCredentialResolver {
    fn resolve(&self, credential_id: &str) -> Option<Zeroizing<Vec<u8>>> {
        self.credentials.get(credential_id).cloned()
    }
}

/// Atomically reloadable credentials backed by one protected Provider-local file.
pub struct ReloadingFileCredentialResolver {
    path: PathBuf,
    current: RwLock<FileCredentialResolver>,
    generation: AtomicU64,
}

impl ReloadingFileCredentialResolver {
    /// Loads the initial credential snapshot. Failure prevents sidecar startup.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, CredentialStoreError> {
        let path = path.as_ref().to_owned();
        let current = FileCredentialResolver::load(&path)?;
        Ok(Self {
            path,
            current: RwLock::new(current),
            generation: AtomicU64::new(1),
        })
    }

    /// Validates a complete replacement and atomically installs it.
    ///
    /// On failure, the previous snapshot remains active.
    pub fn reload(&self) -> Result<u64, CredentialStoreError> {
        let replacement = FileCredentialResolver::load(&self.path)?;
        let mut current = self
            .current
            .write()
            .map_err(|_| CredentialStoreError::StateUnavailable)?;
        *current = replacement;
        Ok(self.generation.fetch_add(1, Ordering::AcqRel) + 1)
    }

    /// Returns the generation of the currently installed snapshot.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

impl fmt::Debug for ReloadingFileCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReloadingFileCredentialResolver")
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}

impl CredentialResolver for ReloadingFileCredentialResolver {
    fn resolve(&self, credential_id: &str) -> Option<Zeroizing<Vec<u8>>> {
        self.current.read().ok()?.resolve(credential_id)
    }
}

/// Provider credential file loading failure.
#[derive(Debug, thiserror::Error)]
pub enum CredentialStoreError {
    /// File access failed.
    #[error("credential file access failed: {0}")]
    Io(#[from] std::io::Error),
    /// The path was a symlink or not a regular file.
    #[error("credential path must identify a non-symlink regular file")]
    NotRegularFile,
    /// Group or other permission bits were present.
    #[error("credential file must not grant group or other access")]
    InsecurePermissions,
    /// The opened file did not match the path that was validated.
    #[error("credential file changed while it was being opened")]
    FileChanged,
    /// The file exceeded the bounded parser input size.
    #[error("credential file exceeds the size limit")]
    TooLarge,
    /// Strict JSON parsing failed.
    #[error("credential file format is invalid")]
    InvalidFormat,
    /// The file version is not supported.
    #[error("credential file version is unsupported")]
    UnsupportedVersion,
    /// The file contains too many credential entries.
    #[error("credential file contains too many entries")]
    TooManyCredentials,
    /// A credential identifier is invalid.
    #[error("credential file contains an invalid identifier")]
    InvalidCredentialId,
    /// A credential is empty, oversized, or unsafe for an HTTP header.
    #[error("credential file contains an invalid credential")]
    InvalidCredential,
    /// The in-process credential snapshot lock was poisoned.
    #[error("credential snapshot is unavailable")]
    StateUnavailable,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialFile {
    version: u16,
    credentials: CredentialMap,
}

struct CredentialMap(HashMap<String, SecretString>);

impl<'de> Deserialize<'de> for CredentialMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(CredentialMapVisitor)
    }
}

struct CredentialMapVisitor;

impl<'de> Visitor<'de> for CredentialMapVisitor {
    type Value = CredentialMap;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a map of unique credential identifiers to secret strings")
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut credentials = HashMap::with_capacity(access.size_hint().unwrap_or(0));
        while let Some((credential_id, credential)) = access.next_entry()? {
            if credentials.insert(credential_id, credential).is_some() {
                return Err(serde::de::Error::custom("duplicate credential identifier"));
            }
        }
        Ok(CredentialMap(credentials))
    }
}

struct SecretString(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

fn valid_credential_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CREDENTIAL_ID_SIZE
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::Arc;
    use tempfile::tempdir;

    fn write_file(contents: &str, mode: u32) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("credentials.json");
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        (directory, path)
    }

    fn replace_file(path: &Path, contents: &str, mode: u32) {
        let replacement = path.with_extension("replacement");
        std::fs::write(&replacement, contents).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(mode)).unwrap();
        std::fs::rename(replacement, path).unwrap();
    }

    #[test]
    fn loads_and_redacts_protected_credentials() {
        let (_directory, path) = write_file(
            r#"{"version":1,"credentials":{"openai-main":"sk-provider-secret"}}"#,
            0o600,
        );
        let resolver = FileCredentialResolver::load(path).unwrap();
        assert_eq!(
            resolver.resolve("openai-main").unwrap().as_slice(),
            b"sk-provider-secret"
        );
        assert!(resolver.resolve("missing").is_none());
        assert!(!format!("{resolver:?}").contains("sk-provider-secret"));
    }

    #[test]
    fn rejects_unsafe_files_and_values() {
        let (_directory, public_path) =
            write_file(r#"{"version":1,"credentials":{"id":"secret"}}"#, 0o644);
        assert!(matches!(
            FileCredentialResolver::load(public_path),
            Err(CredentialStoreError::InsecurePermissions)
        ));

        let (directory, target) =
            write_file(r#"{"version":1,"credentials":{"id":"secret"}}"#, 0o600);
        let link = directory.path().join("credentials-link.json");
        symlink(target, &link).unwrap();
        assert!(matches!(
            FileCredentialResolver::load(link),
            Err(CredentialStoreError::NotRegularFile)
        ));

        let (_directory, duplicate_path) = write_file(
            r#"{"version":1,"credentials":{"id":"first","id":"second"}}"#,
            0o600,
        );
        assert!(matches!(
            FileCredentialResolver::load(duplicate_path),
            Err(CredentialStoreError::InvalidFormat)
        ));

        let (_directory, injection_path) = write_file(
            "{\"version\":1,\"credentials\":{\"id\":\"secret\\r\\nInjected: yes\"}}",
            0o600,
        );
        assert!(matches!(
            FileCredentialResolver::load(injection_path),
            Err(CredentialStoreError::InvalidCredential)
        ));
    }

    #[test]
    fn reloads_complete_snapshot_and_retains_old_snapshot_on_failure() {
        let (_directory, path) = write_file(
            r#"{"version":1,"credentials":{"openai-main":"old-secret"}}"#,
            0o600,
        );
        let resolver = ReloadingFileCredentialResolver::load(&path).unwrap();
        assert_eq!(resolver.generation(), 1);

        replace_file(
            &path,
            r#"{"version":1,"credentials":{"openai-main":"new-secret","second":"other-secret"}}"#,
            0o600,
        );
        assert_eq!(resolver.reload().unwrap(), 2);
        assert_eq!(
            resolver.resolve("openai-main").unwrap().as_slice(),
            b"new-secret"
        );
        assert_eq!(
            resolver.resolve("second").unwrap().as_slice(),
            b"other-secret"
        );

        replace_file(
            &path,
            r#"{"version":1,"credentials":{"openai-main":"exposed-secret"}}"#,
            0o644,
        );
        assert!(matches!(
            resolver.reload(),
            Err(CredentialStoreError::InsecurePermissions)
        ));
        assert_eq!(resolver.generation(), 2);
        assert_eq!(
            resolver.resolve("openai-main").unwrap().as_slice(),
            b"new-secret"
        );
        assert!(!format!("{resolver:?}").contains("new-secret"));
    }

    #[test]
    fn concurrent_resolution_observes_only_complete_snapshots() {
        let (_directory, path) = write_file(
            r#"{"version":1,"credentials":{"id":"generation-a"}}"#,
            0o600,
        );
        let resolver = Arc::new(ReloadingFileCredentialResolver::load(&path).unwrap());
        let mut readers = Vec::new();
        for _ in 0..8 {
            let resolver = Arc::clone(&resolver);
            readers.push(std::thread::spawn(move || {
                for _ in 0..1_000 {
                    let value = resolver.resolve("id").unwrap();
                    assert!(
                        value.as_slice() == b"generation-a" || value.as_slice() == b"generation-b"
                    );
                }
            }));
        }
        replace_file(
            &path,
            r#"{"version":1,"credentials":{"id":"generation-b"}}"#,
            0o600,
        );
        resolver.reload().unwrap();
        for reader in readers {
            reader.join().unwrap();
        }
        assert_eq!(resolver.resolve("id").unwrap().as_slice(), b"generation-b");
    }
}
