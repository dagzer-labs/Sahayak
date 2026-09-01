use secrecy::SecretString;
use std::{fs, path::Path};
use thiserror::Error;

/// Failure while reading one bounded deployment secret file.
#[derive(Debug, Error)]
pub enum SecretFileError {
    /// File metadata or contents could not be read.
    #[error("secret file could not be read")]
    Read,
    /// Path did not refer to a regular file.
    #[error("secret path is not a regular file")]
    NotRegular,
    /// Secret was empty, oversized, or contained a NUL byte.
    #[error("secret file contents are invalid")]
    InvalidContents,
    /// Production file permissions permit group or other access.
    #[error("secret file permissions are too broad")]
    UnsafePermissions,
}

/// Reads a secret while retaining no filename-derived fallback value.
pub fn load_secret_file(
    path: &Path,
    maximum_bytes: usize,
    require_private_permissions: bool,
) -> Result<SecretString, SecretFileError> {
    let metadata = fs::metadata(path).map_err(|_| SecretFileError::Read)?;
    if !metadata.is_file() {
        return Err(SecretFileError::NotRegular);
    }
    #[cfg(unix)]
    if require_private_permissions {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(SecretFileError::UnsafePermissions);
        }
    }
    let mut value = fs::read_to_string(path).map_err(|_| SecretFileError::Read)?;
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    if value.is_empty() || value.len() > maximum_bytes || value.as_bytes().contains(&0) {
        return Err(SecretFileError::InvalidContents);
    }
    Ok(SecretString::from(value))
}

#[cfg(test)]
mod tests {
    use super::load_secret_file;
    use secrecy::ExposeSecret;
    use std::{fs, path::PathBuf};
    use uuid::Uuid;

    #[test]
    fn removes_only_one_trailing_newline() -> Result<(), Box<dyn std::error::Error>> {
        let path = temporary_path();
        fs::write(&path, "secret-value\n")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        let secret = load_secret_file(&path, 100, true)?;
        fs::remove_file(path)?;
        assert_eq!(secret.expose_secret(), "secret-value");
        Ok(())
    }

    fn temporary_path() -> PathBuf {
        std::env::temp_dir().join(format!("sahayak-secret-{}", Uuid::now_v7()))
    }
}
