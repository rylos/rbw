use crate::prelude::*;

use std::io::{Read as _, Write as _};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Entry {
    pub id: String,
    pub org_id: Option<String>,
    pub folder: Option<String>,
    pub folder_id: Option<String>,
    pub name: String,
    pub data: EntryData,
    pub fields: Vec<Field>,
    pub notes: Option<String>,
    pub history: Vec<HistoryEntry>,
    pub key: Option<String>,
    pub master_password_reprompt: crate::api::CipherRepromptType,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub collection_ids: Vec<String>,
}

// what the official clients show in their sidebar; names are encrypted
// like the entries (folders with the user key, collections with their
// organization's key), organization names come in clear
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Organization {
    pub id: String,
    pub name: String,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Collection {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub read_only: bool,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Folder {
    pub id: String,
    pub name: String,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Attachment {
    pub id: String,
    // encrypted, like the key
    pub file_name: Option<String>,
    pub size: Option<String>,
    pub key: Option<String>,
}

impl Entry {
    pub fn master_password_reprompt(&self) -> bool {
        self.master_password_reprompt != crate::api::CipherRepromptType::None
    }
}

#[derive(serde::Serialize, Debug, Clone, Eq, PartialEq)]
pub struct Uri {
    pub uri: String,
    pub match_type: Option<crate::api::UriMatchType>,
}

// backwards compatibility
impl<'de> serde::Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StringOrUri;
        impl<'de> serde::de::Visitor<'de> for StringOrUri {
            type Value = Uri;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("uri")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Uri {
                    uri: value.to_string(),
                    match_type: None,
                })
            }

            fn visit_map<M>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut uri = None;
                let mut match_type = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        "uri" => {
                            if uri.is_some() {
                                return Err(
                                    serde::de::Error::duplicate_field("uri"),
                                );
                            }
                            uri = Some(map.next_value()?);
                        }
                        "match_type" => {
                            if match_type.is_some() {
                                return Err(
                                    serde::de::Error::duplicate_field(
                                        "match_type",
                                    ),
                                );
                            }
                            match_type = map.next_value()?;
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                key,
                                &["uri", "match_type"],
                            ))
                        }
                    }
                }

                uri.map_or_else(
                    || Err(serde::de::Error::missing_field("uri")),
                    |uri| Ok(Self::Value { uri, match_type }),
                )
            }
        }

        deserializer.deserialize_any(StringOrUri)
    }
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub enum EntryData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Vec<Uri>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        private_key: Option<String>,
        public_key: Option<String>,
        fingerprint: Option<String>,
    },
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Field {
    pub ty: Option<crate::api::FieldType>,
    pub name: Option<String>,
    pub value: Option<String>,
    pub linked_id: Option<crate::api::LinkedIdType>,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct HistoryEntry {
    pub last_used_date: String,
    pub password: String,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug)]
pub struct Db {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,

    pub kdf: Option<crate::api::KdfType>,
    pub iterations: Option<u32>,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
    pub protected_key: Option<String>,
    pub protected_private_key: Option<String>,
    pub protected_org_keys: std::collections::HashMap<String, String>,

    // the current access token came from an api key login, which doesn't
    // provide a refresh token
    #[serde(default)]
    pub api_key_login: bool,

    pub entries: Vec<Entry>,

    #[serde(default)]
    pub organizations: Vec<Organization>,
    #[serde(default)]
    pub collections: Vec<Collection>,
    #[serde(default)]
    pub folders: Vec<Folder>,
}

impl Db {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(server: &str, email: &str) -> Result<Self> {
        let file = crate::dirs::db_file(server, email);
        let mut fh =
            std::fs::File::open(&file).map_err(|source| Error::LoadDb {
                source,
                file: file.clone(),
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadDb {
                source,
                file: file.clone(),
            })?;
        let slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadDbJson { source, file })?;
        Ok(slf)
    }

    pub async fn load_async(server: &str, email: &str) -> Result<Self> {
        let file = crate::dirs::db_file(server, email);
        let mut fh =
            tokio::fs::File::open(&file).await.map_err(|source| {
                Error::LoadDbAsync {
                    source,
                    file: file.clone(),
                }
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json).await.map_err(|source| {
            Error::LoadDbAsync {
                source,
                file: file.clone(),
            }
        })?;
        let slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadDbJson { source, file })?;
        Ok(slf)
    }

    // written to a temporary file and renamed over the old one, so a
    // concurrent load never sees a truncated or half written file
    pub fn save(&self, server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        std::fs::create_dir_all(file.parent().unwrap()).map_err(
            |source| Error::SaveDb {
                source,
                file: file.clone(),
            },
        )?;
        let json = serde_json::to_string(self).map_err(|source| {
            Error::SaveDbJson {
                source,
                file: file.clone(),
            }
        })?;
        write_atomic(&file, json.as_bytes())
            .map_err(|source| Error::SaveDb { source, file })?;
        Ok(())
    }

    pub async fn save_async(&self, server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        tokio::fs::create_dir_all(file.parent().unwrap())
            .await
            .map_err(|source| Error::SaveDbAsync {
                source,
                file: file.clone(),
            })?;
        let json = serde_json::to_string(self).map_err(|source| {
            Error::SaveDbJson {
                source,
                file: file.clone(),
            }
        })?;
        write_atomic_async(&file, json.as_bytes())
            .await
            .map_err(|source| Error::SaveDbAsync { source, file })?;
        Ok(())
    }

    pub fn remove(server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        let res = std::fs::remove_file(&file);
        if let Err(e) = &res {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
        }
        res.map_err(|source| Error::RemoveDb { source, file })?;
        Ok(())
    }

    pub fn needs_login(&self) -> bool {
        self.access_token.is_none()
            || (self.refresh_token.is_none() && !self.api_key_login)
            || self.iterations.is_none()
            || self.kdf.is_none()
            || self.protected_key.is_none()
    }
}

// unique per process and per call: the agent can save from several tasks
// at once, and each needs its own temporary file
fn tmp_file(file: &std::path::Path) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut tmp = std::ffi::OsString::from(".");
    tmp.push(file.file_name().unwrap_or_else(|| "db".as_ref()));
    tmp.push(format!(".{}.{n}.tmp", std::process::id()));
    file.with_file_name(tmp)
}

fn write_atomic(file: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = tmp_file(file);
    let res = (|| {
        let mut fh = std::fs::File::create(&tmp)?;
        fh.write_all(data)?;
        fh.sync_all()?;
        std::fs::rename(&tmp, file)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

async fn write_atomic_async(
    file: &std::path::Path,
    data: &[u8],
) -> std::io::Result<()> {
    let tmp = tmp_file(file);
    let res = async {
        let mut fh = tokio::fs::File::create(&tmp).await?;
        fh.write_all(data).await?;
        fh.sync_all().await?;
        tokio::fs::rename(&tmp, file).await
    }
    .await;
    if res.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    res
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("rbw-db-test-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_write_atomic_never_exposes_partial_file() {
        const LEN: usize = 4 * 1024 * 1024;
        let dir = test_dir("sync");
        let file = dir.join("db.json");
        write_atomic(&file, &vec![b'a'; LEN]).unwrap();
        let reader = {
            let file = file.clone();
            std::thread::spawn(move || {
                for _ in 0..200 {
                    let data = std::fs::read(&file).unwrap();
                    assert_eq!(data.len(), LEN);
                    assert!(data.iter().all(|&c| c == data[0]));
                }
            })
        };
        for i in 0..20_u8 {
            write_atomic(&file, &vec![b'a' + i % 2; LEN]).unwrap();
        }
        reader.join().unwrap();
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("db.json")]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn test_write_atomic_async_concurrent_writers() {
        const LEN: usize = 256 * 1024;
        let dir = test_dir("async");
        let file = dir.join("db.json");
        let mut tasks = vec![];
        for i in 0..16_u8 {
            let file = file.clone();
            tasks.push(tokio::spawn(async move {
                write_atomic_async(&file, &vec![i; LEN]).await.unwrap();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let data = std::fs::read(&file).unwrap();
        assert_eq!(data.len(), LEN);
        assert!(data.iter().all(|&c| c == data[0]));
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
