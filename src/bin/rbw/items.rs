// Creating and changing vault items, folders, the trash and attachments.
//
// Items are changed by fetching the item as the server stores it, replacing
// only the values that actually changed, and sending the whole item back.
// Everything rbw doesn't know about (passkeys, favorites, archive state,
// per-item keys, types added after this was written) goes back untouched,
// and the server's revision check rejects the write if the item changed in
// the meantime.

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};

use anyhow::Context as _;
use is_terminal::IsTerminal as _;
use sha2::Digest as _;

use crate::commands::Needle;

const FIELD_TEXT: u64 = 0;
const FIELD_HIDDEN: u64 = 1;
const FIELD_BOOLEAN: u64 = 2;

// Bitwarden's own clients keep this many old passwords
const MAX_PASSWORD_HISTORY: usize = 5;

const NOTES_SEPARATOR: &str = "--- notes ---";

#[derive(Debug, Default, Clone)]
pub struct Changes {
    pub name: Option<String>,
    pub username: Option<String>,
    pub password_stdin: bool,
    // not settable from the command line, where it would end up in the
    // shell history
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Option<Vec<String>>,
    pub add_uris: Vec<String>,
    pub fields: Vec<(u64, String, String)>,
    pub remove_fields: Vec<String>,
    pub notes: Option<String>,
    pub notes_file: Option<std::path::PathBuf>,
    pub folder: Option<String>,
    pub favorite: Option<bool>,
}

impl Changes {
    fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.username.is_none()
            && !self.password_stdin
            && self.password.is_none()
            && self.totp.is_none()
            && self.uris.is_none()
            && self.add_uris.is_empty()
            && self.fields.is_empty()
            && self.remove_fields.is_empty()
            && self.notes.is_none()
            && self.notes_file.is_none()
            && self.folder.is_none()
            && self.favorite.is_none()
    }

    fn apply(&self, form: &mut Form) -> anyhow::Result<()> {
        if let Some(name) = &self.name {
            form.name.clone_from(name);
        }
        if self.username.is_some()
            || self.password_stdin
            || self.password.is_some()
            || self.totp.is_some()
            || self.uris.is_some()
            || !self.add_uris.is_empty()
        {
            let Some(login) = &mut form.login else {
                return Err(anyhow::anyhow!(
                    "username, password, totp and uris can only be set on \
                     login entries"
                ));
            };
            if let Some(username) = &self.username {
                login.username = non_empty(username);
            }
            if let Some(password) = &self.password {
                login.password = non_empty(password);
            }
            if self.password_stdin {
                login.password = non_empty(&read_password_stdin()?);
            }
            if let Some(totp) = &self.totp {
                login.totp = non_empty(totp);
            }
            if let Some(uris) = &self.uris {
                login.uris.clone_from(uris);
            }
            login.uris.extend(self.add_uris.iter().cloned());
        }
        for name in &self.remove_fields {
            let before = form.fields.len();
            form.fields.retain(|field| &field.name != name);
            if form.fields.len() == before {
                return Err(anyhow::anyhow!(
                    "no custom field named '{name}'"
                ));
            }
        }
        for (ty, name, value) in &self.fields {
            if let Some(field) =
                form.fields.iter_mut().find(|field| &field.name == name)
            {
                field.ty = *ty;
                field.value.clone_from(value);
            } else {
                form.fields.push(FormField {
                    ty: *ty,
                    name: name.clone(),
                    value: value.clone(),
                });
            }
        }
        if let Some(notes) = &self.notes {
            form.notes = non_empty(notes);
        }
        if let Some(path) = &self.notes_file {
            let notes = if path.as_os_str() == "-" {
                std::io::read_to_string(std::io::stdin())
                    .context("failed to read notes from stdin")?
            } else {
                std::fs::read_to_string(path).with_context(|| {
                    format!("failed to read notes from {}", path.display())
                })?
            };
            form.notes = non_empty(notes.trim_end_matches('\n'));
        }
        if let Some(folder) = &self.folder {
            form.folder = non_empty(folder);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Form {
    name: String,
    // only for login entries
    login: Option<LoginForm>,
    folder: Option<String>,
    fields: Vec<FormField>,
    notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct LoginForm {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FormField {
    ty: u64,
    name: String,
    value: String,
}

// an item as the server stores it, plus the keys its values are encrypted
// with
struct Item {
    json: serde_json::Value,
    entry_key: Option<String>,
    org_id: Option<String>,
}

impl Item {
    fn fetch(id: &str) -> anyhow::Result<Self> {
        let json = api_call(|client, access_token| {
            client.get_cipher(access_token, id)
        })
        .context("failed to fetch the entry from the server")?;
        Ok(Self::from_json(json))
    }

    fn from_json(json: serde_json::Value) -> Self {
        let entry_key = string(&json, "key");
        let org_id = string(&json, "organizationId");
        Self {
            json,
            entry_key,
            org_id,
        }
    }

    fn id(&self) -> anyhow::Result<String> {
        string(&self.json, "id").ok_or_else(|| {
            anyhow::anyhow!("server returned an item without id")
        })
    }

    fn ty(&self) -> u64 {
        self.json
            .get("type")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    }

    fn decrypt(
        &self,
        value: &serde_json::Value,
    ) -> anyhow::Result<Option<String>> {
        match value.as_str() {
            Some(cipherstring) if !cipherstring.is_empty() => {
                Ok(Some(crate::actions::decrypt(
                    cipherstring,
                    self.entry_key.as_deref(),
                    self.org_id.as_deref(),
                )?))
            }
            _ => Ok(None),
        }
    }

    fn decrypt_key(&self, key: &str) -> anyhow::Result<Option<String>> {
        self.json
            .get(key)
            .map_or(Ok(None), |value| self.decrypt(value))
    }

    fn encrypt(&self, plaintext: &str) -> anyhow::Result<serde_json::Value> {
        Ok(serde_json::Value::String(
            crate::actions::encrypt_for_entry(
                plaintext,
                self.entry_key.as_deref(),
                self.org_id.as_deref(),
            )?,
        ))
    }

    fn encrypt_opt(
        &self,
        plaintext: Option<&str>,
    ) -> anyhow::Result<serde_json::Value> {
        plaintext.map_or(Ok(serde_json::Value::Null), |plaintext| {
            self.encrypt(plaintext)
        })
    }

    fn form(&self, folders: &[(String, String)]) -> anyhow::Result<Form> {
        let folder = string(&self.json, "folderId").and_then(|id| {
            folders
                .iter()
                .find(|(folder_id, _)| folder_id == &id)
                .map(|(_, name)| name.clone())
        });
        let login = if self.ty() == 1 {
            let login = self.json.get("login").cloned().unwrap_or_default();
            let mut uris = vec![];
            for uri in login
                .get("uris")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(uri) =
                    uri.get("uri").map(|v| self.decrypt(v)).transpose()?
                {
                    uris.extend(uri);
                }
            }
            Some(LoginForm {
                username: login
                    .get("username")
                    .map(|v| self.decrypt(v))
                    .transpose()?
                    .flatten(),
                password: login
                    .get("password")
                    .map(|v| self.decrypt(v))
                    .transpose()?
                    .flatten(),
                totp: login
                    .get("totp")
                    .map(|v| self.decrypt(v))
                    .transpose()?
                    .flatten(),
                uris,
            })
        } else {
            None
        };
        let mut fields = vec![];
        for field in self
            .json
            .get("fields")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let ty = field
                .get("type")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(FIELD_TEXT);
            // linked fields have no value of their own and are kept as
            // they are
            if ty > FIELD_BOOLEAN {
                continue;
            }
            fields.push(FormField {
                ty,
                name: field
                    .get("name")
                    .map(|v| self.decrypt(v))
                    .transpose()?
                    .flatten()
                    .unwrap_or_default(),
                value: field
                    .get("value")
                    .map(|v| self.decrypt(v))
                    .transpose()?
                    .flatten()
                    .unwrap_or_default(),
            });
        }
        Ok(Form {
            name: self.decrypt_key("name")?.unwrap_or_default(),
            login,
            folder,
            fields,
            notes: self.decrypt_key("notes")?,
        })
    }

    // writes the values of `new` that differ from `old` into the item,
    // leaving everything else (including the encryption of unchanged
    // values) as it was
    fn apply(
        &mut self,
        old: &Form,
        new: &Form,
        folder_id: Option<String>,
    ) -> anyhow::Result<()> {
        if new.name.is_empty() {
            return Err(anyhow::anyhow!("the name can't be empty"));
        }
        if new.name != old.name {
            self.json["name"] = self.encrypt(&new.name)?;
        }
        if new.notes != old.notes {
            self.json["notes"] = self.encrypt_opt(new.notes.as_deref())?;
        }
        self.json["folderId"] = folder_id
            .map_or(serde_json::Value::Null, serde_json::Value::String);

        if let (Some(old_login), Some(new_login)) = (&old.login, &new.login) {
            self.apply_login(old_login, new_login)?;
        }

        if new.fields != old.fields {
            let old_fields: Vec<serde_json::Value> = self
                .json
                .get("fields")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            let (linked, editable): (Vec<_>, Vec<_>) =
                old_fields.into_iter().partition(|field| {
                    field
                        .get("type")
                        .and_then(serde_json::Value::as_u64)
                        .is_some_and(|ty| ty > FIELD_BOOLEAN)
                });
            let mut fields = vec![];
            for field in &new.fields {
                // keep the stored field when nothing about it changed
                let unchanged = old
                    .fields
                    .iter()
                    .position(|old_field| old_field == field)
                    .and_then(|i| editable.get(i));
                if let Some(unchanged) = unchanged {
                    fields.push(unchanged.clone());
                } else {
                    fields.push(serde_json::json!({
                        "type": field.ty,
                        "name": self.encrypt(&field.name)?,
                        "value": self.encrypt(&field.value)?,
                        "linkedId": null,
                    }));
                }
            }
            fields.extend(linked);
            self.json["fields"] = serde_json::Value::Array(fields);
        }

        Ok(())
    }

    fn apply_login(
        &mut self,
        old: &LoginForm,
        new: &LoginForm,
    ) -> anyhow::Result<()> {
        let mut login = self
            .json
            .get("login")
            .cloned()
            .filter(serde_json::Value::is_object)
            .unwrap_or_else(|| serde_json::json!({}));
        if new.username != old.username {
            login["username"] = self.encrypt_opt(new.username.as_deref())?;
        }
        if new.totp != old.totp {
            login["totp"] = self.encrypt_opt(new.totp.as_deref())?;
        }
        if new.password != old.password {
            let now = now();
            if old.password.is_some() {
                let mut history: Vec<serde_json::Value> = self
                    .json
                    .get("passwordHistory")
                    .and_then(serde_json::Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                history.insert(
                    0,
                    serde_json::json!({
                        "lastUsedDate": now,
                        "password": login["password"].clone(),
                    }),
                );
                history.truncate(MAX_PASSWORD_HISTORY);
                self.json["passwordHistory"] =
                    serde_json::Value::Array(history);
            }
            login["password"] = self.encrypt_opt(new.password.as_deref())?;
            login["passwordRevisionDate"] = serde_json::Value::String(now);
        }
        if new.uris != old.uris {
            let old_uris: Vec<serde_json::Value> = login
                .get("uris")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut uris = vec![];
            for uri in &new.uris {
                let unchanged = old
                    .uris
                    .iter()
                    .position(|old_uri| old_uri == uri)
                    .and_then(|i| old_uris.get(i));
                if let Some(unchanged) = unchanged {
                    uris.push(unchanged.clone());
                } else {
                    uris.push(self.new_uri(uri)?);
                }
            }
            login["uris"] = serde_json::Value::Array(uris);
        }
        self.json["login"] = login;
        Ok(())
    }

    fn new_uri(&self, uri: &str) -> anyhow::Result<serde_json::Value> {
        // the official clients drop uris whose checksum doesn't match
        let checksum =
            rbw::base64::encode(sha2::Sha256::digest(uri.as_bytes()));
        Ok(serde_json::json!({
            "uri": self.encrypt(uri)?,
            "uriChecksum": self.encrypt(&checksum)?,
            "match": null,
        }))
    }

    fn save(&mut self) -> anyhow::Result<()> {
        let id = self.id()?;
        if let Some(revision_date) = self.json.get("revisionDate").cloned() {
            self.json["lastKnownRevisionDate"] = revision_date;
        }
        let json = self.json.clone();
        api_call(|client, access_token| {
            let mut json = json.clone();
            json["encryptedFor"] = serde_json::Value::String(
                rbw::api::access_token_user_id(access_token)?,
            );
            client.update_cipher(access_token, &id, &json)
        })
        .context("failed to save the entry")?;
        Ok(())
    }
}

pub struct NewItem {
    pub name: String,
    pub username: Option<String>,
    pub uris: Vec<String>,
    pub folder: Option<String>,
    pub secure_note: bool,
    pub changes: Changes,
    pub no_edit: bool,
    pub attach: Vec<std::path::PathBuf>,
}

pub fn add(item: &NewItem) -> anyhow::Result<()> {
    crate::commands::unlock()?;

    let mut form = Form {
        name: item.name.clone(),
        login: if item.secure_note {
            None
        } else {
            Some(LoginForm {
                username: item.username.clone(),
                password: None,
                totp: None,
                uris: item.uris.clone(),
            })
        },
        folder: item.folder.clone(),
        fields: vec![],
        notes: None,
    };
    if item.secure_note && (item.username.is_some() || !item.uris.is_empty())
    {
        return Err(anyhow::anyhow!("secure notes have no username or uris"));
    }

    let interactive = std::io::stdin().is_terminal();
    if !item.changes.is_empty() || item.no_edit {
        item.changes.apply(&mut form)?;
    } else if interactive {
        form = edit_form(&form, item.secure_note)?;
    } else {
        // the historical format: the first line of stdin is the password,
        // the rest are the notes
        let (password, notes) = read_legacy_stdin(!item.secure_note)?;
        if let Some(login) = &mut form.login {
            login.password = password;
        }
        form.notes = notes;
    }

    let mut new = Item {
        json: serde_json::json!({}),
        entry_key: None,
        org_id: None,
    };
    let folder_id = resolve_folder(form.folder.as_deref())?;
    let empty = Form {
        name: String::new(),
        login: form.login.as_ref().map(|_| LoginForm::default()),
        folder: None,
        fields: vec![],
        notes: None,
    };
    new.json = if item.secure_note {
        serde_json::json!({
            "type": 2,
            "secureNote": { "type": 0 },
        })
    } else {
        serde_json::json!({
            "type": 1,
            "login": { "username": null, "password": null, "totp": null, "uris": [] },
        })
    };
    new.json["organizationId"] = serde_json::Value::Null;
    new.json["favorite"] =
        serde_json::Value::Bool(item.changes.favorite.unwrap_or(false));
    new.json["reprompt"] = serde_json::json!(0);
    new.json["notes"] = serde_json::Value::Null;
    new.json["fields"] = serde_json::json!([]);
    new.apply(&empty, &form, folder_id)?;

    let json = new.json.clone();
    let created = api_call(|client, access_token| {
        let mut json = json.clone();
        json["encryptedFor"] = serde_json::Value::String(
            rbw::api::access_token_user_id(access_token)?,
        );
        client.create_cipher(access_token, &json)
    })
    .context("failed to create the entry")?;

    let created = Item::from_json(created);
    for path in &item.attach {
        upload_attachment(&created, path, None)?;
    }

    crate::actions::sync()?;
    Ok(())
}

pub fn edit(
    needle: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    changes: &Changes,
) -> anyhow::Result<()> {
    crate::commands::unlock()?;

    let (entry, _) = find(needle, username, folder, ignore_case)?;
    let mut item = Item::fetch(&entry.id)?;
    let folders = folders()?;
    let old = item.form(&folders)?;

    let new = if !changes.is_empty() {
        let mut new = old.clone();
        changes.apply(&mut new)?;
        new
    } else if std::io::stdin().is_terminal() {
        edit_form(&old, old.login.is_none())?
    } else {
        let (password, notes) = read_legacy_stdin(old.login.is_some())?;
        if password.is_none() && notes.is_none() {
            // most likely run from a script or another program by mistake;
            // an empty stdin would otherwise wipe the password and notes
            return Err(anyhow::anyhow!(
                "stdin is not a terminal and is empty, the entry was not \
                 changed (use the options to change single values)"
            ));
        }
        let mut new = old.clone();
        if let Some(login) = &mut new.login {
            login.password = password;
        }
        new.notes = notes;
        new
    };

    if let Some(favorite) = changes.favorite {
        item.json["favorite"] = serde_json::Value::Bool(favorite);
    } else if new == old {
        eprintln!("no changes");
        return Ok(());
    }

    let folder_id = if new.folder == old.folder {
        string(&item.json, "folderId")
    } else {
        resolve_folder(new.folder.as_deref())?
    };
    item.apply(&old, &new, folder_id)?;
    item.save()?;

    crate::actions::sync()?;
    Ok(())
}

pub fn remove(
    needle: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    permanent: bool,
) -> anyhow::Result<()> {
    crate::commands::unlock()?;

    let (entry, _) = find(needle, username, folder, ignore_case)?;
    if permanent {
        api_call(|client, access_token| {
            client.remove(access_token, &entry.id)
        })
        .context("failed to delete the entry")?;
    } else {
        api_call(|client, access_token| {
            client.trash_cipher(access_token, &entry.id)
        })
        .context("failed to move the entry to the trash")?;
    }

    crate::actions::sync()?;
    Ok(())
}

pub fn trash(raw: bool) -> anyhow::Result<()> {
    crate::commands::unlock()?;

    let items = trashed()?;
    if raw {
        let list: Vec<_> = items
            .iter()
            .map(|(id, name, deleted)| {
                serde_json::json!({
                    "id": id,
                    "name": name,
                    "deleted_date": deleted,
                })
            })
            .collect();
        serde_json::to_writer_pretty(std::io::stdout(), &list)?;
        println!();
    } else {
        for (_, name, _) in items {
            println!("{name}");
        }
    }
    Ok(())
}

pub fn restore(needle: &str) -> anyhow::Result<()> {
    crate::commands::unlock()?;

    let items = trashed()?;
    let matches: Vec<_> = items
        .iter()
        .filter(|(id, name, _)| id == needle || name == needle)
        .collect();
    let (id, _, _) = match matches.as_slice() {
        [] => {
            return Err(anyhow::anyhow!(
                "no entry named '{needle}' in the trash"
            ))
        }
        [one] => *one,
        _ => {
            return Err(anyhow::anyhow!(
                "multiple entries named '{needle}' in the trash, use the id \
                 (see `rbw trash --raw`)"
            ))
        }
    };
    api_call(|client, access_token| client.restore_cipher(access_token, id))
        .context("failed to restore the entry")?;

    crate::actions::sync()?;
    Ok(())
}

// (id, name, deleted date) of every item in the trash
fn trashed() -> anyhow::Result<Vec<(String, String, String)>> {
    let ciphers = api_call(rbw::api::Client::trashed_ciphers)
        .context("failed to read the trash from the server")?;
    let mut items = vec![];
    for json in ciphers {
        let item = Item::from_json(json);
        let name = item
            .decrypt_key("name")
            .unwrap_or_else(|e| Some(format!("<undecryptable: {e}>")))
            .unwrap_or_default();
        items.push((
            item.id()?,
            name,
            string(&item.json, "deletedDate").unwrap_or_default(),
        ));
    }
    items.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(items)
}

pub fn folder_list(raw: bool) -> anyhow::Result<()> {
    crate::commands::unlock()?;

    let folders = folders()?;
    if raw {
        let list: Vec<_> = folders
            .iter()
            .map(|(id, name)| serde_json::json!({ "id": id, "name": name }))
            .collect();
        serde_json::to_writer_pretty(std::io::stdout(), &list)?;
        println!();
    } else {
        for (_, name) in folders {
            println!("{name}");
        }
    }
    Ok(())
}

pub fn folder_add(name: &str) -> anyhow::Result<()> {
    crate::commands::unlock()?;

    if folders()?.iter().any(|(_, existing)| existing == name) {
        return Err(anyhow::anyhow!("folder '{name}' already exists"));
    }
    let encrypted = crate::actions::encrypt(name, None)?;
    api_call(|client, access_token| {
        client.create_folder(access_token, &encrypted)
    })
    .context("failed to create the folder")?;

    crate::actions::sync()?;
    Ok(())
}

pub fn folder_rename(name: &str, new_name: &str) -> anyhow::Result<()> {
    crate::commands::unlock()?;

    let folders = folders()?;
    let id = find_folder(&folders, name)?;
    if folders.iter().any(|(_, existing)| existing == new_name) {
        return Err(anyhow::anyhow!("folder '{new_name}' already exists"));
    }
    let encrypted = crate::actions::encrypt(new_name, None)?;
    api_call(|client, access_token| {
        client.rename_folder(access_token, &id, &encrypted)
    })
    .context("failed to rename the folder")?;

    crate::actions::sync()?;
    Ok(())
}

pub fn folder_remove(name: &str) -> anyhow::Result<()> {
    crate::commands::unlock()?;

    let id = find_folder(&folders()?, name)?;
    // the server moves the folder's entries out of it, it doesn't delete
    // them
    api_call(|client, access_token| client.delete_folder(access_token, &id))
        .context("failed to delete the folder")?;

    crate::actions::sync()?;
    Ok(())
}

pub fn attachment_list(
    needle: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    raw: bool,
) -> anyhow::Result<()> {
    crate::commands::unlock()?;

    let (_, decrypted) = find(needle, username, folder, ignore_case)?;
    if raw {
        serde_json::to_writer_pretty(
            std::io::stdout(),
            &decrypted.attachments,
        )?;
        println!();
    } else {
        for attachment in &decrypted.attachments {
            println!(
                "{}\t{}\t{}",
                attachment.file_name.as_deref().unwrap_or(""),
                attachment.size.as_deref().unwrap_or(""),
                attachment.id
            );
        }
    }
    Ok(())
}

pub fn attachment_get(
    needle: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    attachment: Option<&str>,
    output: Option<&std::path::Path>,
    force: bool,
) -> anyhow::Result<()> {
    crate::commands::unlock()?;

    let (entry, decrypted) = find(needle, username, folder, ignore_case)?;
    let chosen = choose_attachment(&decrypted.attachments, attachment)?;
    let file_name = chosen
        .file_name
        .clone()
        .unwrap_or_else(|| chosen.id.clone());

    let (key, data) = api_call(|client, access_token| {
        client.download_attachment(access_token, &entry.id, &chosen.id)
    })
    .context("failed to download the attachment")?;
    let key = key.or_else(|| {
        entry
            .attachments
            .iter()
            .find(|a| a.id == chosen.id)
            .and_then(|a| a.key.clone())
    });
    let plaintext = crate::actions::decrypt_attachment(
        &data,
        key.as_deref(),
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;

    let output = output.map_or_else(
        || {
            // never let a name from the server write outside the current
            // directory
            std::path::Path::new(&file_name).file_name().map_or_else(
                || std::path::PathBuf::from(&chosen.id),
                std::path::PathBuf::from,
            )
        },
        std::path::Path::to_path_buf,
    );
    if output.as_os_str() == "-" {
        std::io::stdout().write_all(&plaintext)?;
        std::io::stdout().flush()?;
    } else {
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        if force {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }
        let mut fh = options.open(&output).with_context(|| {
            if output.exists() && !force {
                format!(
                    "{} already exists (use --force to overwrite)",
                    output.display()
                )
            } else {
                format!("failed to create {}", output.display())
            }
        })?;
        fh.write_all(&plaintext)?;
        eprintln!("saved {}", output.display());
    }
    Ok(())
}

pub fn attachment_add(
    needle: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    files: &[std::path::PathBuf],
    file_name: Option<&str>,
) -> anyhow::Result<()> {
    crate::commands::unlock()?;

    if files.is_empty() {
        return Err(anyhow::anyhow!("no files given"));
    }
    if file_name.is_some() && files.len() > 1 {
        return Err(anyhow::anyhow!(
            "--name can only be used with a single file"
        ));
    }
    let (entry, _) = find(needle, username, folder, ignore_case)?;
    let item = Item::fetch(&entry.id)?;
    for path in files {
        upload_attachment(&item, path, file_name)?;
    }

    crate::actions::sync()?;
    Ok(())
}

pub fn attachment_remove(
    needle: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    attachment: Option<&str>,
) -> anyhow::Result<()> {
    crate::commands::unlock()?;

    let (entry, decrypted) = find(needle, username, folder, ignore_case)?;
    let chosen = choose_attachment(&decrypted.attachments, attachment)?;
    api_call(|client, access_token| {
        client.delete_attachment(access_token, &entry.id, &chosen.id)
    })
    .context("failed to delete the attachment")?;

    crate::actions::sync()?;
    Ok(())
}

fn upload_attachment(
    item: &Item,
    path: &std::path::Path,
    file_name: Option<&str>,
) -> anyhow::Result<()> {
    let (data, default_name) = if path.as_os_str() == "-" {
        let mut data = vec![];
        std::io::stdin()
            .read_to_end(&mut data)
            .context("failed to read the attachment from stdin")?;
        (data, None)
    } else {
        (
            std::fs::read(path).with_context(|| {
                format!("failed to read {}", path.display())
            })?,
            path.file_name()
                .map(|name| name.to_string_lossy().to_string()),
        )
    };
    let Some(file_name) = file_name.map(str::to_string).or(default_name)
    else {
        return Err(anyhow::anyhow!(
            "--name is required when reading the attachment from stdin"
        ));
    };

    let (key, encrypted) = crate::actions::encrypt_attachment(
        &data,
        item.entry_key.as_deref(),
        item.org_id.as_deref(),
    )?;
    let encrypted_name = crate::actions::encrypt_for_entry(
        &file_name,
        item.entry_key.as_deref(),
        item.org_id.as_deref(),
    )?;
    let id = item.id()?;
    api_call(|client, access_token| {
        client.add_attachment(
            access_token,
            &id,
            &key,
            &encrypted_name,
            encrypted.clone(),
        )
    })
    .with_context(|| format!("failed to upload {file_name}"))?;
    Ok(())
}

fn choose_attachment<'a>(
    attachments: &'a [crate::commands::DecryptedAttachment],
    wanted: Option<&str>,
) -> anyhow::Result<&'a crate::commands::DecryptedAttachment> {
    #[allow(clippy::option_if_let_else)]
    if let Some(wanted) = wanted {
        let matches: Vec<_> = attachments
            .iter()
            .filter(|a| {
                a.id == wanted || a.file_name.as_deref() == Some(wanted)
            })
            .collect();
        match matches.as_slice() {
            [] => Err(anyhow::anyhow!("no attachment named '{wanted}'")),
            [one] => Ok(one),
            _ => Err(anyhow::anyhow!(
                "multiple attachments named '{wanted}', use the id (see \
                 `rbw attachment list`)"
            )),
        }
    } else {
        match attachments {
            [] => Err(anyhow::anyhow!("the entry has no attachments")),
            [one] => Ok(one),
            _ => Err(anyhow::anyhow!(
                "the entry has {} attachments, choose one with --name",
                attachments.len()
            )),
        }
    }
}

fn find(
    needle: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<(rbw::db::Entry, crate::commands::DecryptedCipher)> {
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle
    );
    let db = crate::commands::load_db()?;
    crate::commands::find_entry(&db, needle, username, folder, ignore_case)
        .with_context(|| format!("couldn't find entry for '{desc}'"))
}

// (id, decrypted name) of every folder
fn folders() -> anyhow::Result<Vec<(String, String)>> {
    let folders = api_call(rbw::api::Client::folders)
        .context("failed to list folders")?;
    folders
        .into_iter()
        .map(|(id, name)| {
            Ok((id, crate::actions::decrypt(&name, None, None)?))
        })
        .collect()
}

fn find_folder(
    folders: &[(String, String)],
    name: &str,
) -> anyhow::Result<String> {
    folders
        .iter()
        .find(|(_, existing)| existing == name)
        .map(|(id, _)| id.clone())
        .ok_or_else(|| anyhow::anyhow!("no folder named '{name}'"))
}

// the id of the named folder, which is created if it doesn't exist yet
fn resolve_folder(name: Option<&str>) -> anyhow::Result<Option<String>> {
    let Some(name) = name else {
        return Ok(None);
    };
    if let Ok(id) = find_folder(&folders()?, name) {
        return Ok(Some(id));
    }
    let encrypted = crate::actions::encrypt(name, None)?;
    Ok(Some(
        api_call(|client, access_token| {
            client.create_folder(access_token, &encrypted)
        })
        .context("failed to create the folder")?,
    ))
}

// Runs an api request with the current access token. When the server says
// the token expired, the agent gets a new one (from the refresh token or,
// with persistent_login, the api key) and the request is sent again.
fn api_call<T>(
    f: impl Fn(&rbw::api::Client, &str) -> rbw::error::Result<T>,
) -> anyhow::Result<T> {
    let (client, _) = rbw::actions::api_client()?;
    let access_token = || -> anyhow::Result<String> {
        crate::commands::load_db()?
            .access_token
            .ok_or_else(|| anyhow::anyhow!("not logged in, run `rbw login`"))
    };
    match f(&client, &access_token()?) {
        Err(rbw::error::Error::RequestUnauthorized) => {
            crate::actions::refresh_token()?;
            Ok(f(&client, &access_token()?)?)
        }
        res => Ok(res?),
    }
}

const EDIT_HELP: &str = "\
# Lines starting with '#' above the notes are ignored. Leave a value empty
# to remove it, and repeat 'uri:' or the field lines to add more.
# Custom fields:  text: <name> = <value>
#                 hidden: <name> = <value>
#                 boolean: <name> = true|false
# Everything below the '--- notes ---' line is stored as the notes.
";

fn render_form(form: &Form) -> String {
    // writing to a String can't fail
    let mut out = String::new();
    out.push_str(EDIT_HELP);
    let _ = writeln!(out, "name: {}", form.name);
    if let Some(login) = &form.login {
        let _ = writeln!(
            out,
            "username: {}",
            login.username.as_deref().unwrap_or("")
        );
        let _ = writeln!(
            out,
            "password: {}",
            login.password.as_deref().unwrap_or("")
        );
        let _ =
            writeln!(out, "totp: {}", login.totp.as_deref().unwrap_or(""));
        if login.uris.is_empty() {
            out.push_str("uri: \n");
        }
        for uri in &login.uris {
            let _ = writeln!(out, "uri: {uri}");
        }
    }
    let _ = writeln!(out, "folder: {}", form.folder.as_deref().unwrap_or(""));
    for field in &form.fields {
        let ty = match field.ty {
            FIELD_HIDDEN => "hidden",
            FIELD_BOOLEAN => "boolean",
            _ => "text",
        };
        let _ = writeln!(out, "{ty}: {} = {}", field.name, field.value);
    }
    out.push_str(NOTES_SEPARATOR);
    out.push('\n');
    if let Some(notes) = &form.notes {
        out.push_str(notes);
        out.push('\n');
    }
    out
}

fn parse_form(contents: &str, login: bool) -> anyhow::Result<Form> {
    let mut form = Form {
        name: String::new(),
        login: login.then(LoginForm::default),
        folder: None,
        fields: vec![],
        notes: None,
    };
    let mut lines = contents.split('\n');
    let mut found_separator = false;
    for (n, line) in lines.by_ref().enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line == NOTES_SEPARATOR {
            found_separator = true;
            break;
        }
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err(anyhow::anyhow!(
                "line {}: expected 'key: value', got '{line}'",
                n + 1
            ));
        };
        // exactly one space after the colon belongs to the format, anything
        // else to the value (passwords may start with spaces)
        let value = value.strip_prefix(' ').unwrap_or(value);
        let key = key.trim();
        match key {
            "name" => form.name = value.to_string(),
            "username" => {
                login_values(&mut form, key, n + 1)?.username =
                    non_empty(value);
            }
            "password" => {
                login_values(&mut form, key, n + 1)?.password =
                    non_empty(value);
            }
            "totp" => {
                login_values(&mut form, key, n + 1)?.totp = non_empty(value);
            }
            "uri" => {
                let login = login_values(&mut form, key, n + 1)?;
                if !value.trim().is_empty() {
                    login.uris.push(value.trim().to_string());
                }
            }
            "folder" => form.folder = non_empty(value.trim()),
            "text" | "hidden" | "boolean" => {
                let Some((name, value)) = value.split_once(" = ") else {
                    return Err(anyhow::anyhow!(
                        "line {}: expected '{key}: <name> = <value>'",
                        n + 1
                    ));
                };
                let ty = match key {
                    "hidden" => FIELD_HIDDEN,
                    "boolean" => FIELD_BOOLEAN,
                    _ => FIELD_TEXT,
                };
                if ty == FIELD_BOOLEAN && value != "true" && value != "false"
                {
                    return Err(anyhow::anyhow!(
                        "line {}: boolean fields must be true or false",
                        n + 1
                    ));
                }
                form.fields.push(FormField {
                    ty,
                    name: name.trim().to_string(),
                    value: value.to_string(),
                });
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "line {}: unknown key '{key}'",
                    n + 1
                ))
            }
        }
    }
    if !found_separator {
        return Err(anyhow::anyhow!(
            "the '{NOTES_SEPARATOR}' line is missing"
        ));
    }
    let notes = lines.collect::<Vec<_>>().join("\n");
    form.notes = non_empty(notes.trim_end_matches(['\n', '\r']));
    if form.name.trim().is_empty() {
        return Err(anyhow::anyhow!("the name can't be empty"));
    }
    Ok(form)
}

fn login_values<'a>(
    form: &'a mut Form,
    key: &str,
    line: usize,
) -> anyhow::Result<&'a mut LoginForm> {
    form.login.as_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "line {line}: '{key}' is only valid for login entries"
        )
    })
}

// opens the editor until the contents parse, so that a typo doesn't throw
// away what was written
fn edit_form(form: &Form, secure_note: bool) -> anyhow::Result<Form> {
    let mut contents = render_form(form);
    loop {
        let edited = rbw::edit::edit(&contents, "")?;
        match parse_form(&edited, !secure_note && form.login.is_some()) {
            Ok(form) => return Ok(form),
            Err(e) => {
                eprintln!("{e}");
                eprint!("edit again? [Y/n] ");
                std::io::stderr().flush()?;
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if answer.trim().eq_ignore_ascii_case("n") {
                    return Err(e.context("entry not saved"));
                }
                let edited: String = edited
                    .split('\n')
                    .filter(|line| !line.starts_with("# error: "))
                    .collect::<Vec<_>>()
                    .join("\n");
                contents = format!("# error: {e}\n{edited}");
            }
        }
    }
}

// first line password, the rest notes; lines starting with '#' are dropped
// as before
fn read_legacy_stdin(
    with_password: bool,
) -> anyhow::Result<(Option<String>, Option<String>)> {
    let contents = std::io::read_to_string(std::io::stdin())
        .context("failed to read from stdin")?;
    let contents = if with_password {
        contents
    } else {
        format!("\n{contents}")
    };
    let (password, notes) = crate::commands::parse_legacy_editor(&contents);
    Ok((password.and_then(|p| non_empty(&p)), notes))
}

fn read_password_stdin() -> anyhow::Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("failed to read the password from stdin")?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn string(json: &serde_json::Value, key: &str) -> Option<String> {
    json.get(key)
        .and_then(serde_json::Value::as_str)
        .map(std::string::ToString::to_string)
}

fn now() -> String {
    humantime::format_rfc3339_millis(std::time::SystemTime::now()).to_string()
}

pub fn parse_field(arg: &str) -> Result<(String, String), String> {
    arg.split_once('=')
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .ok_or_else(|| format!("expected <name>=<value>, got '{arg}'"))
}

pub const FIELD_TYPE_TEXT: u64 = FIELD_TEXT;
pub const FIELD_TYPE_HIDDEN: u64 = FIELD_HIDDEN;

#[cfg(test)]
mod tests {
    use super::*;

    fn login_form() -> Form {
        Form {
            name: "example".to_string(),
            login: Some(LoginForm {
                username: Some("me".to_string()),
                password: Some(" spaced pass ".to_string()),
                totp: None,
                uris: vec![
                    "https://a.example".to_string(),
                    "https://b.example".to_string(),
                ],
            }),
            folder: Some("Internet".to_string()),
            fields: vec![
                FormField {
                    ty: FIELD_TEXT,
                    name: "pin".to_string(),
                    value: "1234".to_string(),
                },
                FormField {
                    ty: FIELD_HIDDEN,
                    name: "api key".to_string(),
                    value: "a = b".to_string(),
                },
                FormField {
                    ty: FIELD_BOOLEAN,
                    name: "flag".to_string(),
                    value: "true".to_string(),
                },
            ],
            notes: Some("# not a comment\n\nsecond paragraph".to_string()),
        }
    }

    #[test]
    fn test_form_roundtrip() {
        let form = login_form();
        assert_eq!(parse_form(&render_form(&form), true).unwrap(), form);

        let mut note = form;
        note.login = None;
        note.notes = None;
        assert_eq!(parse_form(&render_form(&note), false).unwrap(), note);
    }

    #[test]
    fn test_form_errors() {
        assert!(parse_form("name: x\n", true).is_err());
        assert!(parse_form("name: \n--- notes ---\n", true).is_err());
        assert!(
            parse_form("name: x\nbogus: y\n--- notes ---\n", true).is_err()
        );
        assert!(parse_form("name: x\nusername: y\n--- notes ---\n", false)
            .is_err());
        assert!(parse_form(
            "name: x\nboolean: f = maybe\n--- notes ---\n",
            true
        )
        .is_err());
    }

    #[test]
    fn test_changes() {
        let mut form = login_form();
        Changes {
            name: Some("renamed".to_string()),
            username: Some(String::new()),
            add_uris: vec!["https://c.example".to_string()],
            fields: vec![
                (FIELD_HIDDEN, "pin".to_string(), "9999".to_string()),
                (FIELD_TEXT, "new".to_string(), "value".to_string()),
            ],
            remove_fields: vec!["flag".to_string()],
            folder: Some(String::new()),
            ..Changes::default()
        }
        .apply(&mut form)
        .unwrap();
        assert_eq!(form.name, "renamed");
        let login = form.login.as_ref().unwrap();
        assert_eq!(login.username, None);
        assert_eq!(login.uris.len(), 3);
        assert_eq!(form.folder, None);
        assert_eq!(
            form.fields,
            vec![
                FormField {
                    ty: FIELD_HIDDEN,
                    name: "pin".to_string(),
                    value: "9999".to_string(),
                },
                FormField {
                    ty: FIELD_HIDDEN,
                    name: "api key".to_string(),
                    value: "a = b".to_string(),
                },
                FormField {
                    ty: FIELD_TEXT,
                    name: "new".to_string(),
                    value: "value".to_string(),
                },
            ]
        );

        let mut note = login_form();
        note.login = None;
        assert!(Changes {
            totp: Some("x".to_string()),
            ..Changes::default()
        }
        .apply(&mut note)
        .is_err());
        assert!(Changes {
            remove_fields: vec!["missing".to_string()],
            ..Changes::default()
        }
        .apply(&mut login_form())
        .is_err());
    }
}
