use std::ffi::OsString;
use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{io::Write as _, os::unix::ffi::OsStrExt as _};

use anyhow::Context as _;

// The default number of seconds the generated TOTP
// code lasts for before a new one must be generated
const TOTP_DEFAULT_STEP: u64 = 30;

const MISSING_CONFIG_HELP: &str =
    "Before using rbw, you must configure the email address you would like to \
    use to log in to the server by running:\n\n    \
        rbw config set email <email>\n\n\
    Additionally, if you are using a self-hosted installation, you should \
    run:\n\n    \
        rbw config set base_url <url>\n\n\
    and, if your server has a non-default identity url:\n\n    \
        rbw config set identity_url <url>\n";

#[derive(Debug, Clone)]
pub enum Needle {
    Name(String),
    Uri(url::Url),
    Uuid(uuid::Uuid, String),
}

impl std::fmt::Display for Needle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match &self {
            Self::Name(name) => name.clone(),
            Self::Uri(uri) => uri.to_string(),
            Self::Uuid(_, s) => s.clone(),
        };
        write!(f, "{value}")
    }
}

#[allow(clippy::unnecessary_wraps)]
pub fn parse_needle(arg: &str) -> Result<Needle, std::convert::Infallible> {
    if let Ok(uuid) = uuid::Uuid::parse_str(arg) {
        return Ok(Needle::Uuid(uuid, arg.to_string()));
    }
    if let Ok(url) = url::Url::parse(arg) {
        if url.is_special() {
            return Ok(Needle::Uri(url));
        }
    }

    Ok(Needle::Name(arg.to_string()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Field {
    Notes,
    Username,
    Password,
    Totp,
    Uris,
    IdentityName,
    City,
    State,
    PostalCode,
    Country,
    Phone,
    Ssn,
    License,
    Passport,
    CardNumber,
    Expiration,
    ExpMonth,
    ExpYear,
    Cvv,
    Cardholder,
    Brand,
    Name,
    Email,
    Address,
    Address1,
    Address2,
    Address3,
    Fingerprint,
    PublicKey,
    PrivateKey,
    Title,
    FirstName,
    MiddleName,
    LastName,
}

impl std::str::FromStr for Field {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "notes" | "note" => Self::Notes,
            "username" | "user" => Self::Username,
            "password" => Self::Password,
            "totp" | "code" => Self::Totp,
            "uris" | "urls" | "sites" => Self::Uris,
            "identityname" => Self::IdentityName,
            "city" => Self::City,
            "state" => Self::State,
            "postcode" | "zipcode" | "zip" => Self::PostalCode,
            "country" => Self::Country,
            "phone" => Self::Phone,
            "ssn" => Self::Ssn,
            "license" => Self::License,
            "passport" => Self::Passport,
            "number" | "card" => Self::CardNumber,
            "exp" => Self::Expiration,
            "exp_month" | "month" => Self::ExpMonth,
            "exp_year" | "year" => Self::ExpYear,
            // the word "code" got preceeded by Totp
            "cvv" => Self::Cvv,
            "cardholder" | "cardholder_name" => Self::Cardholder,
            "brand" | "type" => Self::Brand,
            "name" => Self::Name,
            "email" => Self::Email,
            "address1" => Self::Address1,
            "address2" => Self::Address2,
            "address3" => Self::Address3,
            "address" => Self::Address,
            "fingerprint" => Self::Fingerprint,
            "public_key" => Self::PublicKey,
            "private_key" => Self::PrivateKey,
            "title" => Self::Title,
            "first_name" => Self::FirstName,
            "middle_name" => Self::MiddleName,
            "last_name" => Self::LastName,
            _ => anyhow::bail!("unknown field {s}"),
        })
    }
}

impl Field {
    fn as_str(&self) -> &str {
        match self {
            Self::Notes => "notes",
            Self::Username => "username",
            Self::Password => "password",
            Self::Totp => "totp",
            Self::Uris => "uris",
            Self::IdentityName => "identityname",
            Self::City => "city",
            Self::State => "state",
            Self::PostalCode => "postcode",
            Self::Country => "country",
            Self::Phone => "phone",
            Self::Ssn => "ssn",
            Self::License => "license",
            Self::Passport => "passport",
            Self::CardNumber => "number",
            Self::Expiration => "exp",
            Self::ExpMonth => "exp_month",
            Self::ExpYear => "exp_year",
            Self::Cvv => "cvv",
            Self::Cardholder => "cardholder",
            Self::Brand => "brand",
            Self::Name => "name",
            Self::Email => "email",
            Self::Address1 => "address1",
            Self::Address2 => "address2",
            Self::Address3 => "address3",
            Self::Address => "address",
            Self::Fingerprint => "fingerprint",
            Self::PublicKey => "public_key",
            Self::PrivateKey => "private_key",
            Self::Title => "title",
            Self::FirstName => "first_name",
            Self::MiddleName => "middle_name",
            Self::LastName => "last_name",
        }
    }
}

impl std::fmt::Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, serde::Serialize)]
struct DecryptedListCipher {
    id: String,
    name: Option<String>,
    user: Option<String>,
    folder: Option<String>,
    uris: Option<Vec<String>>,
    #[serde(rename = "type")]
    entry_type: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedSearchCipher {
    id: String,
    #[serde(rename = "type")]
    entry_type: String,
    folder: Option<String>,
    name: String,
    user: Option<String>,
    uris: Vec<(String, Option<rbw::api::UriMatchType>)>,
    fields: Vec<String>,
    notes: Option<String>,
}

impl DecryptedSearchCipher {
    fn display_name(&self) -> String {
        self.user.as_ref().map_or_else(
            || self.name.clone(),
            |user| format!("{user}@{}", self.name),
        )
    }

    fn matches(
        &self,
        needle: &Needle,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
        strict_username: bool,
        strict_folder: bool,
        exact: bool,
    ) -> bool {
        let match_str = match (ignore_case, exact) {
            (true, true) => |field: &str, search_term: &str| {
                field.to_lowercase() == search_term.to_lowercase()
            },
            (true, false) => |field: &str, search_term: &str| {
                field.to_lowercase().contains(&search_term.to_lowercase())
            },
            (false, true) => {
                |field: &str, search_term: &str| field == search_term
            }
            (false, false) => {
                |field: &str, search_term: &str| field.contains(search_term)
            }
        };

        match (self.folder.as_deref(), folder) {
            (Some(folder), Some(given_folder)) => {
                if !match_str(folder, given_folder) {
                    return false;
                }
            }
            (Some(_), None) => {
                if strict_folder {
                    return false;
                }
            }
            (None, Some(_)) => {
                return false;
            }
            (None, None) => {}
        }

        match (&self.user, username) {
            (Some(username), Some(given_username)) => {
                if !match_str(username, given_username) {
                    return false;
                }
            }
            (Some(_), None) => {
                if strict_username {
                    return false;
                }
            }
            (None, Some(_)) => {
                return false;
            }
            (None, None) => {}
        }

        match needle {
            Needle::Uuid(uuid, s) => {
                if uuid::Uuid::parse_str(&self.id) != Ok(*uuid)
                    && !match_str(&self.name, s)
                {
                    return false;
                }
            }
            Needle::Name(name) => {
                if !match_str(&self.name, name) {
                    return false;
                }
            }
            Needle::Uri(given_uri) => {
                if self.uris.iter().all(|(uri, match_type)| {
                    !matches_url(uri, *match_type, given_uri)
                }) {
                    return false;
                }
            }
        }

        true
    }

    fn search_match(&self, term: &str, folder: Option<&str>) -> bool {
        if let Some(folder) = folder {
            if self.folder.as_deref() != Some(folder) {
                return false;
            }
        }

        let mut fields = vec![self.name.clone()];
        if let Some(notes) = &self.notes {
            fields.push(notes.clone());
        }
        if let Some(user) = &self.user {
            fields.push(user.clone());
        }
        fields.extend(self.uris.iter().map(|(uri, _)| uri).cloned());
        fields.extend(self.fields.iter().cloned());

        for field in fields {
            if field.to_lowercase().contains(&term.to_lowercase()) {
                return true;
            }
        }

        false
    }
}

impl From<DecryptedSearchCipher> for DecryptedListCipher {
    fn from(value: DecryptedSearchCipher) -> Self {
        Self {
            id: value.id,
            entry_type: Some(value.entry_type),
            name: Some(value.name),
            user: value.user,
            folder: value.folder,
            uris: Some(value.uris.into_iter().map(|(s, _)| s).collect()),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DecryptedCipher {
    id: String,
    folder: Option<String>,
    name: String,
    data: DecryptedData,
    fields: Vec<DecryptedField>,
    notes: Option<String>,
    history: Vec<DecryptedHistoryEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<DecryptedAttachment>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DecryptedAttachment {
    pub id: String,
    pub file_name: Option<String>,
    pub size: Option<String>,
}

impl DecryptedCipher {
    fn display_short(&self, desc: &str, clipboard: bool) -> bool {
        match &self.data {
            DecryptedData::Login { password, .. } => {
                password.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no password");
                        false
                    },
                    |password| val_display_or_store(clipboard, password),
                )
            }
            DecryptedData::Card { number, .. } => {
                number.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no card number");
                        false
                    },
                    |number| val_display_or_store(clipboard, number),
                )
            }
            DecryptedData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                let names: Vec<_> =
                    [title, first_name, middle_name, last_name]
                        .iter()
                        .copied()
                        .flatten()
                        .cloned()
                        .collect();
                if names.is_empty() {
                    eprintln!("entry for '{desc}' had no name");
                    false
                } else {
                    val_display_or_store(clipboard, &names.join(" "))
                }
            }
            DecryptedData::SecureNote => self.notes.as_ref().map_or_else(
                || {
                    eprintln!("entry for '{desc}' had no notes");
                    false
                },
                |notes| val_display_or_store(clipboard, notes),
            ),
            DecryptedData::SshKey { public_key, .. } => {
                public_key.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no public key");
                        false
                    },
                    |public_key| val_display_or_store(clipboard, public_key),
                )
            }
        }
    }

    fn display_field(&self, desc: &str, field: &str, clipboard: bool) {
        let field = field.to_lowercase();
        let field = field.as_str();
        match &self.data {
            DecryptedData::Login {
                username,
                totp,
                uris,
                ..
            } => match field.parse() {
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                Ok(Field::Username) => {
                    if let Some(username) = &username {
                        val_display_or_store(clipboard, username);
                    }
                }
                Ok(Field::Totp) => {
                    if let Some(totp) = totp {
                        match generate_totp(totp) {
                            Ok(code) => {
                                val_display_or_store(clipboard, &code);
                            }
                            Err(e) => {
                                eprintln!("{e}");
                            }
                        }
                    }
                }
                Ok(Field::Uris) => {
                    if let Some(uris) = uris {
                        let uri_strs: Vec<_> =
                            uris.iter().map(|uri| uri.uri.clone()).collect();
                        val_display_or_store(clipboard, &uri_strs.join("\n"));
                    }
                }
                Ok(Field::Password) => {
                    self.display_short(desc, clipboard);
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => match field.parse() {
                Ok(Field::CardNumber) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::Expiration) => {
                    if let (Some(month), Some(year)) = (exp_month, exp_year) {
                        val_display_or_store(
                            clipboard,
                            &format!("{month}/{year}"),
                        );
                    }
                }
                Ok(Field::ExpMonth) => {
                    if let Some(exp_month) = exp_month {
                        val_display_or_store(clipboard, exp_month);
                    }
                }
                Ok(Field::ExpYear) => {
                    if let Some(exp_year) = exp_year {
                        val_display_or_store(clipboard, exp_year);
                    }
                }
                Ok(Field::Cvv) => {
                    if let Some(code) = code {
                        val_display_or_store(clipboard, code);
                    }
                }
                Ok(Field::Name | Field::Cardholder) => {
                    if let Some(cardholder_name) = cardholder_name {
                        val_display_or_store(clipboard, cardholder_name);
                    }
                }
                Ok(Field::Brand) => {
                    if let Some(brand) = brand {
                        val_display_or_store(clipboard, brand);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::Identity {
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
                ..
            } => match field.parse() {
                Ok(Field::Name) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::Email) => {
                    if let Some(email) = email {
                        val_display_or_store(clipboard, email);
                    }
                }
                Ok(Field::Address) => {
                    let mut strs = vec![];
                    if let Some(address1) = address1 {
                        strs.push(address1.clone());
                    }
                    if let Some(address2) = address2 {
                        strs.push(address2.clone());
                    }
                    if let Some(address3) = address3 {
                        strs.push(address3.clone());
                    }
                    if !strs.is_empty() {
                        val_display_or_store(clipboard, &strs.join("\n"));
                    }
                }
                Ok(Field::City) => {
                    if let Some(city) = city {
                        val_display_or_store(clipboard, city);
                    }
                }
                Ok(Field::State) => {
                    if let Some(state) = state {
                        val_display_or_store(clipboard, state);
                    }
                }
                Ok(Field::PostalCode) => {
                    if let Some(postal_code) = postal_code {
                        val_display_or_store(clipboard, postal_code);
                    }
                }
                Ok(Field::Country) => {
                    if let Some(country) = country {
                        val_display_or_store(clipboard, country);
                    }
                }
                Ok(Field::Phone) => {
                    if let Some(phone) = phone {
                        val_display_or_store(clipboard, phone);
                    }
                }
                Ok(Field::Ssn) => {
                    if let Some(ssn) = ssn {
                        val_display_or_store(clipboard, ssn);
                    }
                }
                Ok(Field::License) => {
                    if let Some(license_number) = license_number {
                        val_display_or_store(clipboard, license_number);
                    }
                }
                Ok(Field::Passport) => {
                    if let Some(passport_number) = passport_number {
                        val_display_or_store(clipboard, passport_number);
                    }
                }
                Ok(Field::Username) => {
                    if let Some(username) = username {
                        val_display_or_store(clipboard, username);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::SecureNote => match field.parse() {
                Ok(Field::Notes) => {
                    self.display_short(desc, clipboard);
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::SshKey {
                fingerprint,
                private_key,
                ..
            } => match field.parse() {
                Ok(Field::Fingerprint) => {
                    if let Some(fingerprint) = fingerprint {
                        val_display_or_store(clipboard, fingerprint);
                    }
                }
                Ok(Field::PublicKey) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::PrivateKey) => {
                    if let Some(private_key) = private_key {
                        val_display_or_store(clipboard, private_key);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
        }
    }

    fn display_long(&self, desc: &str, clipboard: bool) {
        match &self.data {
            DecryptedData::Login {
                username,
                totp,
                uris,
                ..
            } => {
                let mut displayed = self.display_short(desc, clipboard);
                displayed |=
                    display_field("Username", username.as_deref(), clipboard);
                displayed |=
                    display_field("TOTP Secret", totp.as_deref(), clipboard);

                if let Some(uris) = uris {
                    for uri in uris {
                        displayed |=
                            display_field("URI", Some(&uri.uri), clipboard);
                        let match_type =
                            uri.match_type.map(|ty| format!("{ty}"));
                        displayed |= display_field(
                            "Match type",
                            match_type.as_deref(),
                            clipboard,
                        );
                    }
                }

                for field in &self.fields {
                    displayed |= display_field(
                        field.name.as_deref().unwrap_or("(null)"),
                        Some(field.value.as_deref().unwrap_or("")),
                        clipboard,
                    );
                }

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
            DecryptedData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => {
                let mut displayed = false;

                displayed |= self.display_short(desc, clipboard);
                if let (Some(exp_month), Some(exp_year)) =
                    (exp_month, exp_year)
                {
                    println!("Expiration: {exp_month}/{exp_year}");
                    displayed = true;
                }
                displayed |= display_field("CVV", code.as_deref(), clipboard);
                displayed |= display_field(
                    "Name",
                    cardholder_name.as_deref(),
                    clipboard,
                );
                displayed |=
                    display_field("Brand", brand.as_deref(), clipboard);

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
            DecryptedData::Identity {
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
                ..
            } => {
                let mut displayed = self.display_short(desc, clipboard);

                displayed |=
                    display_field("Address", address1.as_deref(), clipboard);
                displayed |=
                    display_field("Address", address2.as_deref(), clipboard);
                displayed |=
                    display_field("Address", address3.as_deref(), clipboard);
                displayed |=
                    display_field("City", city.as_deref(), clipboard);
                displayed |=
                    display_field("State", state.as_deref(), clipboard);
                displayed |= display_field(
                    "Postcode",
                    postal_code.as_deref(),
                    clipboard,
                );
                displayed |=
                    display_field("Country", country.as_deref(), clipboard);
                displayed |=
                    display_field("Phone", phone.as_deref(), clipboard);
                displayed |=
                    display_field("Email", email.as_deref(), clipboard);
                displayed |= display_field("SSN", ssn.as_deref(), clipboard);
                displayed |= display_field(
                    "License",
                    license_number.as_deref(),
                    clipboard,
                );
                displayed |= display_field(
                    "Passport",
                    passport_number.as_deref(),
                    clipboard,
                );
                displayed |=
                    display_field("Username", username.as_deref(), clipboard);

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
            DecryptedData::SecureNote => {
                self.display_short(desc, clipboard);
            }
            DecryptedData::SshKey { fingerprint, .. } => {
                let mut displayed = self.display_short(desc, clipboard);
                displayed |= display_field(
                    "Fingerprint",
                    fingerprint.as_deref(),
                    clipboard,
                );

                for field in &self.fields {
                    displayed |= display_field(
                        field.name.as_deref().unwrap_or("(null)"),
                        Some(field.value.as_deref().unwrap_or("")),
                        clipboard,
                    );
                }

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
        }
    }

    /// This implementation mirror the `fn display_fied` method on which field to list
    fn display_fields_list(&self) {
        match &self.data {
            DecryptedData::Login {
                username,
                password,
                totp,
                uris,
                ..
            } => {
                if username.is_some() {
                    println!("{}", Field::Username);
                }
                if totp.is_some() {
                    println!("{}", Field::Totp);
                }
                if uris.is_some() {
                    println!("{}", Field::Uris);
                }
                if password.is_some() {
                    println!("{}", Field::Password);
                }
            }
            DecryptedData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => {
                if number.is_some() {
                    println!("{}", Field::CardNumber);
                }
                if exp_month.is_some() {
                    println!("{}", Field::ExpMonth);
                }
                if exp_year.is_some() {
                    println!("{}", Field::ExpYear);
                }
                if code.is_some() {
                    println!("{}", Field::Cvv);
                }
                if cardholder_name.is_some() {
                    println!("{}", Field::Cardholder);
                }
                if brand.is_some() {
                    println!("{}", Field::Brand);
                }
            }

            DecryptedData::Identity {
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                if [title, first_name, middle_name, last_name]
                    .iter()
                    .any(|f| f.is_some())
                {
                    // the display_field combines all these fields together.
                    println!("name");
                }
                if email.is_some() {
                    println!("{}", Field::Email);
                }
                if [address1, address2, address3].iter().any(|f| f.is_some())
                {
                    // the display_field combines all these fields together.
                    println!("address");
                }
                if city.is_some() {
                    println!("{}", Field::City);
                }
                if state.is_some() {
                    println!("{}", Field::State);
                }
                if postal_code.is_some() {
                    println!("{}", Field::PostalCode);
                }
                if country.is_some() {
                    println!("{}", Field::Country);
                }
                if phone.is_some() {
                    println!("{}", Field::Phone);
                }
                if ssn.is_some() {
                    println!("{}", Field::Ssn);
                }
                if license_number.is_some() {
                    println!("{}", Field::License);
                }
                if passport_number.is_some() {
                    println!("{}", Field::Passport);
                }
                if username.is_some() {
                    println!("{}", Field::Username);
                }
            }

            DecryptedData::SecureNote => (), // handled at the end
            DecryptedData::SshKey {
                fingerprint,
                public_key,
                ..
            } => {
                if fingerprint.is_some() {
                    println!("{}", Field::Fingerprint);
                }
                if public_key.is_some() {
                    println!("{}", Field::PublicKey);
                }
            }
        }

        if self.notes.is_some() {
            println!("{}", Field::Notes);
        }
        for f in &self.fields {
            if let Some(name) = &f.name {
                println!("{name}");
            }
        }
    }

    fn display_json(&self, desc: &str) -> anyhow::Result<()> {
        serde_json::to_writer_pretty(std::io::stdout(), &self)
            .context(format!("failed to write entry '{desc}' to stdout"))?;
        println!();

        Ok(())
    }
}

fn val_display_or_store(clipboard: bool, password: &str) -> bool {
    if clipboard {
        match clipboard_store(password) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("{e}");
                false
            }
        }
    } else {
        println!("{password}");
        true
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
#[cfg_attr(test, derive(Eq, PartialEq))]
enum DecryptedData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Option<Vec<DecryptedUri>>,
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
        public_key: Option<String>,
        fingerprint: Option<String>,
        private_key: Option<String>,
    },
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedField {
    name: Option<String>,
    value: Option<String>,
    #[serde(serialize_with = "serialize_field_type", rename = "type")]
    ty: Option<rbw::api::FieldType>,
}

#[allow(clippy::trivially_copy_pass_by_ref, clippy::ref_option)]
fn serialize_field_type<S>(
    ty: &Option<rbw::api::FieldType>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match ty {
        Some(ty) => {
            let s = match ty {
                rbw::api::FieldType::Text => "text",
                rbw::api::FieldType::Hidden => "hidden",
                rbw::api::FieldType::Boolean => "boolean",
                rbw::api::FieldType::Linked => "linked",
            };
            serializer.serialize_some(&Some(s))
        }
        None => serializer.serialize_none(),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedHistoryEntry {
    last_used_date: String,
    password: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedUri {
    uri: String,
    match_type: Option<rbw::api::UriMatchType>,
}

fn matches_url(
    url: &str,
    match_type: Option<rbw::api::UriMatchType>,
    given_url: &url::Url,
) -> bool {
    match match_type.unwrap_or(rbw::api::UriMatchType::Domain) {
        rbw::api::UriMatchType::Domain => {
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url) {
                if let Some(self_host_port) = host_port(&self_url) {
                    if self_url.scheme() == given_url.scheme()
                        && (self_host_port == given_host_port
                            || given_host_port
                                .ends_with(&format!(".{self_host_port}")))
                    {
                        return true;
                    }
                }
            }
            url == given_host_port
                || given_host_port.ends_with(&format!(".{url}"))
        }
        rbw::api::UriMatchType::Host => {
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url) {
                if let Some(self_host_port) = host_port(&self_url) {
                    if self_url.scheme() == given_url.scheme()
                        && self_host_port == given_host_port
                    {
                        return true;
                    }
                }
            }
            url == given_host_port
        }
        rbw::api::UriMatchType::StartsWith => {
            given_url.to_string().starts_with(url)
        }
        rbw::api::UriMatchType::Exact => {
            if given_url.path() == "/" {
                given_url.to_string().trim_end_matches('/')
                    == url.trim_end_matches('/')
            } else {
                given_url.to_string() == url
            }
        }
        rbw::api::UriMatchType::RegularExpression => {
            let Ok(rx) = regex::Regex::new(url) else {
                return false;
            };
            rx.is_match(given_url.as_ref())
        }
        rbw::api::UriMatchType::Never => false,
    }
}

fn host_port(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(
        url.port().map_or_else(
            || host.to_string(),
            |port| format!("{host}:{port}"),
        ),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListField {
    Id,
    Name,
    User,
    Folder,
    Uri,
    EntryType,
}

impl ListField {
    fn all() -> Vec<Self> {
        vec![
            Self::Id,
            Self::Name,
            Self::User,
            Self::Folder,
            Self::Uri,
            Self::EntryType,
        ]
    }
}

impl std::convert::TryFrom<&String> for ListField {
    type Error = anyhow::Error;

    fn try_from(s: &String) -> anyhow::Result<Self> {
        Ok(match s.as_str() {
            "name" => Self::Name,
            "id" => Self::Id,
            "user" => Self::User,
            "folder" => Self::Folder,
            "type" => Self::EntryType,
            _ => return Err(anyhow::anyhow!("unknown field {s}")),
        })
    }
}

pub fn config_show() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    serde_json::to_writer_pretty(std::io::stdout(), &config)
        .context("failed to write config to stdout")?;
    println!();

    Ok(())
}

pub fn config_set(key: &str, value: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = Some(value.to_string()),
        "sso_id" => config.sso_id = Some(value.to_string()),
        "base_url" => config.base_url = Some(value.to_string()),
        "identity_url" => config.identity_url = Some(value.to_string()),
        "ui_url" => config.ui_url = Some(value.to_string()),
        "notifications_url" => {
            config.notifications_url = Some(value.to_string());
        }
        "client_cert_path" => {
            config.client_cert_path =
                Some(std::path::PathBuf::from(value.to_string()));
        }
        "lock_timeout" => {
            config.lock_timeout = rbw::config::parse_lock_timeout(value)
                .map_err(|e| anyhow::anyhow!(e))?;
        }
        "sync_interval" => {
            let interval = value
                .parse()
                .context("failed to parse value for sync_interval")?;
            config.sync_interval = interval;
        }
        "pinentry" => config.pinentry = value.to_string(),
        "persistent_login" => {
            config.persistent_login = parse_bool(value)
                .context("failed to parse value for persistent_login")?;
        }
        "notify" => {
            config.notify = parse_bool(value)
                .context("failed to parse value for notify")?;
        }
        "system_auth" => {
            let on = parse_bool(value)
                .context("failed to parse value for system_auth")?;
            if on && !block_on(rbw::biometric::polkit_available()) {
                return Err(anyhow::anyhow!(
                    "the polkit action {} is not installed: see \
                     contrib/polkit/README.md",
                    rbw::biometric::POLKIT_ACTION
                ));
            }
            config.system_auth = on;
        }
        "auto_unlock" => {
            config.auto_unlock = parse_bool(value)
                .context("failed to parse value for auto_unlock")?;
        }
        "tui_auth" => {
            let on = parse_bool(value)
                .context("failed to parse value for tui_auth")?;
            if on && !block_on(rbw::biometric::polkit_available()) {
                return Err(anyhow::anyhow!(
                    "the polkit action {} is not installed: see \
                     contrib/polkit/README.md",
                    rbw::biometric::POLKIT_ACTION
                ));
            }
            config.tui_auth = on;
        }
        "lock_on_sleep" => {
            config.lock_on_sleep = parse_bool(value)
                .context("failed to parse value for lock_on_sleep")?;
        }
        "lock_on_idle" => {
            config.lock_on_idle = parse_bool(value)
                .context("failed to parse value for lock_on_idle")?;
        }
        "timeout_action" => {
            config.timeout_action =
                value.parse().map_err(|e: String| anyhow::anyhow!(e))?;
        }
        "sort_by_usage" => {
            config.sort_by_usage = parse_bool(value)
                .context("failed to parse value for sort_by_usage")?;
        }
        "attachments_dir" => {
            config.attachments_dir = (!value.is_empty())
                .then(|| std::path::PathBuf::from(value));
        }
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    config.save()?;
    apply_config(key)
}

pub fn config_unset(key: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = None,
        "sso_id" => config.sso_id = None,
        "base_url" => config.base_url = None,
        "identity_url" => config.identity_url = None,
        "ui_url" => config.ui_url = None,
        "notifications_url" => config.notifications_url = None,
        "client_cert_path" => config.client_cert_path = None,
        "lock_timeout" => {
            config.lock_timeout = rbw::config::default_lock_timeout();
        }
        "pinentry" => config.pinentry = rbw::config::default_pinentry(),
        "persistent_login" => config.persistent_login = false,
        "notify" => config.notify = rbw::config::default_notify(),
        "system_auth" => config.system_auth = false,
        "auto_unlock" => config.auto_unlock = false,
        "tui_auth" => config.tui_auth = false,
        "lock_on_sleep" => config.lock_on_sleep = false,
        "lock_on_idle" => config.lock_on_idle = false,
        "timeout_action" => {
            config.timeout_action = rbw::config::TimeoutAction::default();
        }
        "sort_by_usage" => config.sort_by_usage = false,
        "attachments_dir" => config.attachments_dir = None,
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    config.save()?;
    apply_config(key)
}

// settings the running agent can pick up; anything else (email, urls...)
// restarts it
const LIVE_KEYS: &[&str] = &[
    "lock_timeout",
    "lock_on_sleep",
    "lock_on_idle",
    "timeout_action",
    "system_auth",
    "auto_unlock",
    "tui_auth",
    "sort_by_usage",
    "notify",
    // read by the tui when it saves, the agent doesn't use it
    "attachments_dir",
];

fn apply_config(key: &str) -> anyhow::Result<()> {
    if LIVE_KEYS.contains(&key) {
        if crate::actions::status()?.is_some() {
            crate::actions::reload_config()?;
        }
        return Ok(());
    }

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `rbw config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()
}

fn parse_bool(value: &str) -> anyhow::Result<bool> {
    match value {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(anyhow::anyhow!("expected true or false, got '{value}'")),
    }
}

fn clipboard_store(val: &str) -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::clipboard_store(val)?;

    Ok(())
}

pub fn register() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::register()?;

    Ok(())
}

pub fn login() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;

    Ok(())
}

pub fn unlock() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;
    crate::actions::unlock()?;

    Ok(())
}

pub fn unlocked() -> anyhow::Result<()> {
    // not ensure_agent, because we don't want `rbw unlocked` to start the
    // agent if it's not running
    let _ = check_agent_version();
    crate::actions::unlocked()?;

    Ok(())
}

pub fn sync() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;
    crate::actions::sync()?;

    Ok(())
}

pub fn list(fields: &[String], raw: bool) -> anyhow::Result<()> {
    let fields: Vec<ListField> = if raw {
        ListField::all()
    } else {
        fields
            .iter()
            .map(std::convert::TryFrom::try_from)
            .collect::<anyhow::Result<_>>()?
    };

    unlock()?;

    let db = load_db()?;
    let mut entries: Vec<DecryptedListCipher> =
        batch_decrypt(&db.entries, |entry, decryptor| {
            decrypt_list_cipher(entry, &fields, decryptor)
        })?;
    sort_entries(&mut entries);

    print_entry_list(&entries, &fields, raw)?;

    Ok(())
}

#[allow(clippy::fn_params_excessive_bools)]
pub fn get(
    needle: Needle,
    user: Option<&str>,
    folder: Option<&str>,
    field: Option<&str>,
    full: bool,
    raw: bool,
    clipboard: bool,
    ignore_case: bool,
    list_fields: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let (entry, decrypted) =
        find_entry(&db, needle, user, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    rbw::usage::Usage::record(&entry.id);
    if list_fields {
        decrypted.display_fields_list();
    } else if raw {
        decrypted.display_json(&desc)?;
    } else if full {
        decrypted.display_long(&desc, clipboard);
    } else if let Some(field) = field {
        decrypted.display_field(&desc, field, clipboard);
    } else {
        decrypted.display_short(&desc, clipboard);
    }

    Ok(())
}

// by name, or with sort_by_usage the most used first
fn sort_entries(entries: &mut [DecryptedListCipher]) {
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    if rbw::config::Config::load().is_ok_and(|c| c.sort_by_usage) {
        let usage = rbw::usage::Usage::load();
        entries.sort_by(|a, b| {
            usage.score(&b.id).total_cmp(&usage.score(&a.id))
        });
    }
}

fn print_entry_list(
    entries: &[DecryptedListCipher],
    fields: &[ListField],
    raw: bool,
) -> anyhow::Result<()> {
    if raw {
        serde_json::to_writer_pretty(std::io::stdout(), &entries)
            .context("failed to write entries to stdout".to_string())?;
        println!();
    } else {
        for entry in entries {
            let values: Vec<String> = fields
                .iter()
                .map(|field| match field {
                    ListField::Id => entry.id.clone(),
                    ListField::Name => entry.name.as_ref().map_or_else(
                        String::new,
                        std::string::ToString::to_string,
                    ),
                    ListField::User => entry.user.as_ref().map_or_else(
                        String::new,
                        std::string::ToString::to_string,
                    ),
                    ListField::Folder => entry.folder.as_ref().map_or_else(
                        String::new,
                        std::string::ToString::to_string,
                    ),
                    ListField::Uri => {
                        // "uri" is not listed in the TryFrom
                        // implementation, so there's no way to try to
                        // print it (and it's not clear what that would
                        // look like, since it's a list and not a single
                        // string)
                        unreachable!()
                    }
                    ListField::EntryType => {
                        entry.entry_type.as_ref().map_or_else(
                            String::new,
                            std::string::ToString::to_string,
                        )
                    }
                })
                .collect();

            // write to stdout but don't panic when pipe get's closed
            // this happens when piping stdout in a shell
            match writeln!(&mut std::io::stdout(), "{}", values.join("\t")) {
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    Ok(())
                }
                res => res,
            }?;
        }
    }

    Ok(())
}

pub fn search(
    term: &str,
    fields: &[String],
    folder: Option<&str>,
    raw: bool,
) -> anyhow::Result<()> {
    let fields: Vec<ListField> = if raw {
        ListField::all()
    } else {
        fields
            .iter()
            .map(std::convert::TryFrom::try_from)
            .collect::<anyhow::Result<_>>()?
    };

    unlock()?;

    let db = load_db()?;

    let mut entries: Vec<DecryptedListCipher> =
        batch_decrypt(&db.entries, |entry, decryptor| {
            decrypt_search_cipher(entry, decryptor)
        })?
        .into_iter()
        .filter(|entry| entry.search_match(term, folder))
        .map(std::convert::Into::into)
        .collect();
    sort_entries(&mut entries);

    print_entry_list(&entries, &fields, raw)?;

    Ok(())
}

pub fn code(
    needle: Needle,
    user: Option<&str>,
    folder: Option<&str>,
    clipboard: bool,
    ignore_case: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let (entry, decrypted) =
        find_entry(&db, needle, user, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    rbw::usage::Usage::record(&entry.id);

    if let DecryptedData::Login { totp, .. } = decrypted.data {
        if let Some(totp) = totp {
            val_display_or_store(clipboard, &generate_totp(&totp)?);
        } else {
            return Err(anyhow::anyhow!(
                "entry does not contain a totp secret"
            ));
        }
    } else {
        return Err(anyhow::anyhow!("not a login entry"));
    }

    Ok(())
}

pub fn generate(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    len: usize,
    ty: rbw::pwgen::Type,
) -> anyhow::Result<()> {
    let password = rbw::pwgen::pwgen(ty, len);
    println!("{password}");

    if let Some(name) = name {
        crate::items::add(&crate::items::NewItem {
            name: name.to_string(),
            username: username.map(std::string::ToString::to_string),
            uris: uris.iter().map(|(uri, _)| uri.clone()).collect(),
            folder: folder.map(std::string::ToString::to_string),
            kind: crate::items::Kind::Login,
            org: None,
            collections: vec![],
            password: None,
            changes: crate::items::Changes {
                password: Some(password),
                ..crate::items::Changes::default()
            },
            no_edit: true,
            attach: vec![],
        })?;
    }

    Ok(())
}

pub fn history(
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let (_, decrypted) = find_entry(&db, name, username, folder, ignore_case)
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    for history in decrypted.history {
        println!("{}: {}", history.last_used_date, history.password);
    }

    Ok(())
}

pub fn lock(hard: bool) -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::lock(hard)?;

    Ok(())
}

#[derive(serde::Serialize)]
struct StatusOutput {
    agent: bool,
    logged_in: bool,
    locked: bool,
    keys_in_memory: bool,
    system_auth: bool,
    pin: bool,
    login_expired: bool,
    // unix time of the last successful sync
    last_sync: Option<u64>,
    // for bars and panels: whose vault, and how it opens
    email: Option<String>,
    server: Option<String>,
    // unlocks with the saved password, without asking
    auto_unlock: bool,
    // system authentication once per login session to open the tui
    tui_auth: bool,
}

// cheap enough to be polled by a status bar: it never starts the agent,
// never prompts and doesn't decrypt anything
pub fn status(json: bool) -> anyhow::Result<()> {
    let config = rbw::config::Config::load().ok();
    let db_file = config.as_ref().and_then(|config| {
        config
            .email
            .as_ref()
            .map(|email| rbw::dirs::db_file(&config.server_name(), email))
    });
    let last_sync = db_file
        .as_ref()
        .and_then(|file| std::fs::metadata(file).ok())
        .and_then(|meta| meta.modified().ok())
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    let agent = crate::actions::status()?;
    let system_auth = agent.as_ref().map_or_else(
        || config.as_ref().is_some_and(|config| config.system_auth),
        |agent| agent.system_auth,
    );
    let pin = agent
        .as_ref()
        .map_or_else(rbw::pin::is_set, |agent| agent.pin);
    let out = StatusOutput {
        agent: agent.is_some(),
        logged_in: last_sync.is_some(),
        locked: agent.as_ref().is_none_or(|agent| agent.locked),
        keys_in_memory: agent.as_ref().is_some_and(|a| a.keys_in_memory),
        system_auth,
        pin,
        login_expired: agent.as_ref().is_some_and(|a| a.login_expired),
        last_sync,
        email: config.as_ref().and_then(|c| c.email.clone()),
        server: config.as_ref().map(|c| {
            let url = c.base_url();
            url::Url::parse(&url)
                .ok()
                .and_then(|u| u.host_str().map(ToString::to_string))
                .unwrap_or(url)
        }),
        auto_unlock: config
            .as_ref()
            .is_some_and(|c| c.auto_unlock && c.saved_password.is_some()),
        tui_auth: config.as_ref().is_some_and(|c| c.tui_auth),
    };

    if json {
        println!("{}", serde_json::to_string(&out)?);
    } else {
        let state = if !out.logged_in {
            "logged out"
        } else if out.login_expired {
            "login expired"
        } else if !out.agent {
            "agent not running"
        } else if !out.locked {
            "unlocked"
        } else if out.keys_in_memory {
            "locked (pin or system unlock ready)"
        } else {
            "locked"
        };
        println!("{state}");
    }

    Ok(())
}

pub fn remember_password(store: Option<&str>) -> anyhow::Result<()> {
    let store = store
        .map(str::parse::<rbw::biometric::SecretStore>)
        .transpose()?;
    ensure_agent()?;
    let store = crate::actions::remember_password(store)?;

    let mut config = rbw::config::Config::load()?;
    config.saved_password = Some(store);
    config.save()?;
    println!("master password saved in {}", store.name());

    Ok(())
}

pub fn forget_password() -> anyhow::Result<()> {
    if crate::actions::status()?.is_some() {
        crate::actions::forget_password()?;
    } else if let Some(store) = rbw::config::Config::load()?.saved_password {
        block_on(rbw::biometric::forget(store))?;
    }
    let mut config = rbw::config::Config::load()?;
    config.saved_password = None;
    config.save()?;

    Ok(())
}

pub fn pin_set() -> anyhow::Result<()> {
    unlock()?;
    crate::actions::pin_set()?;
    println!("pin set");

    Ok(())
}

pub fn pin_clear() -> anyhow::Result<()> {
    if crate::actions::status()?.is_some() {
        crate::actions::pin_clear()?;
    } else {
        rbw::pin::clear()?;
    }

    Ok(())
}

pub fn security() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    let yes_no = |b: bool| if b { "yes" } else { "no" };
    let timeout = if config.lock_timeout == 0 {
        "never (until the agent stops)".to_string()
    } else {
        humantime::format_duration(std::time::Duration::from_secs(
            config.lock_timeout,
        ))
        .to_string()
    };
    println!("lock_timeout      {timeout}");
    println!("lock_on_sleep     {}", yes_no(config.lock_on_sleep));
    println!("lock_on_idle      {}", yes_no(config.lock_on_idle));
    println!(
        "timeout_action    {} ({})",
        config.timeout_action.name(),
        match config.timeout_action {
            rbw::config::TimeoutAction::Lock => {
                "keep the keys for pin or system unlock"
            }
            rbw::config::TimeoutAction::Forget => {
                "the master password is needed"
            }
        }
    );
    println!("pin               {}", yes_no(rbw::pin::is_set()));
    println!("system_auth       {}", yes_no(config.system_auth));
    println!(
        "auto_unlock       {}",
        if config.auto_unlock && config.saved_password.is_none() {
            "yes, but no saved password (run rbw remember-password)"
        } else {
            yes_no(config.auto_unlock)
        }
    );
    println!("tui_auth          {}", yes_no(config.tui_auth));
    println!(
        "saved password    {}",
        config.saved_password.map_or(
            "no (the first unlock after a restart needs the master password)",
            rbw::biometric::SecretStore::name
        )
    );
    println!();
    println!(
        "polkit action     {}",
        if block_on(rbw::biometric::polkit_available()) {
            "installed"
        } else {
            "missing (contrib/polkit/README.md)"
        }
    );
    println!(
        "tpm2              {}",
        yes_no(block_on(rbw::biometric::has_tpm2()))
    );
    println!(
        "password store    {}",
        block_on(rbw::biometric::default_store())
            .map_or("none available", rbw::biometric::SecretStore::name)
    );

    Ok(())
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

pub fn purge() -> anyhow::Result<()> {
    stop_agent()?;

    remove_db()?;

    Ok(())
}

pub fn stop_agent() -> anyhow::Result<()> {
    crate::actions::quit()?;

    Ok(())
}

pub fn inject(
    input: Option<&std::path::Path>,
    output: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let ctx = InjectContext::load()?;
    let rendered = ctx.render_input(input)?;

    match output {
        Some(path) => write_rendered_template_file(path, &rendered)?,
        None => {
            std::io::stdout()
                .write_all(rendered.as_bytes())
                .context("failed to write rendered template to stdout")?;
        }
    }

    Ok(())
}

pub fn run(
    env_file: &std::path::Path,
    command: &[OsString],
) -> anyhow::Result<std::process::ExitStatus> {
    let ctx = InjectContext::load()?;
    let env_bindings = ctx.env_bindings_from_file(env_file)?;
    run_inject_command(command, &env_bindings)
}

fn ensure_agent() -> anyhow::Result<()> {
    check_config()?;
    if matches!(check_agent_version(), Ok(())) {
        return Ok(());
    }
    run_agent()?;
    // when another command started the agent a moment ago, run_agent
    // returns at once (the pid file is taken) but the agent may not listen
    // on its socket yet
    let mut res = check_agent_version();
    for _ in 0..100 {
        if !matches!(&res, Err(e) if agent_not_listening(e)) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        res = check_agent_version();
    }
    res
}

fn run_agent() -> anyhow::Result<()> {
    let agent_path = std::env::var_os("RBW_AGENT");
    let agent_path = agent_path
        .as_deref()
        .unwrap_or_else(|| std::ffi::OsStr::from_bytes(b"rbw-agent"));
    let status = std::process::Command::new(agent_path)
        .status()
        .context("failed to run rbw-agent")?;
    if !status.success() {
        if let Some(code) = status.code() {
            if code != 23 {
                return Err(anyhow::anyhow!(
                    "failed to run rbw-agent: {status}"
                ));
            }
        }
    }

    Ok(())
}

fn check_config() -> anyhow::Result<()> {
    rbw::config::Config::validate().map_err(|e| {
        log::error!("{MISSING_CONFIG_HELP}");
        anyhow::Error::new(e)
    })
}

fn check_agent_version() -> anyhow::Result<()> {
    let client_version = rbw::protocol::VERSION;
    let agent_version = version_or_quit()?;
    if agent_version != client_version {
        crate::actions::quit()?;
        return Err(anyhow::anyhow!(
            "client protocol version is {client_version} but agent protocol version is {agent_version}"
        ));
    }
    Ok(())
}

// stops an agent that answers but can't be talked to. When nothing listens
// there is nothing to stop, and the quit could reach an agent that another
// command is starting right now: it would lose its keys and ask for the
// master password again.
fn version_or_quit() -> anyhow::Result<u32> {
    crate::actions::version().inspect_err(|e| {
        if !agent_not_listening(e) {
            let _ = crate::actions::quit();
        }
    })
}

fn agent_not_listening(e: &anyhow::Error) -> bool {
    e.chain().any(|e| {
        e.downcast_ref::<std::io::Error>().is_some_and(|e| {
            matches!(
                e.kind(),
                std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::ConnectionRefused
            )
        })
    })
}

pub fn find_entry(
    db: &rbw::db::Db,
    mut needle: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<(rbw::db::Entry, DecryptedCipher)> {
    if let Needle::Uuid(uuid, s) = needle {
        for cipher in &db.entries {
            if uuid::Uuid::parse_str(&cipher.id) == Ok(uuid) {
                return Ok((cipher.clone(), decrypt_cipher_batched(cipher)?));
            }
        }
        needle = Needle::Name(s);
    }

    let decrypted = batch_decrypt(&db.entries, |entry, decryptor| {
        decrypt_search_cipher(entry, decryptor)
    })?;
    let ciphers: Vec<(rbw::db::Entry, DecryptedSearchCipher)> =
        db.entries.iter().cloned().zip(decrypted).collect();
    let (entry, _) =
        find_entry_raw(&ciphers, &needle, username, folder, ignore_case)?;
    let decrypted_entry = decrypt_cipher_batched(&entry)?;
    Ok((entry, decrypted_entry))
}

fn find_entry_raw(
    entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
    needle: &Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<(rbw::db::Entry, DecryptedSearchCipher)> {
    let mut matches: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = vec![];

    let find_matches = |strict_username, strict_folder, exact| {
        entries
            .iter()
            .filter(|&(_, decrypted_cipher)| {
                decrypted_cipher.matches(
                    needle,
                    username,
                    folder,
                    ignore_case,
                    strict_username,
                    strict_folder,
                    exact,
                )
            })
            .cloned()
            .collect()
    };

    for exact in [true, false] {
        matches = find_matches(true, true, exact);
        if matches.len() == 1 {
            return Ok(matches[0].clone());
        }

        let strict_folder_matches = find_matches(false, true, exact);
        let strict_username_matches = find_matches(true, false, exact);
        if strict_folder_matches.len() == 1
            && strict_username_matches.len() != 1
        {
            return Ok(strict_folder_matches[0].clone());
        } else if strict_folder_matches.len() != 1
            && strict_username_matches.len() == 1
        {
            return Ok(strict_username_matches[0].clone());
        }

        matches = find_matches(false, false, exact);
        if matches.len() == 1 {
            return Ok(matches[0].clone());
        }
    }

    if matches.is_empty() {
        Err(anyhow::anyhow!("no entry found"))
    } else {
        let entries: Vec<String> = matches
            .iter()
            .map(|(_, decrypted)| decrypted.display_name())
            .collect();
        let entries = entries.join(", ");
        Err(anyhow::anyhow!("multiple entries found: {entries}"))
    }
}

// decrypting an entry takes one agent round trip per field, which adds up
// fast when looking at the whole vault (e.g. finding an entry by name). to
// batch these into a single round trip, the per-entry decryption functions
// go through an EntryDecryptor: a recording pass first collects every
// cipherstring they want (their control flow only depends on the entry
// structure, never on decrypted values, so this is exact), then the whole
// batch is decrypted with one agent request, and a replay pass hands the
// results back out in the same order.
trait EntryDecryptor {
    fn decrypt(
        &self,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> anyhow::Result<String>;
}

#[derive(Default)]
struct RecordingDecryptor(
    std::cell::RefCell<Vec<rbw::protocol::DecryptItem>>,
);

impl EntryDecryptor for RecordingDecryptor {
    fn decrypt(
        &self,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        self.0.borrow_mut().push(rbw::protocol::DecryptItem {
            cipherstring: cipherstring.to_string(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        });
        Ok(String::new())
    }
}

struct ReplayingDecryptor(
    std::cell::RefCell<std::vec::IntoIter<Result<String, String>>>,
);

impl EntryDecryptor for ReplayingDecryptor {
    fn decrypt(
        &self,
        _cipherstring: &str,
        _entry_key: Option<&str>,
        _org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        self.0
            .borrow_mut()
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!("agent returned too few decryption results")
            })?
            .map_err(|e| anyhow::anyhow!("failed to decrypt: {e}"))
    }
}

fn record_batch<T>(
    entries: &[rbw::db::Entry],
    each: &impl Fn(&rbw::db::Entry, &dyn EntryDecryptor) -> anyhow::Result<T>,
) -> Vec<rbw::protocol::DecryptItem> {
    let recorder = RecordingDecryptor::default();
    for entry in entries {
        // the recording decryptor never fails, and these functions have no
        // other failure modes; anything real will surface during replay
        let _ = each(entry, &recorder);
    }
    recorder.0.into_inner()
}

fn replay_batch<T>(
    entries: &[rbw::db::Entry],
    each: &impl Fn(&rbw::db::Entry, &dyn EntryDecryptor) -> anyhow::Result<T>,
    results: Vec<Result<String, String>>,
) -> anyhow::Result<Vec<T>> {
    let replayer =
        ReplayingDecryptor(std::cell::RefCell::new(results.into_iter()));
    let decrypted = entries
        .iter()
        .map(|entry| each(entry, &replayer))
        .collect::<anyhow::Result<Vec<T>>>()?;
    if replayer.0.borrow_mut().next().is_some() {
        return Err(anyhow::anyhow!(
            "agent returned too many decryption results"
        ));
    }
    Ok(decrypted)
}

fn batch_decrypt<T>(
    entries: &[rbw::db::Entry],
    each: impl Fn(&rbw::db::Entry, &dyn EntryDecryptor) -> anyhow::Result<T>,
) -> anyhow::Result<Vec<T>> {
    let items = record_batch(entries, &each);
    let results = if items.is_empty() {
        vec![]
    } else {
        crate::actions::decrypt_many(items)?
    };
    replay_batch(entries, &each, results)
}

fn decrypt_cipher_batched(
    entry: &rbw::db::Entry,
) -> anyhow::Result<DecryptedCipher> {
    batch_decrypt(std::slice::from_ref(entry), |entry, decryptor| {
        decrypt_cipher(entry, decryptor)
    })?
    .pop()
    .ok_or_else(|| anyhow::anyhow!("no decryption result"))
}

fn decrypt_field(
    name: Field,
    field: Option<&str>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
    decryptor: &dyn EntryDecryptor,
) -> Option<String> {
    let field = field
        .as_ref()
        .map(|field| decryptor.decrypt(field, entry_key, org_id))
        .transpose();
    match field {
        Ok(field) => field,
        Err(e) => {
            log::warn!("failed to decrypt {name}: {e}");
            None
        }
    }
}

fn decrypt_list_cipher(
    entry: &rbw::db::Entry,
    fields: &[ListField],
    decryptor: &dyn EntryDecryptor,
) -> anyhow::Result<DecryptedListCipher> {
    let id = entry.id.clone();
    let name = if fields.contains(&ListField::Name) {
        Some(decryptor.decrypt(
            &entry.name,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?)
    } else {
        None
    };
    let user = if fields.contains(&ListField::User) {
        match &entry.data {
            rbw::db::EntryData::Login { username, .. } => decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            _ => None,
        }
    } else {
        None
    };
    let folder = if fields.contains(&ListField::Folder) {
        // folder name should always be decrypted with the local key because
        // folders are local to a specific user's vault, not the organization
        entry
            .folder
            .as_ref()
            .map(|folder| decryptor.decrypt(folder, None, None))
            .transpose()?
    } else {
        None
    };
    let uris = if fields.contains(&ListField::Uri) {
        match &entry.data {
            rbw::db::EntryData::Login { uris, .. } => Some(
                uris.iter()
                    .filter_map(|s| {
                        decrypt_field(
                            Field::Uris,
                            Some(&s.uri),
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                            decryptor,
                        )
                    })
                    .collect(),
            ),
            _ => None,
        }
    } else {
        None
    };
    let entry_type = fields
        .contains(&ListField::EntryType)
        .then_some(match &entry.data {
            rbw::db::EntryData::Login { .. } => "Login",
            rbw::db::EntryData::Identity { .. } => "Identity",
            rbw::db::EntryData::SshKey { .. } => "SSH Key",
            rbw::db::EntryData::SecureNote => "Note",
            rbw::db::EntryData::Card { .. } => "Card",
        })
        .map(str::to_string);

    Ok(DecryptedListCipher {
        id,
        name,
        user,
        folder,
        uris,
        entry_type,
    })
}

fn decrypt_search_cipher(
    entry: &rbw::db::Entry,
    decryptor: &dyn EntryDecryptor,
) -> anyhow::Result<DecryptedSearchCipher> {
    let id = entry.id.clone();
    let name = decryptor.decrypt(
        &entry.name,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    let user = match &entry.data {
        rbw::db::EntryData::Login { username, .. } => decrypt_field(
            Field::Username,
            username.as_deref(),
            entry.key.as_deref(),
            entry.org_id.as_deref(),
            decryptor,
        ),
        _ => None,
    };
    // folder name should always be decrypted with the local key because
    // folders are local to a specific user's vault, not the organization
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| decryptor.decrypt(folder, None, None))
        .transpose()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            decryptor.decrypt(
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .transpose();
    let uris = if let rbw::db::EntryData::Login { uris, .. } = &entry.data {
        uris.iter()
            .filter_map(|s| {
                decrypt_field(
                    Field::Uris,
                    Some(&s.uri),
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                    decryptor,
                )
                .map(|uri| (uri, s.match_type))
            })
            .collect()
    } else {
        vec![]
    };
    let fields = entry
        .fields
        .iter()
        .filter_map(|field| {
            if field.ty == Some(rbw::api::FieldType::Hidden) {
                None
            } else {
                field.value.as_ref()
            }
        })
        .map(|value| {
            decryptor.decrypt(
                value,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .collect::<anyhow::Result<_>>()?;
    let notes = match notes {
        Ok(notes) => notes,
        Err(e) => {
            log::warn!("failed to decrypt notes: {e}");
            None
        }
    };
    let entry_type = (match &entry.data {
        rbw::db::EntryData::Login { .. } => "Login",
        rbw::db::EntryData::Identity { .. } => "Identity",
        rbw::db::EntryData::SshKey { .. } => "SSH Key",
        rbw::db::EntryData::SecureNote => "Note",
        rbw::db::EntryData::Card { .. } => "Card",
    })
    .to_string();

    Ok(DecryptedSearchCipher {
        id,
        entry_type,
        folder,
        name,
        user,
        uris,
        fields,
        notes,
    })
}

fn decrypt_cipher(
    entry: &rbw::db::Entry,
    decryptor: &dyn EntryDecryptor,
) -> anyhow::Result<DecryptedCipher> {
    // folder name should always be decrypted with the local key because
    // folders are local to a specific user's vault, not the organization
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| decryptor.decrypt(folder, None, None))
        .transpose();
    let folder = match folder {
        Ok(folder) => folder,
        Err(e) => {
            log::warn!("failed to decrypt folder name: {e}");
            None
        }
    };
    let fields = entry
        .fields
        .iter()
        .map(|field| {
            Ok(DecryptedField {
                name: field
                    .name
                    .as_ref()
                    .map(|name| {
                        decryptor.decrypt(
                            name,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                value: field
                    .value
                    .as_ref()
                    .map(|value| {
                        decryptor.decrypt(
                            value,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                ty: field.ty,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            decryptor.decrypt(
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .transpose();
    let notes = match notes {
        Ok(notes) => notes,
        Err(e) => {
            log::warn!("failed to decrypt notes: {e}");
            None
        }
    };
    let history = entry
        .history
        .iter()
        .map(|history_entry| {
            Ok(DecryptedHistoryEntry {
                last_used_date: history_entry.last_used_date.clone(),
                password: decryptor.decrypt(
                    &history_entry.password,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )?,
            })
        })
        .collect::<anyhow::Result<_>>()?;

    let data = match &entry.data {
        rbw::db::EntryData::Login {
            username,
            password,
            totp,
            uris,
        } => DecryptedData::Login {
            username: decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            password: decrypt_field(
                Field::Password,
                password.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            totp: decrypt_field(
                Field::Totp,
                totp.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            uris: uris
                .iter()
                .map(|s| {
                    decrypt_field(
                        Field::Uris,
                        Some(&s.uri),
                        entry.key.as_deref(),
                        entry.org_id.as_deref(),
                        decryptor,
                    )
                    .map(|uri| DecryptedUri {
                        uri,
                        match_type: s.match_type,
                    })
                })
                .collect(),
        },
        rbw::db::EntryData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => DecryptedData::Card {
            cardholder_name: decrypt_field(
                Field::Cardholder,
                cardholder_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            number: decrypt_field(
                Field::CardNumber,
                number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            brand: decrypt_field(
                Field::Brand,
                brand.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            exp_month: decrypt_field(
                Field::ExpMonth,
                exp_month.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            exp_year: decrypt_field(
                Field::ExpYear,
                exp_year.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            code: decrypt_field(
                Field::Cvv,
                code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
        },
        rbw::db::EntryData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => DecryptedData::Identity {
            title: decrypt_field(
                Field::Title,
                title.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            first_name: decrypt_field(
                Field::FirstName,
                first_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            middle_name: decrypt_field(
                Field::MiddleName,
                middle_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            last_name: decrypt_field(
                Field::LastName,
                last_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            address1: decrypt_field(
                Field::Address1,
                address1.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            address2: decrypt_field(
                Field::Address2,
                address2.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            address3: decrypt_field(
                Field::Address3,
                address3.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            city: decrypt_field(
                Field::City,
                city.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            state: decrypt_field(
                Field::State,
                state.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            postal_code: decrypt_field(
                Field::PostalCode,
                postal_code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            country: decrypt_field(
                Field::Country,
                country.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            phone: decrypt_field(
                Field::Phone,
                phone.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            email: decrypt_field(
                Field::Email,
                email.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            ssn: decrypt_field(
                Field::Ssn,
                ssn.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            license_number: decrypt_field(
                Field::License,
                license_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            passport_number: decrypt_field(
                Field::Passport,
                passport_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            username: decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
        },
        rbw::db::EntryData::SecureNote => DecryptedData::SecureNote {},
        rbw::db::EntryData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => DecryptedData::SshKey {
            public_key: decrypt_field(
                Field::PublicKey,
                public_key.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            fingerprint: decrypt_field(
                Field::Fingerprint,
                fingerprint.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            private_key: decrypt_field(
                Field::PrivateKey,
                private_key.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
        },
    };

    Ok(DecryptedCipher {
        id: entry.id.clone(),
        folder,
        name: decryptor.decrypt(
            &entry.name,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?,
        data,
        fields,
        notes,
        history,
        attachments: entry
            .attachments
            .iter()
            .map(|attachment| DecryptedAttachment {
                id: attachment.id.clone(),
                file_name: decrypt_field(
                    Field::Name,
                    attachment.file_name.as_deref(),
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                    decryptor,
                ),
                size: attachment.size.clone(),
            })
            .collect(),
    })
}

pub fn parse_legacy_editor(
    contents: &str,
) -> (Option<String>, Option<String>) {
    let mut lines = contents.lines();

    let password = lines.next().map(std::string::ToString::to_string);

    let mut notes: String = lines
        .skip_while(|line| line.is_empty())
        .filter(|line| !line.starts_with('#'))
        .fold(String::new(), |mut notes, line| {
            notes.push_str(line);
            notes.push('\n');
            notes
        });
    while notes.ends_with('\n') {
        notes.pop();
    }
    let notes = if notes.is_empty() { None } else { Some(notes) };

    (password, notes)
}

pub fn load_db() -> anyhow::Result<rbw::db::Db> {
    let config = rbw::config::Config::load()?;
    config.email.as_ref().map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        |email| {
            rbw::db::Db::load(&config.server_name(), email)
                .map_err(anyhow::Error::new)
        },
    )
}

fn remove_db() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    config.email.as_ref().map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        |email| {
            rbw::db::Db::remove(&config.server_name(), email)
                .map_err(anyhow::Error::new)
        },
    )
}

struct TotpParams {
    secret: Vec<u8>,
    algorithm: String,
    digits: usize,
    period: u64,
}

fn decode_totp_secret(secret: &str) -> anyhow::Result<Vec<u8>> {
    let secret = secret.trim().replace(' ', "");
    let alphabets = [
        base32::Alphabet::Rfc4648 { padding: false },
        base32::Alphabet::Rfc4648 { padding: true },
        base32::Alphabet::Rfc4648Lower { padding: false },
        base32::Alphabet::Rfc4648Lower { padding: true },
    ];
    for alphabet in alphabets {
        if let Some(secret) = base32::decode(alphabet, &secret) {
            return Ok(secret);
        }
    }
    Err(anyhow::anyhow!("totp secret was not valid base32"))
}

fn parse_totp_secret(secret: &str) -> anyhow::Result<TotpParams> {
    if let Ok(u) = url::Url::parse(secret) {
        match u.scheme() {
            "otpauth" => {
                if u.host_str() != Some("totp") {
                    return Err(anyhow::anyhow!(
                        "totp secret url must have totp host"
                    ));
                }

                let query: std::collections::HashMap<_, _> =
                    u.query_pairs().collect();

                let secret = decode_totp_secret(
                    query.get("secret").ok_or_else(|| {
                        anyhow::anyhow!("totp secret url must have secret")
                    })?,
                )?;
                let algorithm = query.get("algorithm").map_or_else(
                    || String::from("SHA1"),
                    std::string::ToString::to_string,
                );
                let digits = match query.get("digits") {
                    Some(dig) => dig
                        .parse::<usize>()
                        .map_err(|_| anyhow::anyhow!("digits parameter in totp url must be a valid integer."))?,
                    None => 6,
                };
                let period = match query.get("period") {
                    Some(dig) => {
                        dig.parse::<u64>().map_err(|_| anyhow::anyhow!("period parameter in totp url must be a valid integer."))?
                    }
                    None => TOTP_DEFAULT_STEP,
                };

                Ok(TotpParams {
                    secret,
                    algorithm,
                    digits,
                    period,
                })
            }
            "steam" => {
                let steam_secret = u.host_str().unwrap();

                Ok(TotpParams {
                    secret: decode_totp_secret(steam_secret)?,
                    algorithm: String::from("STEAM"),
                    digits: 5,
                    period: TOTP_DEFAULT_STEP,
                })
            }
            _ => Err(anyhow::anyhow!(
                "totp secret url must have 'otpauth' or 'steam' scheme"
            )),
        }
    } else {
        Ok(TotpParams {
            secret: decode_totp_secret(secret)?,
            algorithm: String::from("SHA1"),
            digits: 6,
            period: TOTP_DEFAULT_STEP,
        })
    }
}

struct InjectContext {
    entries: Vec<rbw::db::Entry>,
}

impl InjectContext {
    fn load() -> anyhow::Result<Self> {
        unlock()?;

        let db = load_db()?;
        Ok(Self {
            entries: db.entries,
        })
    }

    fn render_input(
        &self,
        input: Option<&std::path::Path>,
    ) -> anyhow::Result<String> {
        let template = read_inject_template(input)?;
        InjectTemplate::new(&template)
            .render(|reference| self.resolve(reference))
    }

    fn env_bindings_from_file(
        &self,
        env_file: &std::path::Path,
    ) -> anyhow::Result<Vec<(String, String)>> {
        let template =
            std::fs::read_to_string(env_file).with_context(|| {
                format!("failed to read env file {}", env_file.display())
            })?;
        parse_run_env_file(&template, |reference| self.resolve(reference))
            .with_context(|| {
                format!("failed to parse env file {}", env_file.display())
            })
    }

    fn resolve(&self, reference: &InjectReference) -> anyhow::Result<String> {
        let (entry, _) = self.find_entry_raw(&reference.target)?;
        let decrypted =
            decrypt_cipher_batched(&entry).with_context(|| {
                format!("failed to decrypt entry '{}'", reference.id)
            })?;
        resolve_inject_value(&decrypted, reference.field.as_deref())
            .with_context(|| {
                format!(
                    "failed to resolve inject reference '{}'",
                    reference.id
                )
            })
    }

    fn find_entry_raw(
        &self,
        target: &InjectReferenceTarget,
    ) -> anyhow::Result<(rbw::db::Entry, DecryptedSearchCipher)> {
        let decrypted = batch_decrypt(&self.entries, |entry, decryptor| {
            decrypt_search_cipher(entry, decryptor)
        })?;
        let entries: Vec<_> =
            self.entries.iter().cloned().zip(decrypted).collect();
        target.find_entry(&entries)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum InjectReferenceTarget {
    Uuid(String),
    Name(String),
}

impl InjectReferenceTarget {
    fn parse(raw_target: &str) -> anyhow::Result<Self> {
        if let Ok(uuid) = uuid::Uuid::parse_str(raw_target) {
            Ok(Self::Uuid(uuid.to_string()))
        } else if Self::is_valid_name(raw_target) {
            Ok(Self::Name(raw_target.to_string()))
        } else {
            anyhow::bail!(
                "invalid item uuid or supported name '{raw_target}'"
            );
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Uuid(value) | Self::Name(value) => value,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Uuid(_) => "id",
            Self::Name(_) => "name",
        }
    }

    fn matches_entry(
        &self,
        entry: &rbw::db::Entry,
        decrypted: &DecryptedSearchCipher,
    ) -> bool {
        match self {
            Self::Uuid(id) => entry.id.eq_ignore_ascii_case(id),
            Self::Name(name) => decrypted.name.eq_ignore_ascii_case(name),
        }
    }

    fn find_entry(
        &self,
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
    ) -> anyhow::Result<(rbw::db::Entry, DecryptedSearchCipher)> {
        let matches: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = entries
            .iter()
            .filter(|(entry, decrypted)| self.matches_entry(entry, decrypted))
            .cloned()
            .collect();

        if matches.is_empty() {
            anyhow::bail!(
                "no entry found for item {} '{}'",
                self.kind(),
                self.as_str()
            );
        } else if matches.len() == 1 {
            Ok(matches[0].clone())
        } else {
            let entries: Vec<String> = matches
                .iter()
                .map(|(_, decrypted)| decrypted.display_name())
                .collect();
            match self {
                Self::Name(name) => anyhow::bail!(
                    "multiple entries found for item name '{}': {}; use bw://<uuid> instead",
                    name,
                    entries.join(", ")
                ),
                Self::Uuid(id) => anyhow::bail!(
                    "multiple entries found for item id '{}': {}",
                    id,
                    entries.join(", ")
                ),
            }
        }
    }

    fn is_valid_name(name: &str) -> bool {
        !name.is_empty()
            && name.chars().all(|ch| {
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'
            })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct InjectReference {
    id: String,
    target: InjectReferenceTarget,
    field: Option<String>,
}

impl InjectReference {
    fn parse(reference: &str) -> anyhow::Result<Self> {
        let parsed = url::Url::parse(reference).with_context(|| {
            format!("invalid inject reference '{reference}'")
        })?;
        if parsed.scheme() != "bw" {
            anyhow::bail!(
                "invalid inject reference scheme '{}'",
                parsed.scheme()
            );
        }
        if parsed.fragment().is_some() {
            anyhow::bail!("inject references do not support fragments");
        }
        if !parsed.username().is_empty() {
            anyhow::bail!("inject references do not support usernames");
        }
        if parsed.password().is_some() {
            anyhow::bail!("inject references do not support passwords");
        }
        if parsed.port().is_some() {
            anyhow::bail!("inject references do not support ports");
        }
        if !parsed.path().is_empty() {
            anyhow::bail!("inject references do not support paths");
        }

        let raw_target = parsed
            .host_str()
            .context("inject reference is missing an item id or name")?;
        let target = InjectReferenceTarget::parse(raw_target)?;

        let mut field = None;
        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "field" => {
                    if field.replace(value.into_owned()).is_some() {
                        anyhow::bail!(
                            "inject reference has multiple field parameters"
                        );
                    }
                }
                _ => anyhow::bail!(
                    "unsupported inject query parameter '{key}'"
                ),
            }
        }

        let field = field
            .map(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    anyhow::bail!(
                        "inject field query parameter cannot be empty"
                    );
                }
                Ok(trimmed.to_string())
            })
            .transpose()?;

        Ok(Self {
            id: target.as_str().to_string(),
            target,
            field,
        })
    }

    fn parse_braced(expr: &str) -> anyhow::Result<Option<Self>> {
        let expr = expr.trim();
        let expr = if expr.starts_with('"') {
            match serde_json::from_str::<String>(expr) {
                Ok(expr) => expr,
                Err(_) => return Ok(None),
            }
        } else {
            expr.to_string()
        };
        if !expr.starts_with("bw://") {
            return Ok(None);
        }
        Self::parse(&expr).map(Some)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum InjectMarker {
    Braced,
    Raw,
}

struct InjectTemplate<'a> {
    src: &'a str,
}

impl<'a> InjectTemplate<'a> {
    fn new(src: &'a str) -> Self {
        Self { src }
    }

    fn render<F>(&self, mut resolver: F) -> anyhow::Result<String>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        self.render_with_variable_resolver(
            lookup_inject_template_variable,
            |reference| resolver(reference),
        )
    }

    fn render_with_variable_resolver<F, G>(
        &self,
        mut lookup_variable: G,
        mut resolver: F,
    ) -> anyhow::Result<String>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
        G: FnMut(&str) -> Option<String>,
    {
        let expanded =
            self.expand_variables_with_lookup(&mut lookup_variable)?;
        InjectTemplate::new(&expanded)
            .render_secret_references(|reference| resolver(reference))
    }

    fn render_secret_references<F>(
        &self,
        mut resolver: F,
    ) -> anyhow::Result<String>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        let mut rendered = String::with_capacity(self.src.len());
        let mut start = 0;
        while let Some((idx, marker)) = self.next_marker(start) {
            rendered.push_str(
                self.src
                    .get(start..idx)
                    .expect("marker range should be valid"),
            );
            start = match marker {
                InjectMarker::Braced => {
                    self.render_braced(idx, &mut rendered, &mut resolver)?
                }
                InjectMarker::Raw => {
                    self.render_raw(idx, &mut rendered, &mut resolver)?
                }
            };
        }
        rendered.push_str(
            self.src
                .get(start..)
                .expect("template tail range should be valid"),
        );
        Ok(rendered)
    }

    fn expand_variables_with_lookup<G>(
        &self,
        lookup_variable: &mut G,
    ) -> anyhow::Result<String>
    where
        G: FnMut(&str) -> Option<String>,
    {
        let mut rendered = String::with_capacity(self.src.len());
        let mut start = 0;
        while let Some(offset) = self
            .src
            .get(start..)
            .expect("variable search start should be valid")
            .find('$')
        {
            let idx = start + offset;
            rendered.push_str(
                self.src
                    .get(start..idx)
                    .expect("variable prefix range should be valid"),
            );
            if let Some((value, next_start)) =
                self.resolve_variable_at(idx, lookup_variable)?
            {
                rendered.push_str(&value);
                start = next_start;
            } else {
                rendered.push('$');
                start = idx + '$'.len_utf8();
            }
        }
        rendered.push_str(
            self.src
                .get(start..)
                .expect("variable tail range should be valid"),
        );
        Ok(rendered)
    }

    fn take_braced_expression(
        &self,
        idx: usize,
    ) -> anyhow::Result<(&'a str, usize)> {
        let rest = self
            .src
            .get(idx..)
            .expect("braced expression start should be valid")
            .strip_prefix("{{")
            .expect("braced expression must start with '{{'");
        let Some((expr, tail)) = rest.split_once("}}") else {
            anyhow::bail!("unterminated inject template expression");
        };
        Ok((expr, self.src.len() - tail.len()))
    }

    fn render_braced<F>(
        &self,
        idx: usize,
        out: &mut String,
        resolver: &mut F,
    ) -> anyhow::Result<usize>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        let (expr, next_start) = self.take_braced_expression(idx)?;
        if let Some(reference) = InjectReference::parse_braced(expr)? {
            out.push_str(&resolver(&reference)?);
        } else {
            out.push_str("{{");
            out.push_str(expr);
            out.push_str("}}");
        }
        Ok(next_start)
    }

    fn render_raw<F>(
        &self,
        idx: usize,
        out: &mut String,
        resolver: &mut F,
    ) -> anyhow::Result<usize>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        let end = self.raw_reference_end(idx);
        let candidate = self
            .src
            .get(idx..end)
            .expect("raw reference range should be valid");
        let reference = InjectReference::parse(candidate)?;
        out.push_str(&resolver(&reference)?);
        Ok(end)
    }

    fn resolve_variable_at<G>(
        &self,
        idx: usize,
        lookup_variable: &mut G,
    ) -> anyhow::Result<Option<(String, usize)>>
    where
        G: FnMut(&str) -> Option<String>,
    {
        let rest = self
            .src
            .get(idx + '$'.len_utf8()..)
            .expect("variable suffix range should be valid");
        match rest.chars().next() {
            Some('{') => self.resolve_braced_variable(idx, lookup_variable),
            Some(ch) if Self::is_valid_variable_start(ch) => {
                let name_len = rest
                    .char_indices()
                    .take_while(|(_, ch)| {
                        Self::is_valid_variable_continue(*ch)
                    })
                    .last()
                    .map_or(0, |(offset, ch)| offset + ch.len_utf8());
                let name = rest
                    .get(..name_len)
                    .expect("raw variable name range should be valid");
                if let Some(value) = lookup_variable(name) {
                    Ok(Some((value, idx + '$'.len_utf8() + name_len)))
                } else {
                    anyhow::bail!(
                        "inject template variable '{name}' is not set"
                    );
                }
            }
            _ => Ok(None),
        }
    }

    fn resolve_braced_variable<G>(
        &self,
        idx: usize,
        lookup_variable: &mut G,
    ) -> anyhow::Result<Option<(String, usize)>>
    where
        G: FnMut(&str) -> Option<String>,
    {
        let expr_start = idx + "${".len();
        let rest = self
            .src
            .get(expr_start..)
            .expect("braced variable start should be valid");
        let mut depth = 1usize;
        let mut end = None;
        let mut offset = 0;
        while offset < rest.len() {
            let tail = rest
                .get(offset..)
                .expect("braced variable tail range should be valid");
            if tail.starts_with("\\}") {
                offset += "\\}".len();
                continue;
            }
            if tail.starts_with("${") {
                depth += 1;
                offset += "${".len();
                continue;
            }
            let ch = tail
                .chars()
                .next()
                .expect("braced variable tail should not be empty");
            if ch == '}' {
                depth -= 1;
                if depth == 0 {
                    end = Some(expr_start + offset);
                    break;
                }
            }
            offset += ch.len_utf8();
        }
        let end = end.context("unterminated inject template variable")?;
        let expr = self
            .src
            .get(expr_start..end)
            .expect("braced variable expression range should be valid");
        let (name, default) = match expr.split_once(":-") {
            Some((name, default)) => (name.trim(), Some(default)),
            None => (expr.trim(), None),
        };
        if !Self::is_valid_variable_name(name) {
            return Ok(None);
        }
        let value = if let Some(value) = lookup_variable(name) {
            value
        } else if let Some(default) = default {
            InjectTemplate::new(default)
                .expand_variables_with_lookup(lookup_variable)?
        } else {
            anyhow::bail!("inject template variable '{name}' is not set");
        };
        Ok(Some((value, end + '}'.len_utf8())))
    }

    fn next_marker(&self, start: usize) -> Option<(usize, InjectMarker)> {
        let rest = self
            .src
            .get(start..)
            .expect("marker search start should be valid");
        let braced = rest
            .find("{{")
            .map(|offset| (start + offset, InjectMarker::Braced));
        let raw = rest
            .match_indices("bw://")
            .map(|(offset, _)| start + offset)
            .find(|&idx| Self::raw_reference_can_start(self.src, idx))
            .map(|idx| (idx, InjectMarker::Raw));

        match (braced, raw) {
            (Some(braced), Some(raw)) => {
                Some(if braced.0 <= raw.0 { braced } else { raw })
            }
            (Some(braced), None) => Some(braced),
            (None, Some(raw)) => Some(raw),
            (None, None) => None,
        }
    }

    fn raw_reference_end(&self, start: usize) -> usize {
        let mut end = start + "bw://".len();
        let mut seen_query = false;
        let mut seen_query_equals = false;
        for (offset, ch) in self
            .src
            .get(end..)
            .expect("raw reference start should be valid")
            .char_indices()
        {
            let is_allowed = if ch.is_ascii_alphanumeric()
                || matches!(ch, '-' | '_')
                || (seen_query_equals && matches!(ch, '.' | '%' | '+'))
            {
                true
            } else if ch == '?' && !seen_query {
                seen_query = true;
                true
            } else if ch == '=' && seen_query && !seen_query_equals {
                seen_query_equals = true;
                true
            } else {
                false
            };
            if !is_allowed {
                break;
            }
            end = start + "bw://".len() + offset + ch.len_utf8();
        }
        end
    }

    fn raw_reference_can_start(template: &str, idx: usize) -> bool {
        template
            .get(..idx)
            .and_then(|prefix| prefix.chars().next_back())
            .is_none_or(|ch| {
                !ch.is_ascii_alphanumeric()
                    && !matches!(ch, '-' | '+' | '\\' | '.')
            })
    }

    fn is_valid_variable_name(name: &str) -> bool {
        let mut chars = name.chars();
        matches!(chars.next(), Some(ch) if Self::is_valid_variable_start(ch))
            && chars.all(Self::is_valid_variable_continue)
    }

    fn is_valid_variable_start(ch: char) -> bool {
        ch.is_ascii_alphabetic() || ch == '_'
    }

    fn is_valid_variable_continue(ch: char) -> bool {
        ch.is_ascii_alphanumeric() || ch == '_'
    }
}

fn lookup_inject_template_variable(name: &str) -> Option<String> {
    std::env::vars().find_map(|(key, value)| {
        key.eq_ignore_ascii_case(name).then_some(value)
    })
}

fn read_inject_template(
    input: Option<&std::path::Path>,
) -> anyhow::Result<String> {
    let mut template = String::new();
    match input {
        Some(path) => {
            std::fs::File::open(path)
                .with_context(|| {
                    format!("failed to open template {}", path.display())
                })?
                .read_to_string(&mut template)
                .with_context(|| {
                    format!("failed to read template {}", path.display())
                })?;
        }
        None => {
            std::io::stdin()
                .read_to_string(&mut template)
                .context("failed to read template from stdin")?;
        }
    }
    Ok(template)
}

fn parse_run_env_file<F>(
    template: &str,
    mut resolver: F,
) -> anyhow::Result<Vec<(String, String)>>
where
    F: FnMut(&InjectReference) -> anyhow::Result<String>,
{
    dotenvy::from_read_iter(std::io::Cursor::new(template))
        .map(|item| {
            let (key, value) = item.map_err(anyhow::Error::from)?;
            InjectTemplate::new(&value)
                .render_secret_references(|reference| resolver(reference))
                .map(|rendered| (key, rendered))
        })
        .collect()
}

fn build_inject_run_command(
    command: &[OsString],
    env_bindings: &[(String, String)],
) -> anyhow::Result<std::process::Command> {
    let Some(program) = command.first() else {
        anyhow::bail!("missing child command");
    };

    let mut child = std::process::Command::new(program);
    child.args(&command[1..]);
    child.stdin(std::process::Stdio::inherit());
    child.stdout(std::process::Stdio::inherit());
    child.stderr(std::process::Stdio::inherit());
    for (key, value) in env_bindings {
        child.env(key, value);
    }
    Ok(child)
}

fn run_inject_command(
    command: &[OsString],
    env_bindings: &[(String, String)],
) -> anyhow::Result<std::process::ExitStatus> {
    let mut child = build_inject_run_command(command, env_bindings)?;
    child.status().with_context(|| {
        let program = command.first().map_or_else(
            || "<missing command>".to_string(),
            |program| program.to_string_lossy().into_owned(),
        );
        format!("failed to run child command '{program}'")
    })
}

fn resolve_inject_value(
    cipher: &DecryptedCipher,
    field: Option<&str>,
) -> anyhow::Result<String> {
    let normalized = field
        .map(str::trim)
        .filter(|field| !field.is_empty())
        .map(str::to_lowercase);
    match normalized.as_deref() {
        None | Some("password") => match &cipher.data {
            DecryptedData::Login {
                password: Some(password),
                ..
            } => Ok(password.clone()),
            DecryptedData::Login { .. } => {
                anyhow::bail!("entry '{}' has no password", cipher.name)
            }
            _ => {
                anyhow::bail!("entry '{}' is not a login entry", cipher.name)
            }
        },
        Some("username" | "user") => match &cipher.data {
            DecryptedData::Login {
                username: Some(username),
                ..
            } => Ok(username.clone()),
            DecryptedData::Login { .. } => {
                anyhow::bail!("entry '{}' has no username", cipher.name)
            }
            _ => {
                anyhow::bail!("entry '{}' is not a login entry", cipher.name)
            }
        },
        Some(field) => cipher
            .fields
            .iter()
            .find(|custom| {
                custom
                    .name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(field))
            })
            .and_then(|custom| custom.value.clone())
            .with_context(|| {
                format!(
                    "entry '{}' has no field named '{}'",
                    cipher.name, field
                )
            }),
    }
}

fn write_rendered_template_file(
    path: &std::path::Path,
    rendered: &str,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    anyhow::bail!(
                        "rendered template target '{}' must not be a symlink",
                        path.display()
                    );
                }
                if !metadata.file_type().is_file() {
                    anyhow::bail!(
                        "rendered template target '{}' is not a regular file",
                        path.display()
                    );
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to inspect rendered template {}",
                        path.display()
                    )
                });
            }
        }

        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => std::path::Path::new("."),
        };
        let mut file = tempfile::Builder::new()
            .prefix(".rbw-rendered-template.")
            .tempfile_in(parent)
            .with_context(|| {
                format!(
                    "failed to open temporary rendered template near {}",
                    path.display()
                )
            })?;
        file.as_file_mut()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!(
                    "failed to set secure permissions on {}",
                    path.display()
                )
            })?;
        file.write_all(rendered.as_bytes()).with_context(|| {
            format!("failed to write rendered template {}", path.display())
        })?;
        file.as_file_mut().sync_all().with_context(|| {
            format!("failed to sync rendered template {}", path.display())
        })?;
        file.persist(path)
            .map_err(|err| err.error)
            .with_context(|| {
                format!(
                    "failed to persist rendered template {}",
                    path.display()
                )
            })?;
        std::fs::File::open(parent)
            .with_context(|| {
                format!(
                    "failed to sync rendered template directory {}",
                    parent.display()
                )
            })?
            .sync_all()
            .with_context(|| {
                format!(
                    "failed to sync rendered template directory {}",
                    parent.display()
                )
            })?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, rendered).with_context(|| {
            format!("failed to write rendered template {}", path.display())
        })?;
        Ok(())
    }
}

// This function exists for the sake of making the generate_totp function less
// densely packed and more readable
fn generate_totp_algorithm_type(
    alg: &str,
) -> anyhow::Result<totp_rs::Algorithm> {
    match alg {
        "SHA1" => Ok(totp_rs::Algorithm::SHA1),
        "SHA256" => Ok(totp_rs::Algorithm::SHA256),
        "SHA512" => Ok(totp_rs::Algorithm::SHA512),
        "STEAM" => Ok(totp_rs::Algorithm::Steam),
        _ => Err(anyhow::anyhow!(format!("{alg} is not a valid algorithm"))),
    }
}

fn generate_totp(secret: &str) -> anyhow::Result<String> {
    let totp_params = parse_totp_secret(secret)?;
    let alg = totp_params.algorithm.as_str();

    match alg {
        "SHA1" | "SHA256" | "SHA512" => Ok(totp_rs::TOTP::new_unchecked(
            generate_totp_algorithm_type(alg)?,
            totp_params.digits,
            1, // the library docs say this should be a 1
            totp_params.period,
            totp_params.secret,
        )
        .generate_current()?),
        "STEAM" => Ok(totp_rs::TOTP::new_steam(totp_params.secret)
            .generate_current()?),
        _ => Err(anyhow::anyhow!(format!(
            "{alg} is not a valid totp algorithm"
        ))),
    }
}

fn display_field(name: &str, field: Option<&str>, clipboard: bool) -> bool {
    field.map_or_else(
        || false,
        |field| val_display_or_store(clipboard, &format!("{name}: {field}")),
    )
}

// what the tui lists: nothing secret, decrypted for the whole vault with a
// single agent round trip
pub struct TuiEntry {
    pub id: String,
    pub name: String,
    pub user: Option<String>,
    pub folder: Option<String>,
    pub uris: Vec<String>,
    pub kind: &'static str,
    pub reprompt: bool,
    pub attachments: usize,
    pub org_id: Option<String>,
    pub folder_id: Option<String>,
    pub collection_ids: Vec<String>,
    pub favorite: bool,
    pub archived: bool,
    // items in the trash only: when they were deleted
    pub deleted: Option<String>,
}

pub struct TuiCollection {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub read_only: bool,
}

// the organizations, collections and folders, with their names decrypted
// and sorted like the official clients do
pub struct TuiVault {
    pub organizations: Vec<(String, String)>,
    pub collections: Vec<TuiCollection>,
    pub folders: Vec<(String, String)>,
}

pub fn tui_vault(db: &rbw::db::Db) -> anyhow::Result<TuiVault> {
    let mut items = vec![];
    for c in &db.collections {
        items.push(rbw::protocol::DecryptItem {
            cipherstring: c.name.clone(),
            entry_key: None,
            org_id: Some(c.org_id.clone()),
        });
    }
    for f in &db.folders {
        items.push(rbw::protocol::DecryptItem {
            cipherstring: f.name.clone(),
            entry_key: None,
            org_id: None,
        });
    }
    let mut names = if items.is_empty() {
        vec![]
    } else {
        crate::actions::decrypt_many(items)?
    }
    .into_iter()
    .map(|res| res.unwrap_or_else(|e| format!("<undecryptable: {e}>")));
    let mut collections: Vec<TuiCollection> = db
        .collections
        .iter()
        .map(|c| TuiCollection {
            id: c.id.clone(),
            org_id: c.org_id.clone(),
            name: names.next().unwrap_or_default(),
            read_only: c.read_only,
        })
        .collect();
    let mut folders: Vec<(String, String)> = db
        .folders
        .iter()
        .map(|f| (f.id.clone(), names.next().unwrap_or_default()))
        .collect();
    let mut organizations: Vec<(String, String)> = db
        .organizations
        .iter()
        .map(|o| (o.id.clone(), o.name.clone()))
        .collect();
    let key = |s: &str| s.to_lowercase();
    collections.sort_by_key(|c| key(&c.name));
    folders.sort_by_key(|(_, name)| key(name));
    organizations.sort_by_key(|(_, name)| key(name));
    Ok(TuiVault {
        organizations,
        collections,
        folders,
    })
}

pub fn tui_entries(db: &rbw::db::Db) -> anyhow::Result<Vec<TuiEntry>> {
    let fields = [
        ListField::Name,
        ListField::User,
        ListField::Folder,
        ListField::Uri,
    ];
    let decrypted = batch_decrypt(&db.entries, |entry, decryptor| {
        decrypt_list_cipher(entry, &fields, decryptor)
    })?;
    Ok(db
        .entries
        .iter()
        .zip(decrypted)
        .map(|(entry, decrypted)| TuiEntry {
            id: entry.id.clone(),
            name: decrypted.name.unwrap_or_default(),
            user: decrypted.user.filter(|u| !u.is_empty()),
            folder: decrypted.folder,
            uris: decrypted.uris.unwrap_or_default(),
            kind: match &entry.data {
                rbw::db::EntryData::Login { .. } => "login",
                rbw::db::EntryData::Identity { .. } => "identity",
                rbw::db::EntryData::SshKey { .. } => "ssh key",
                rbw::db::EntryData::SecureNote => "note",
                rbw::db::EntryData::Card { .. } => "card",
            },
            reprompt: entry.master_password_reprompt(),
            attachments: entry.attachments.len(),
            org_id: entry.org_id.clone(),
            folder_id: entry.folder_id.clone(),
            collection_ids: entry.collection_ids.clone(),
            favorite: entry.favorite,
            archived: entry.archived,
            deleted: None,
        })
        .collect())
}

// one value of an entry, as the tui shows it
#[derive(Clone)]
pub struct TuiValue {
    pub label: String,
    pub value: String,
    pub secret: bool,
}

#[derive(Clone)]
pub struct TuiDetails {
    // the value Enter copies: password, card number, notes, public key
    pub primary: Option<String>,
    pub username: Option<String>,
    pub totp: Option<String>,
    pub values: Vec<TuiValue>,
    pub notes: Option<String>,
    pub history: usize,
    pub attachments: Vec<TuiAttachment>,
}

#[derive(Clone)]
pub struct TuiAttachment {
    pub id: String,
    pub name: String,
}

// decrypts everything, so for entries with master password reprompt this
// asks for the master password
pub fn tui_details(db: &rbw::db::Db, id: &str) -> anyhow::Result<TuiDetails> {
    let entry = db
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .ok_or_else(|| anyhow::anyhow!("entry not found"))?;
    let decrypted = decrypt_cipher_batched(entry)?;
    let value = |label: &str, value: &Option<String>, secret: bool| {
        value.as_ref().filter(|v| !v.is_empty()).map(|v| TuiValue {
            label: label.to_string(),
            value: v.clone(),
            secret,
        })
    };
    let mut details = TuiDetails {
        primary: None,
        username: None,
        totp: None,
        values: vec![],
        notes: decrypted.notes.clone().filter(|n| !n.is_empty()),
        history: decrypted.history.len(),
        attachments: decrypted
            .attachments
            .iter()
            .map(|a| TuiAttachment {
                id: a.id.clone(),
                name: a.file_name.clone().unwrap_or_else(|| a.id.clone()),
            })
            .collect(),
    };
    match &decrypted.data {
        DecryptedData::Login {
            username,
            password,
            totp,
            uris,
        } => {
            details.primary.clone_from(password);
            details.username.clone_from(username);
            details.totp.clone_from(totp);
            details.values.extend(value("username", username, false));
            details.values.extend(value("password", password, true));
            for uri in uris.iter().flatten() {
                details.values.push(TuiValue {
                    label: "uri".to_string(),
                    value: uri.uri.clone(),
                    secret: false,
                });
            }
        }
        DecryptedData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => {
            details.primary.clone_from(number);
            details.values.extend(value(
                "cardholder",
                cardholder_name,
                false,
            ));
            details.values.extend(value("number", number, true));
            details.values.extend(value("brand", brand, false));
            if let (Some(m), Some(y)) = (exp_month, exp_year) {
                details.values.push(TuiValue {
                    label: "expires".to_string(),
                    value: format!("{m}/{y}"),
                    secret: false,
                });
            }
            details.values.extend(value("code", code, true));
        }
        DecryptedData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => {
            let name: Vec<_> = [title, first_name, middle_name, last_name]
                .into_iter()
                .flatten()
                .cloned()
                .collect();
            if !name.is_empty() {
                details.values.push(TuiValue {
                    label: "name".to_string(),
                    value: name.join(" "),
                    secret: false,
                });
            }
            details.username.clone_from(username);
            for (label, v, secret) in [
                ("username", username, false),
                ("email", email, false),
                ("phone", phone, false),
                ("address", address1, false),
                ("address", address2, false),
                ("address", address3, false),
                ("city", city, false),
                ("state", state, false),
                ("postal code", postal_code, false),
                ("country", country, false),
                ("ssn", ssn, true),
                ("license", license_number, true),
                ("passport", passport_number, true),
            ] {
                details.values.extend(value(label, v, secret));
            }
        }
        DecryptedData::SecureNote => {
            details.primary.clone_from(&details.notes);
        }
        DecryptedData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => {
            details.primary.clone_from(public_key);
            details
                .values
                .extend(value("public key", public_key, false));
            details
                .values
                .extend(value("fingerprint", fingerprint, false));
            details
                .values
                .extend(value("private key", private_key, true));
        }
    }
    for field in &decrypted.fields {
        let secret = field.ty == Some(rbw::api::FieldType::Hidden);
        details.values.extend(value(
            field.name.as_deref().unwrap_or("field"),
            &field.value,
            secret,
        ));
    }
    Ok(details)
}

// the current code and the seconds it stays valid
pub fn tui_totp(secret: &str) -> anyhow::Result<(String, u64)> {
    let code = generate_totp(secret)?;
    let period = parse_totp_secret(secret).map_or(30, |p| p.period.max(1));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    Ok((code, period - now % period))
}

pub fn tui_ensure_unlocked() -> anyhow::Result<()> {
    unlock()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_agent_not_listening() {
        let connect = |kind: std::io::ErrorKind| {
            Err::<(), _>(std::io::Error::from(kind))
                .context("failed to connect to rbw-agent")
                .unwrap_err()
        };
        assert!(agent_not_listening(&connect(
            std::io::ErrorKind::ConnectionRefused
        )));
        assert!(agent_not_listening(&connect(std::io::ErrorKind::NotFound)));
        assert!(!agent_not_listening(&connect(
            std::io::ErrorKind::ConnectionReset
        )));
        assert!(!agent_not_listening(&anyhow::anyhow!("unexpected message")));
    }

    #[test]
    fn test_find_entry() {
        let entries = &[
            make_entry("github", Some("foo"), None, &[]),
            make_entry("gitlab", Some("foo"), None, &[]),
            make_entry("gitlab", Some("bar"), None, &[]),
            make_entry("gitter", Some("baz"), None, &[]),
            make_entry("git", Some("foo"), None, &[]),
            make_entry("bitwarden", None, None, &[]),
            make_entry("github", Some("foo"), Some("websites"), &[]),
            make_entry("github", Some("foo"), Some("ssh"), &[]),
            make_entry("github", Some("root"), Some("ssh"), &[]),
            make_entry("codeberg", Some("foo"), None, &[]),
            make_entry("codeberg", None, None, &[]),
            make_entry("1password", Some("foo"), None, &[]),
            make_entry("1password", None, Some("foo"), &[]),
        ];

        assert!(
            one_match(entries, "github", Some("foo"), None, 0, false),
            "foo@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("foo"), None, 0, true),
            "foo@GITHUB"
        );
        assert!(one_match(entries, "github", None, None, 0, false), "github");
        assert!(one_match(entries, "GITHUB", None, None, 0, true), "GITHUB");
        assert!(
            one_match(entries, "gitlab", Some("foo"), None, 1, false),
            "foo@gitlab"
        );
        assert!(
            one_match(entries, "GITLAB", Some("foo"), None, 1, true),
            "foo@GITLAB"
        );
        assert!(
            one_match(entries, "git", Some("bar"), None, 2, false),
            "bar@git"
        );
        assert!(
            one_match(entries, "GIT", Some("bar"), None, 2, true),
            "bar@GIT"
        );
        assert!(
            one_match(entries, "gitter", Some("ba"), None, 3, false),
            "ba@gitter"
        );
        assert!(
            one_match(entries, "GITTER", Some("ba"), None, 3, true),
            "ba@GITTER"
        );
        assert!(
            one_match(entries, "git", Some("foo"), None, 4, false),
            "foo@git"
        );
        assert!(
            one_match(entries, "GIT", Some("foo"), None, 4, true),
            "foo@GIT"
        );
        assert!(one_match(entries, "git", None, None, 4, false), "git");
        assert!(one_match(entries, "GIT", None, None, 4, true), "GIT");
        assert!(
            one_match(entries, "bitwarden", None, None, 5, false),
            "bitwarden"
        );
        assert!(
            one_match(entries, "BITWARDEN", None, None, 5, true),
            "BITWARDEN"
        );
        assert!(
            one_match(
                entries,
                "github",
                Some("foo"),
                Some("websites"),
                6,
                false
            ),
            "websites/foo@github"
        );
        assert!(
            one_match(
                entries,
                "GITHUB",
                Some("foo"),
                Some("websites"),
                6,
                true
            ),
            "websites/foo@GITHUB"
        );
        assert!(
            one_match(entries, "github", Some("foo"), Some("ssh"), 7, false),
            "ssh/foo@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("foo"), Some("ssh"), 7, true),
            "ssh/foo@GITHUB"
        );
        assert!(
            one_match(entries, "github", Some("root"), None, 8, false),
            "ssh/root@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("root"), None, 8, true),
            "ssh/root@GITHUB"
        );

        assert!(
            no_matches(entries, "gitlab", Some("baz"), None, false),
            "baz@gitlab"
        );
        assert!(
            no_matches(entries, "GITLAB", Some("baz"), None, true),
            "baz@"
        );
        assert!(
            no_matches(entries, "bitbucket", Some("foo"), None, false),
            "foo@bitbucket"
        );
        assert!(
            no_matches(entries, "BITBUCKET", Some("foo"), None, true),
            "foo@BITBUCKET"
        );
        assert!(
            no_matches(entries, "github", Some("foo"), Some("bar"), false),
            "bar/foo@github"
        );
        assert!(
            no_matches(entries, "GITHUB", Some("foo"), Some("bar"), true),
            "bar/foo@"
        );
        assert!(
            no_matches(entries, "gitlab", Some("foo"), Some("bar"), false),
            "bar/foo@gitlab"
        );
        assert!(
            no_matches(entries, "GITLAB", Some("foo"), Some("bar"), true),
            "bar/foo@GITLAB"
        );

        assert!(many_matches(entries, "gitlab", None, None, false), "gitlab");
        assert!(many_matches(entries, "gitlab", None, None, true), "GITLAB");
        assert!(
            many_matches(entries, "gi", Some("foo"), None, false),
            "foo@gi"
        );
        assert!(
            many_matches(entries, "GI", Some("foo"), None, true),
            "foo@GI"
        );
        assert!(
            many_matches(entries, "git", Some("ba"), None, false),
            "ba@git"
        );
        assert!(
            many_matches(entries, "GIT", Some("ba"), None, true),
            "ba@GIT"
        );
        assert!(
            many_matches(entries, "github", Some("foo"), Some("s"), false),
            "s/foo@github"
        );
        assert!(
            many_matches(entries, "GITHUB", Some("foo"), Some("s"), true),
            "s/foo@GITHUB"
        );

        assert!(
            one_match(entries, "codeberg", Some("foo"), None, 9, false),
            "foo@codeberg"
        );
        assert!(
            one_match(entries, "codeberg", None, None, 10, false),
            "codeberg"
        );
        assert!(
            no_matches(entries, "codeberg", Some("bar"), None, false),
            "bar@codeberg"
        );

        assert!(
            many_matches(entries, "1password", None, None, false),
            "1password"
        );
    }

    #[test]
    fn test_find_by_uuid() {
        let entries = &[
            make_entry("github", Some("foo"), None, &[]),
            make_entry("gitlab", Some("foo"), None, &[]),
            make_entry("gitlab", Some("bar"), None, &[]),
            make_entry(
                "12345678-1234-1234-1234-1234567890ab",
                None,
                None,
                &[],
            ),
            make_entry(
                "12345678-1234-1234-1234-1234567890AC",
                None,
                None,
                &[],
            ),
            make_entry("123456781234123412341234567890AD", None, None, &[]),
        ];

        assert!(
            one_match(entries, &entries[0].0.id, None, None, 0, false),
            "foo@github"
        );
        assert!(
            one_match(entries, &entries[1].0.id, None, None, 1, false),
            "foo@gitlab"
        );
        assert!(
            one_match(entries, &entries[2].0.id, None, None, 2, false),
            "bar@gitlab"
        );

        assert!(
            one_match(
                entries,
                &entries[0].0.id.to_uppercase(),
                None,
                None,
                0,
                false
            ),
            "foo@github"
        );
        assert!(
            one_match(
                entries,
                &entries[0].0.id.to_lowercase(),
                None,
                None,
                0,
                false
            ),
            "foo@github"
        );

        assert!(one_match(entries, &entries[3].0.id, None, None, 3, false));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890ab",
            None,
            None,
            3,
            false
        ));
        assert!(no_matches(
            entries,
            "12345678-1234-1234-1234-1234567890AB",
            None,
            None,
            false
        ));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890AB",
            None,
            None,
            3,
            true
        ));
        assert!(one_match(entries, &entries[4].0.id, None, None, 4, false));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890AC",
            None,
            None,
            4,
            false
        ));
        assert!(one_match(entries, &entries[5].0.id, None, None, 5, false));
        assert!(one_match(
            entries,
            "123456781234123412341234567890AD",
            None,
            None,
            5,
            false
        ));
    }

    #[test]
    fn test_find_by_url_default() {
        let entries = &[
            make_entry("one", None, None, &[("https://one.com/", None)]),
            make_entry("two", None, None, &[("https://two.com/login", None)]),
            make_entry(
                "three",
                None,
                None,
                &[("https://login.three.com/", None)],
            ),
            make_entry("four", None, None, &[("four.com", None)]),
            make_entry(
                "five",
                None,
                None,
                &[("https://five.com:8080/", None)],
            ),
            make_entry("six", None, None, &[("six.com:8080", None)]),
            make_entry("seven", None, None, &[("192.168.0.128:8080", None)]),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(
                entries,
                "https://login.one.com/",
                None,
                None,
                0,
                false
            ),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/other-page",
                None,
                None,
                1,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(
                entries,
                "https://five.com:8080/",
                None,
                None,
                4,
                false
            ),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(
                entries,
                "https://192.168.0.128:8080/",
                None,
                None,
                6,
                false
            ),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_domain() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "seven",
                None,
                None,
                &[(
                    "192.168.0.128:8080",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(
                entries,
                "https://login.one.com/",
                None,
                None,
                0,
                false
            ),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/other-page",
                None,
                None,
                1,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(
                entries,
                "https://five.com:8080/",
                None,
                None,
                4,
                false
            ),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(
                entries,
                "https://192.168.0.128:8080/",
                None,
                None,
                6,
                false
            ),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_host() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "seven",
                None,
                None,
                &[("192.168.0.128:8080", Some(rbw::api::UriMatchType::Host))],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/other-page",
                None,
                None,
                1,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(
                entries,
                "https://five.com:8080/",
                None,
                None,
                4,
                false
            ),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(
                entries,
                "https://192.168.0.128:8080/",
                None,
                None,
                6,
                false
            ),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_starts_with() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[(
                    "https://one.com/",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/login/sso",
                None,
                None,
                1,
                false
            ),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );
    }

    #[test]
    fn test_find_by_url_exact() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Exact))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Exact),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Exact),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("https://four.com", Some(rbw::api::UriMatchType::Exact))],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://one.com/foo", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/login/sso",
                None,
                None,
                false
            ),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );
        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );
        assert!(
            one_match(entries, "https://four.com", None, None, 3, false),
            "four"
        );
        assert!(
            no_matches(entries, "https://four.com/foo", None, None, false),
            "four"
        );
    }

    #[test]
    fn test_find_by_url_regex() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[(
                    r"^https://one\.com/$",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    r"^https://two\.com/(login|start)",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    r"^https://(login\.)?three\.com/$",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(entries, "https://two.com/start", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/login/sso",
                None,
                None,
                1,
                false
            ),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            one_match(entries, "https://three.com/", None, None, 2, false),
            "three"
        );
        assert!(
            no_matches(entries, "https://www.three.com/", None, None, false),
            "three"
        );
    }

    #[test]
    fn test_find_by_url_never() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Never))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Never))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Never))],
            ),
        ];

        assert!(
            no_matches(entries, "https://one.com/", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://one.com:443/", None, None, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            no_matches(
                entries,
                "https://login.three.com/",
                None,
                None,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            no_matches(entries, "https://four.com/", None, None, false),
            "four"
        );

        assert!(
            no_matches(entries, "https://five.com:8080/", None, None, false),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            no_matches(entries, "https://six.com:8080/", None, None, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
    }

    #[test]
    fn test_find_with_multiple_urls() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[
                    (
                        "https://one.com/",
                        Some(rbw::api::UriMatchType::Domain),
                    ),
                    (
                        "https://two.com/",
                        Some(rbw::api::UriMatchType::Domain),
                    ),
                ],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
        ];

        assert!(
            no_matches(entries, "https://zero.com/", None, None, false),
            "zero"
        );
        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            many_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
    }

    #[test]
    fn test_decode_totp_secret() {
        let decoded = decode_totp_secret("NBSW Y3DP EB3W 64TM MQQQ").unwrap();
        let want = b"hello world!".to_vec();
        assert!(decoded == want, "strips spaces");
    }

    #[track_caller]
    fn one_match(
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        idx: usize,
        ignore_case: bool,
    ) -> bool {
        entries_eq(
            &find_entry_raw(
                entries,
                &parse_needle(needle).unwrap(),
                username,
                folder,
                ignore_case,
            )
            .unwrap(),
            &entries[idx],
        )
    }

    #[track_caller]
    fn no_matches(
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
    ) -> bool {
        let res = find_entry_raw(
            entries,
            &parse_needle(needle).unwrap(),
            username,
            folder,
            ignore_case,
        );
        if let Err(e) = res {
            format!("{e}").contains("no entry found")
        } else {
            false
        }
    }

    #[track_caller]
    fn many_matches(
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
    ) -> bool {
        let res = find_entry_raw(
            entries,
            &parse_needle(needle).unwrap(),
            username,
            folder,
            ignore_case,
        );
        if let Err(e) = res {
            format!("{e}").contains("multiple entries found")
        } else {
            false
        }
    }

    #[track_caller]
    fn entries_eq(
        a: &(rbw::db::Entry, DecryptedSearchCipher),
        b: &(rbw::db::Entry, DecryptedSearchCipher),
    ) -> bool {
        a.0 == b.0 && a.1 == b.1
    }

    #[test]
    fn test_batch_decrypt_record_replay() {
        // the recording pass and the replay pass must request exactly the
        // same decryptions in the same order; a replay with exactly as
        // many results as were recorded consumes all of them, and extra
        // results are an error
        fn check<T>(
            entries: &[rbw::db::Entry],
            each: impl Fn(
                &rbw::db::Entry,
                &dyn EntryDecryptor,
            ) -> anyhow::Result<T>,
        ) -> Vec<rbw::protocol::DecryptItem> {
            let items = record_batch(entries, &each);
            assert!(!items.is_empty());
            let results = vec![Ok(String::new()); items.len()];
            replay_batch(entries, &each, results).unwrap();
            let results = vec![Ok(String::new()); items.len() + 1];
            assert!(replay_batch(entries, &each, results).is_err());
            items
        }

        // an entry exercising every decryption site: login with username,
        // password, totp, uris, custom fields (text and hidden), notes,
        // history, folder, and an individual entry key
        let entry = rbw::db::Entry {
            id: uuid::Uuid::new_v4().to_string(),
            org_id: Some("org".to_string()),
            folder: Some("encrypted folder".to_string()),
            folder_id: None,
            name: "encrypted name".to_string(),
            data: rbw::db::EntryData::Login {
                username: Some("encrypted username".to_string()),
                password: Some("encrypted password".to_string()),
                totp: Some("encrypted totp".to_string()),
                uris: vec![
                    rbw::db::Uri {
                        uri: "encrypted uri 1".to_string(),
                        match_type: None,
                    },
                    rbw::db::Uri {
                        uri: "encrypted uri 2".to_string(),
                        match_type: None,
                    },
                ],
            },
            fields: vec![
                rbw::db::Field {
                    ty: Some(rbw::api::FieldType::Text),
                    name: Some("encrypted field name".to_string()),
                    value: Some("encrypted field value".to_string()),
                    linked_id: None,
                },
                rbw::db::Field {
                    ty: Some(rbw::api::FieldType::Hidden),
                    name: Some("encrypted hidden name".to_string()),
                    value: Some("encrypted hidden value".to_string()),
                    linked_id: None,
                },
            ],
            notes: Some("encrypted notes".to_string()),
            history: vec![rbw::db::HistoryEntry {
                last_used_date: "2020-01-01".to_string(),
                password: "encrypted old password".to_string(),
            }],
            key: Some("entry key".to_string()),
            master_password_reprompt: rbw::api::CipherRepromptType::None,
            attachments: vec![],
            favorite: false,
            archived: false,
            collection_ids: vec![],
        };
        let entries = vec![entry.clone(), entry];

        let search_items = check(&entries, |entry, decryptor| {
            decrypt_search_cipher(entry, decryptor)
        });
        // search must never ask for hidden field values (they could
        // trigger master password reprompt)
        assert!(!search_items
            .iter()
            .any(|item| item.cipherstring == "encrypted hidden value"));

        check(&entries, |entry, decryptor| {
            decrypt_cipher(entry, decryptor)
        });
        check(&entries, |entry, decryptor| {
            decrypt_list_cipher(entry, &ListField::all(), decryptor)
        });
    }

    fn make_entry(
        name: &str,
        username: Option<&str>,
        folder: Option<&str>,
        uris: &[(&str, Option<rbw::api::UriMatchType>)],
    ) -> (rbw::db::Entry, DecryptedSearchCipher) {
        let id = uuid::Uuid::new_v4();
        (
            rbw::db::Entry {
                id: id.to_string(),
                org_id: None,
                folder: folder.map(|_| "encrypted folder name".to_string()),
                folder_id: None,
                name: "this is the encrypted name".to_string(),
                data: rbw::db::EntryData::Login {
                    username: username.map(|_| {
                        "this is the encrypted username".to_string()
                    }),
                    password: None,
                    uris: uris
                        .iter()
                        .map(|(_, match_type)| rbw::db::Uri {
                            uri: "this is the encrypted uri".to_string(),
                            match_type: *match_type,
                        })
                        .collect(),
                    totp: None,
                },
                fields: vec![],
                notes: None,
                history: vec![],
                key: None,
                master_password_reprompt: rbw::api::CipherRepromptType::None,
                attachments: vec![],
                favorite: false,
                archived: false,
                collection_ids: vec![],
            },
            DecryptedSearchCipher {
                id: id.to_string(),
                entry_type: "Login".to_string(),
                folder: folder.map(std::string::ToString::to_string),
                name: name.to_string(),
                user: username.map(std::string::ToString::to_string),
                uris: uris
                    .iter()
                    .map(|(uri, match_type)| {
                        ((*uri).to_string(), *match_type)
                    })
                    .collect(),
                fields: vec![],
                notes: None,
            },
        )
    }
    mod inject_tests {
        use super::*;

        fn render_inject_template<F>(
            template: &str,
            resolver: F,
        ) -> anyhow::Result<String>
        where
            F: FnMut(&InjectReference) -> anyhow::Result<String>,
        {
            InjectTemplate::new(template).render(resolver)
        }

        fn render_inject_template_with_env<F>(
            template: &str,
            env: &[(&str, &str)],
            resolver: F,
        ) -> anyhow::Result<String>
        where
            F: FnMut(&InjectReference) -> anyhow::Result<String>,
        {
            InjectTemplate::new(template).render_with_variable_resolver(
                |name| {
                    env.iter().find_map(|(key, value)| {
                        key.eq_ignore_ascii_case(name)
                            .then(|| (*value).to_string())
                    })
                },
                resolver,
            )
        }

        #[test]
        fn test_take_braced_inject_expression_returns_expression_and_tail() {
            let template = InjectTemplate::new(
                "{{ bw://some-api-key?field=username }} and more",
            );
            let (expr, next_start) =
                template.take_braced_expression(0).unwrap();

            assert_eq!(expr, " bw://some-api-key?field=username ");
            assert_eq!(template.src.get(next_start..).unwrap(), " and more");
        }

        #[test]
        fn test_parse_braced_inject_reference_trims_and_parses_bw_urls() {
            let reference = InjectReference::parse_braced(
                " bw://some-api-key?field=username ",
            )
            .unwrap()
            .unwrap();

            assert_eq!(
                reference.target,
                InjectReferenceTarget::Name("some-api-key".to_string())
            );
            assert_eq!(reference.field.as_deref(), Some("username"));
        }

        #[test]
        fn test_parse_braced_inject_reference_ignores_non_bw_expressions() {
            let reference =
                InjectReference::parse_braced(" not-a-reference ").unwrap();

            assert_eq!(reference, None);
        }

        #[test]
        fn test_render_inject_template_replaces_braced_and_raw_refs() {
            let password_id = uuid::Uuid::new_v4();
            let username_id = uuid::Uuid::new_v4();
            let template = format!(
                "password={{{{ bw://{password_id} }}}}\nuser=bw://{username_id}?field=username"
            );

            let rendered = render_inject_template(&template, |reference| {
                match (reference.id.as_str(), reference.field.as_deref()) {
                    (id, None) if id == password_id.to_string() => {
                        Ok("hunter2".to_string())
                    }
                    (id, Some("username"))
                        if id == username_id.to_string() =>
                    {
                        Ok("alice".to_string())
                    }
                    _ => Err(anyhow::anyhow!("unexpected reference")),
                }
            })
            .unwrap();

            assert_eq!(rendered, "password=hunter2\nuser=alice");
        }

        #[test]
        fn test_render_inject_template_supports_name_refs() {
            let template = "token=bw://some-api-key";

            let rendered = render_inject_template(template, |reference| {
                assert_eq!(
                    reference.target,
                    InjectReferenceTarget::Name("some-api-key".to_string())
                );
                assert_eq!(reference.field, None);
                Ok("secret".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "token=secret");
        }

        #[test]
        fn test_render_inject_template_supports_name_refs_with_field_query() {
            let template = "user=bw://some-api-key?field=username";

            let rendered = render_inject_template(template, |reference| {
                assert_eq!(
                    reference.target,
                    InjectReferenceTarget::Name("some-api-key".to_string())
                );
                assert_eq!(reference.field.as_deref(), Some("username"));
                Ok("alice".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "user=alice");
        }

        #[test]
        fn test_render_inject_template_expands_variables_before_resolving_refs(
        ) {
            let template =
                "user=bw://${ ITEM_NAME }?field=${FIELD:-username}";

            let rendered = render_inject_template_with_env(
                template,
                &[("item_name", "some-api-key")],
                |reference| {
                    assert_eq!(
                        reference.target,
                        InjectReferenceTarget::Name(
                            "some-api-key".to_string()
                        )
                    );
                    assert_eq!(reference.field.as_deref(), Some("username"));
                    Ok("alice".to_string())
                },
            )
            .unwrap();

            assert_eq!(rendered, "user=alice");
        }

        #[test]
        fn test_render_inject_template_supports_nested_default_variables() {
            let template = "${ITEM_NAME:-${FALLBACK_ITEM:-some-api-key}}";

            let rendered =
                render_inject_template_with_env(template, &[], |_| {
                    anyhow::bail!("unexpected inject reference")
                })
                .unwrap();
            assert_eq!(rendered, "some-api-key");

            let rendered = render_inject_template_with_env(
                template,
                &[("fallback_item", "fallback-key")],
                |_| anyhow::bail!("unexpected inject reference"),
            )
            .unwrap();
            assert_eq!(rendered, "fallback-key");
        }

        #[test]
        fn test_render_inject_template_treats_invalid_variable_tags_as_literals(
        ) {
            let template = "$1BAD ${foo-bar} cost=$5";

            let rendered =
                render_inject_template_with_env(template, &[], |_| {
                    anyhow::bail!("unexpected inject reference")
                })
                .unwrap();

            assert_eq!(rendered, template);
        }

        #[test]
        fn test_render_inject_template_supports_quoted_braced_refs() {
            let template =
                r#"password={{ "bw://some-api-key?field=db.password" }}"#;

            let rendered = render_inject_template(template, |reference| {
                assert_eq!(
                    reference.target,
                    InjectReferenceTarget::Name("some-api-key".to_string())
                );
                assert_eq!(reference.field.as_deref(), Some("db.password"));
                Ok("hunter2".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "password=hunter2");
        }

        #[test]
        fn test_render_inject_template_preserves_quoted_non_reference_expressions(
        ) {
            let template = r#"before {{ "not-a-reference" + "x" }} after"#;

            let rendered = render_inject_template(template, |_| {
                anyhow::bail!("unexpected inject reference")
            })
            .unwrap();

            assert_eq!(rendered, template);
        }

        #[test]
        fn test_render_inject_template_respects_op_inject_raw_start_boundaries(
        ) {
            let entry_id = uuid::Uuid::new_v4();

            let rendered = render_inject_template(
                &format!("prefix_bw://{entry_id}"),
                |reference| {
                    assert_eq!(reference.id, entry_id.to_string());
                    Ok("secret".to_string())
                },
            )
            .unwrap();
            assert_eq!(rendered, "prefix_secret");

            for template in [
                format!("prefix+bw://{entry_id}"),
                format!(r"prefix\bw://{entry_id}"),
                format!("prefix.bw://{entry_id}"),
            ] {
                let rendered = render_inject_template(&template, |_| {
                    Ok("secret".to_string())
                })
                .unwrap();
                assert_eq!(rendered, template);
            }
        }

        #[test]
        fn test_render_inject_template_preserves_trailing_punctuation() {
            let entry_id = uuid::Uuid::new_v4();
            for (template, resolved, expected) in [
                (
                    format!("dsn=bw://{entry_id}, done."),
                    "postgres://db",
                    "dsn=postgres://db, done.".to_string(),
                ),
                (
                    format!(
                        "token=bw://{entry_id}. wow! alert=bw://{entry_id}!"
                    ),
                    "secret",
                    "token=secret. wow! alert=secret!".to_string(),
                ),
            ] {
                let rendered =
                    render_inject_template(&template, |reference| {
                        assert_eq!(reference.id, entry_id.to_string());
                        assert_eq!(reference.field, None);
                        Ok(resolved.to_string())
                    })
                    .unwrap();

                assert_eq!(rendered, expected);
            }
        }

        #[test]
        fn test_render_inject_template_treats_special_characters_as_raw_reference_boundaries(
        ) {
            let entry_id = uuid::Uuid::new_v4();
            for (template, expected, field) in [
                (
                    format!("dsn=bw://{entry_id}/extra"),
                    "dsn=secret/extra".to_string(),
                    None,
                ),
                (
                    format!("dsn=bw://{entry_id}#prod"),
                    "dsn=secret#prod".to_string(),
                    None,
                ),
                (
                    format!("value=bw://{entry_id}:5432"),
                    "value=secret:5432".to_string(),
                    None,
                ),
                (
                    format!("value=bw://{entry_id}@host"),
                    "value=secret@host".to_string(),
                    None,
                ),
                (
                    format!("value=bw://{entry_id}=suffix"),
                    "value=secret=suffix".to_string(),
                    None,
                ),
                (
                    format!("bw://{entry_id}?field=username&field=password"),
                    "alice&field=password".to_string(),
                    Some("username"),
                ),
                (
                    format!("bw://{entry_id}?field=username&bogus=1"),
                    "alice&bogus=1".to_string(),
                    Some("username"),
                ),
            ] {
                let rendered =
                    render_inject_template(&template, |reference| {
                        assert_eq!(reference.id, entry_id.to_string());
                        assert_eq!(reference.field.as_deref(), field);
                        Ok(if field.is_some() { "alice" } else { "secret" }
                            .to_string())
                    })
                    .unwrap();

                assert_eq!(rendered, expected);
            }
        }

        #[test]
        fn test_render_inject_template_supports_raw_field_names_with_periods()
        {
            let entry_id = uuid::Uuid::new_v4();
            let template =
                format!("token=bw://{entry_id}?field=db.password, done");

            let rendered = render_inject_template(&template, |reference| {
                assert_eq!(reference.id, entry_id.to_string());
                assert_eq!(reference.field.as_deref(), Some("db.password"));
                Ok("secret".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "token=secret, done");
        }

        #[test]
        fn test_render_inject_template_supports_encoded_raw_field_queries() {
            let entry_id = uuid::Uuid::new_v4();
            for template in [
                format!("token=bw://{entry_id}?field=API%20Token"),
                format!("token=bw://{entry_id}?field=API+Token"),
            ] {
                let rendered =
                    render_inject_template(&template, |reference| {
                        assert_eq!(reference.id, entry_id.to_string());
                        assert_eq!(
                            reference.field.as_deref(),
                            Some("API Token")
                        );
                        Ok("secret".to_string())
                    })
                    .unwrap();

                assert_eq!(rendered, "token=secret");
            }
        }

        #[test]
        fn test_render_inject_template_rejects_empty_field_query() {
            let entry_id = uuid::Uuid::new_v4();
            let template = format!("token=bw://{entry_id}?field=");

            let err = render_inject_template(&template, |_| {
                Ok("secret".to_string())
            })
            .unwrap_err();

            assert!(format!("{err}").contains("empty"));
        }

        #[test]
        fn test_render_inject_template_supports_raw_refs_in_dsn_and_query_contexts(
        ) {
            let dsn_id = uuid::Uuid::new_v4();
            let query_id = uuid::Uuid::new_v4();
            let template = format!(
                "postgres://user:bw://{dsn_id}@db.example/app?token=bw://{query_id}&mode=ro"
            );

            let rendered =
                render_inject_template(
                    &template,
                    |reference| match reference.id.as_str() {
                        id if id == dsn_id.to_string() => {
                            Ok("pw".to_string())
                        }
                        id if id == query_id.to_string() => {
                            Ok("token".to_string())
                        }
                        _ => Err(anyhow::anyhow!("unexpected reference")),
                    },
                )
                .unwrap();

            assert_eq!(
                rendered,
                "postgres://user:pw@db.example/app?token=token&mode=ro"
            );
        }

        #[test]
        fn test_render_inject_template_supports_raw_field_refs_in_outer_query_contexts(
        ) {
            let entry_id = uuid::Uuid::new_v4();
            let template = format!(
                "https://example.test?user=bw://{entry_id}?field=username&mode=ro"
            );

            let rendered = render_inject_template(&template, |reference| {
                assert_eq!(reference.id, entry_id.to_string());
                assert_eq!(reference.field.as_deref(), Some("username"));
                Ok("alice".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "https://example.test?user=alice&mode=ro");
        }

        #[test]
        fn test_render_inject_template_supports_raw_field_refs_in_dsn_username_contexts(
        ) {
            let entry_id = uuid::Uuid::new_v4();
            let template = format!(
                "postgres://bw://{entry_id}?field=username@db.example/app"
            );

            let rendered = render_inject_template(&template, |reference| {
                assert_eq!(reference.id, entry_id.to_string());
                assert_eq!(reference.field.as_deref(), Some("username"));
                Ok("alice".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "postgres://alice@db.example/app");
        }

        #[test]
        fn test_render_inject_template_replaces_unenclosed_refs_in_structured_text(
        ) {
            let entry_id = uuid::Uuid::new_v4();
            for (template, expected) in [
                (
                    format!(
                        "apiVersion: v1\nkind: Secret\nstringData:\n  password: \"{{{{ bw://{entry_id} }}}}\"\n  note: \"bw://{entry_id}\"\n"
                    ),
                    "apiVersion: v1\nkind: Secret\nstringData:\n  password: \"hunter2\"\n  note: \"hunter2\"\n"
                        .to_string(),
                ),
                (
                    format!(
                        "{{\n  \"password\": \"{{{{ bw://{entry_id} }}}}\",\n  \"note\": \"bw://{entry_id}\"\n}}\n"
                    ),
                    "{\n  \"password\": \"hunter2\",\n  \"note\": \"hunter2\"\n}\n"
                        .to_string(),
                ),
            ] {
                let rendered = render_inject_template(&template, |reference| {
                    assert_eq!(reference.id, entry_id.to_string());
                    Ok("hunter2".to_string())
                })
                .unwrap();

                assert_eq!(rendered, expected);
            }
        }

        #[test]
        fn test_find_inject_entry_raw_matches_name_refs_exactly_ignoring_case(
        ) {
            let entries = &[
                make_entry("some-api-key", None, None, &[]),
                make_entry("some-api-key-prod", None, None, &[]),
            ];

            let (entry, _) =
                InjectReferenceTarget::Name("SOME-API-KEY".to_string())
                    .find_entry(entries)
                    .unwrap();

            assert_eq!(entry.id, entries[0].0.id);
        }

        #[test]
        fn test_find_inject_entry_raw_rejects_duplicate_name_refs() {
            let entries = &[
                make_entry("some-api-key", Some("alice"), None, &[]),
                make_entry("some-api-key", Some("bob"), None, &[]),
            ];

            let err = InjectReferenceTarget::Name("some-api-key".to_string())
                .find_entry(entries)
                .unwrap_err();

            assert!(format!("{err}").contains("multiple entries found"));
            assert!(format!("{err}").contains("use bw://<uuid> instead"));
        }

        #[test]
        fn test_find_inject_entry_raw_does_not_fuzzy_match_name_refs() {
            let entries = &[make_entry("some-api-key-prod", None, None, &[])];

            let err = InjectReferenceTarget::Name("some-api-key".to_string())
                .find_entry(entries)
                .unwrap_err();

            assert!(format!("{err}").contains("no entry found"));
        }

        #[test]
        fn test_parse_inject_reference_rejects_userinfo_ports_and_paths() {
            let entry_id = uuid::Uuid::new_v4();

            for reference in [
                format!("bw://user@{entry_id}"),
                format!("bw://user:pass@{entry_id}"),
                format!("bw://{entry_id}:5432"),
                format!("bw://{entry_id}/"),
            ] {
                assert!(
                    InjectReference::parse(&reference).is_err(),
                    "{reference} should be rejected"
                );
            }
        }

        #[test]
        fn test_parse_run_env_matches_dotenvy_parsing_rules() {
            let pairs = parse_run_env_file(
                concat!(
                    "BACKSLASH='a\\\\b'\n",
                    "PATH='C:\\temp\\logs\\q'\n",
                    r#"ESCAPED="contains \"quote\" and slash \\ and newline \n""#,
                    "\n",
                    "HASH=# comment\n",
                    "MULTILINE=\"line 1\nline 2\"\n",
                ),
                |_| anyhow::bail!("unexpected inject reference"),
            )
            .unwrap();

            assert_eq!(
                pairs,
                vec![
                    ("BACKSLASH".to_string(), r"a\\b".to_string()),
                    ("PATH".to_string(), r"C:\temp\logs\q".to_string()),
                    (
                        "ESCAPED".to_string(),
                        "contains \"quote\" and slash \\ and newline \n"
                            .to_string()
                    ),
                    ("HASH".to_string(), String::new()),
                    ("MULTILINE".to_string(), "line 1\nline 2".to_string()),
                ]
            );
        }

        #[test]
        fn test_parse_run_env_expands_then_resolves_raw_references() {
            use std::sync::{Mutex, OnceLock};

            static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

            let _guard =
                ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
            let host_var = "RBW_TEST_HOST_VAR";
            std::env::set_var(host_var, "expanded-by-host");

            let entry_id = uuid::Uuid::new_v4();
            let template = format!(
                "RAW=bw://{entry_id}\nQUOTED=\"bw://{entry_id}\"\nCOPY=$RAW\nHOST=${{{host_var}}}\nMIXED=${{{host_var}}}:$RAW\nLITERAL=__RBW_RUN_BRACED_REF_0__\nEXPANDED=${{LITERAL}}\n"
            );

            let pairs = parse_run_env_file(&template, |reference| {
                assert_eq!(reference.id, entry_id.to_string());
                Ok("secret".to_string())
            })
            .unwrap();

            std::env::remove_var(host_var);

            assert_eq!(
                pairs,
                vec![
                    ("RAW".to_string(), "secret".to_string()),
                    ("QUOTED".to_string(), "secret".to_string()),
                    ("COPY".to_string(), "secret".to_string()),
                    ("HOST".to_string(), "expanded-by-host".to_string()),
                    (
                        "MIXED".to_string(),
                        "expanded-by-host:secret".to_string()
                    ),
                    (
                        "LITERAL".to_string(),
                        "__RBW_RUN_BRACED_REF_0__".to_string()
                    ),
                    (
                        "EXPANDED".to_string(),
                        "__RBW_RUN_BRACED_REF_0__".to_string()
                    ),
                ]
            );
        }

        #[test]
        fn test_parse_run_env_preserves_injected_values_verbatim() {
            let token_id = uuid::Uuid::new_v4().to_string();
            let secret_id = uuid::Uuid::new_v4().to_string();
            let multiline_id = uuid::Uuid::new_v4().to_string();
            let template = format!(
                "TOKEN=bw://{token_id}\nSECRET='bw://{secret_id}'\nMULTILINE=\"bw://{multiline_id}\"\n"
            );

            let pairs = parse_run_env_file(&template, |reference| {
                match reference.id.as_str() {
                    id if id == token_id => {
                        Ok("abc#not-a-comment".to_string())
                    }
                    id if id == secret_id => {
                        Ok("value with \"double\" and 'single' quotes"
                            .to_string())
                    }
                    id if id == multiline_id => {
                        Ok("line 1\nline 2  ".to_string())
                    }
                    _ => anyhow::bail!(
                        "unexpected inject reference '{}'",
                        reference.id
                    ),
                }
            })
            .unwrap();

            assert_eq!(
                pairs,
                vec![
                    ("TOKEN".to_string(), "abc#not-a-comment".to_string()),
                    (
                        "SECRET".to_string(),
                        "value with \"double\" and 'single' quotes"
                            .to_string()
                    ),
                    ("MULTILINE".to_string(), "line 1\nline 2  ".to_string()),
                ]
            );
        }

        #[test]
        fn test_build_inject_run_command_overrides_inherited_env_bindings() {
            let env_bindings = vec![
                ("API_KEY".to_string(), "new-secret".to_string()),
                ("EXTRA".to_string(), "value".to_string()),
            ];
            let command = build_inject_run_command(
                &[std::ffi::OsString::from("env")],
                &env_bindings,
            )
            .unwrap();

            let envs = command
                .get_envs()
                .map(|(key, value)| {
                    (
                        key.to_os_string(),
                        value.map(std::ffi::OsStr::to_os_string),
                    )
                })
                .collect::<std::collections::BTreeMap<
                    std::ffi::OsString,
                    Option<std::ffi::OsString>,
                >>();

            assert_eq!(
                envs.get(std::ffi::OsStr::new("API_KEY")),
                Some(&Some(std::ffi::OsString::from("new-secret")))
            );
            assert_eq!(
                envs.get(std::ffi::OsStr::new("EXTRA")),
                Some(&Some(std::ffi::OsString::from("value")))
            );
        }

        #[test]
        #[cfg(unix)]
        fn test_inject_run_passes_values_without_shell_evaluation() {
            use std::process::Stdio;

            let env_bindings =
                parse_run_env_file("VALUE='$(echo still-literal)'\n", |_| {
                    anyhow::bail!("unexpected inject reference")
                })
                .unwrap();
            let mut command = build_inject_run_command(
                &[
                    std::ffi::OsString::from("printenv"),
                    std::ffi::OsString::from("VALUE"),
                ],
                &env_bindings,
            )
            .unwrap();
            command.stdout(Stdio::piped());

            let output = command.output().unwrap();

            assert!(output.status.success());
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                "$(echo still-literal)\n"
            );
        }

        #[test]
        #[cfg(unix)]
        fn test_run_inject_command_returns_child_exit_status() {
            let status =
                run_inject_command(&[std::ffi::OsString::from("false")], &[])
                    .unwrap();

            assert_eq!(status.code(), Some(1));
        }

        #[test]
        fn test_resolve_inject_value_uses_password_username_and_custom_fields(
        ) {
            let cipher = DecryptedCipher {
                id: uuid::Uuid::new_v4().to_string(),
                folder: None,
                name: "example".to_string(),
                data: DecryptedData::Login {
                    username: Some("alice".to_string()),
                    password: Some("hunter2".to_string()),
                    totp: None,
                    uris: None,
                },
                fields: [("api-token", "xyz"), ("deployment", "prod")]
                    .iter()
                    .map(|(name, value)| DecryptedField {
                        name: Some((*name).to_string()),
                        value: Some((*value).to_string()),
                        ty: None,
                    })
                    .collect(),
                notes: None,
                history: vec![],
                attachments: vec![],
            };

            assert_eq!(
                resolve_inject_value(&cipher, None).unwrap(),
                "hunter2"
            );
            assert_eq!(
                resolve_inject_value(&cipher, Some("username")).unwrap(),
                "alice"
            );
            assert_eq!(
                resolve_inject_value(&cipher, Some("api-token")).unwrap(),
                "xyz"
            );
        }

        #[test]
        #[cfg(unix)]
        fn test_write_rendered_template_file_replaces_existing_file_atomically(
        ) {
            use std::os::unix::fs::MetadataExt as _;

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("secret.txt");
            std::fs::write(&path, "existing").unwrap();
            let original_inode = std::fs::metadata(&path).unwrap().ino();

            write_rendered_template_file(&path, "hunter2").unwrap();

            assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
            let updated_inode = std::fs::metadata(&path).unwrap().ino();
            assert_ne!(updated_inode, original_inode);
        }

        #[test]
        #[cfg(unix)]
        fn test_write_rendered_template_file_accepts_bare_relative_paths() {
            use std::os::unix::fs::PermissionsExt as _;

            struct CwdGuard(std::path::PathBuf);

            impl Drop for CwdGuard {
                fn drop(&mut self) {
                    let _ = std::env::set_current_dir(&self.0);
                }
            }

            let dir = tempfile::tempdir().unwrap();
            let cwd = std::env::current_dir().unwrap();
            let _guard = CwdGuard(cwd);
            std::env::set_current_dir(dir.path()).unwrap();

            let path = std::path::Path::new("secret.txt");
            write_rendered_template_file(path, "hunter2").unwrap();

            assert_eq!(std::fs::read_to_string(path).unwrap(), "hunter2");
            let mode =
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        #[test]
        #[cfg(unix)]
        fn test_write_rendered_template_file_uses_owner_only_permissions() {
            use std::os::unix::fs::PermissionsExt as _;

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("secret.txt");
            write_rendered_template_file(&path, "hunter2").unwrap();

            let mode = std::fs::metadata(&path).unwrap().permissions().mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        #[test]
        #[cfg(unix)]
        fn test_write_rendered_template_file_rejects_symlinks() {
            use std::os::unix::fs::symlink;

            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("target.txt");
            std::fs::write(&target, "existing").unwrap();
            let link = dir.path().join("secret.txt");
            symlink(&target, &link).unwrap();

            let err =
                write_rendered_template_file(&link, "hunter2").unwrap_err();
            assert!(format!("{err}").contains("must not be a symlink"));
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "existing");
        }

        #[test]
        #[cfg(unix)]
        fn test_write_rendered_template_file_rejects_non_regular_files() {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt as _;
            use std::os::unix::fs::OpenOptionsExt as _;

            let dir = tempfile::tempdir().unwrap();
            let fifo = dir.path().join("secret.fifo");
            let fifo_cstr =
                CString::new(fifo.as_os_str().as_bytes()).unwrap();
            let status = unsafe { libc::mkfifo(fifo_cstr.as_ptr(), 0o600) };
            assert_eq!(status, 0);

            let _reader = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo)
                .unwrap();

            let err =
                write_rendered_template_file(&fifo, "hunter2").unwrap_err();
            assert!(format!("{err}").contains("regular file"));
        }
    }
}
