// The tui's sidebar: the same views as the official clients (all items,
// favorites, types, vaults, collections, folders, archive, trash).

use crate::commands::{TuiEntry, TuiVault};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum View {
    All,
    Favorites,
    Kind(&'static str),
    MyVault,
    Org(String),
    Collection(String),
    // None: the items without a folder
    Folder(Option<String>),
    Archive,
    Trash,
}

// (kind as TuiEntry names it, label)
pub const KINDS: [(&str, &str); 5] = [
    ("login", "Login"),
    ("card", "Card"),
    ("identity", "Identity"),
    ("note", "Secure note"),
    ("ssh key", "SSH key"),
];

pub enum Row {
    Header(&'static str),
    View {
        view: View,
        label: String,
        count: Option<usize>,
    },
}

impl View {
    // archived items only show up in the archive, as in the official
    // clients; the trash has its own list
    pub fn matches(&self, e: &TuiEntry) -> bool {
        if *self == Self::Archive {
            return e.archived;
        }
        if e.archived {
            return false;
        }
        match self {
            Self::All => true,
            Self::Favorites => e.favorite,
            Self::Kind(kind) => e.kind == *kind,
            Self::MyVault => e.org_id.is_none(),
            Self::Org(id) => e.org_id.as_ref() == Some(id),
            Self::Collection(id) => e.collection_ids.contains(id),
            Self::Folder(id) => e.folder_id == *id,
            Self::Archive | Self::Trash => false,
        }
    }

    pub fn label(&self, vault: &TuiVault) -> String {
        let find = |list: &[(String, String)], id: &str| {
            list.iter()
                .find(|(i, _)| i == id)
                .map_or_else(|| id.to_string(), |(_, name)| name.clone())
        };
        match self {
            Self::All => "All items".to_string(),
            Self::Favorites => "Favorites".to_string(),
            Self::Kind(kind) => {
                KINDS.iter().find(|(k, _)| k == kind).map_or_else(
                    || (*kind).to_string(),
                    |(_, l)| (*l).to_string(),
                )
            }
            Self::MyVault => "My vault".to_string(),
            Self::Org(id) => find(&vault.organizations, id),
            Self::Collection(id) => vault
                .collections
                .iter()
                .find(|c| &c.id == id)
                .map_or_else(|| id.clone(), |c| c.name.clone()),
            Self::Folder(Some(id)) => find(&vault.folders, id),
            Self::Folder(None) => "No folder".to_string(),
            Self::Archive => "Archive".to_string(),
            Self::Trash => "Trash".to_string(),
        }
    }
}

pub fn rows(vault: &TuiVault, entries: &[TuiEntry]) -> Vec<Row> {
    let row = |view: View, label: String| {
        let count = (view != View::Trash)
            .then(|| entries.iter().filter(|e| view.matches(e)).count());
        Row::View { view, label, count }
    };
    let mut rows = vec![
        row(View::All, "All items".to_string()),
        row(View::Favorites, "★ Favorites".to_string()),
        Row::Header("Types"),
    ];
    for (kind, label) in KINDS {
        rows.push(row(View::Kind(kind), label.to_string()));
    }
    if !vault.organizations.is_empty() {
        rows.push(Row::Header("Vaults"));
        rows.push(row(View::MyVault, "My vault".to_string()));
        for (id, name) in &vault.organizations {
            rows.push(row(View::Org(id.clone()), name.clone()));
        }
    }
    if !vault.collections.is_empty() {
        rows.push(Row::Header("Collections"));
        let several = vault.organizations.len() > 1;
        for c in &vault.collections {
            let label = if several {
                let org = vault
                    .organizations
                    .iter()
                    .find(|(id, _)| id == &c.org_id)
                    .map_or("", |(_, name)| name.as_str());
                format!("{} ({org})", c.name)
            } else {
                c.name.clone()
            };
            rows.push(row(View::Collection(c.id.clone()), label));
        }
    }
    rows.push(Row::Header("Folders"));
    for (id, name) in &vault.folders {
        rows.push(row(View::Folder(Some(id.clone())), name.clone()));
    }
    rows.push(row(View::Folder(None), "No folder".to_string()));
    rows.push(Row::Header(""));
    rows.push(row(View::Archive, "Archive".to_string()));
    rows.push(row(View::Trash, "Trash".to_string()));
    rows
}
