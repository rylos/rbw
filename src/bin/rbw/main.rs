use std::ffi::OsString;
use std::io::Write as _;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt as _;

use anyhow::Context as _;
use clap::{CommandFactory as _, Parser as _};

mod actions;
mod commands;
mod items;
mod settings;
mod sock;
mod tui;
mod typer;
mod views;

#[derive(Debug, clap::Args)]
struct FindArgs {
    #[arg(help = "Name, URI or UUID of the entry to display", value_parser = commands::parse_needle)]
    needle: commands::Needle,
    #[arg(help = "Username of the entry to display")]
    user: Option<String>,
    #[arg(long, help = "Folder name to search in")]
    folder: Option<String>,
    #[arg(short, long, help = "Ignore case")]
    ignorecase: bool,
}

// values that can be set on an entry from the command line
#[derive(Debug, clap::Args)]
struct ValueArgs {
    #[arg(long, help = "Set the username")]
    username: Option<String>,
    #[arg(long, help = "Read the password from the first line of stdin")]
    password_stdin: bool,
    #[arg(long, help = "Set the TOTP secret or otpauth:// URI")]
    totp: Option<String>,
    #[arg(
        long,
        value_name = "NAME=VALUE",
        help = "Set a text custom field",
        value_parser = items::parse_field,
        number_of_values = 1
    )]
    field: Vec<(String, String)>,
    #[arg(
        long,
        value_name = "NAME=VALUE",
        help = "Set a hidden custom field",
        value_parser = items::parse_field,
        number_of_values = 1
    )]
    hidden_field: Vec<(String, String)>,
    #[arg(long, help = "Set the notes")]
    notes: Option<String>,
    #[arg(long, help = "Read the notes from a file (- for stdin)")]
    notes_file: Option<std::path::PathBuf>,
}

impl ValueArgs {
    fn changes(self) -> items::Changes {
        let mut fields: Vec<_> = self
            .field
            .into_iter()
            .map(|(name, value)| (items::FIELD_TYPE_TEXT, name, value))
            .collect();
        fields.extend(
            self.hidden_field
                .into_iter()
                .map(|(name, value)| (items::FIELD_TYPE_HIDDEN, name, value)),
        );
        items::Changes {
            username: self.username,
            password_stdin: self.password_stdin,
            totp: self.totp,
            fields,
            notes: self.notes,
            notes_file: self.notes_file,
            ..items::Changes::default()
        }
    }
}

#[derive(Debug, clap::Subcommand)]
enum FolderCommand {
    #[command(about = "List folders", visible_alias = "ls")]
    List {
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
    },
    #[command(about = "Create a folder")]
    Add { name: String },
    #[command(about = "Rename a folder")]
    Rename { name: String, new_name: String },
    #[command(
        about = "Delete a folder (its entries are kept, without a folder)",
        visible_alias = "rm"
    )]
    Remove { name: String },
}

#[derive(Debug, clap::Subcommand)]
enum AttachmentCommand {
    #[command(
        about = "List the attachments of an entry",
        visible_alias = "ls"
    )]
    List {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
    },
    #[command(about = "Save an attachment to a file")]
    Get {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            long,
            help = "File name or id of the attachment (needed when there \
                is more than one)"
        )]
        name: Option<String>,
        #[arg(
            short,
            long,
            help = "Where to save it (- for stdout); defaults to the \
                attachment's name in the current directory"
        )]
        output: Option<std::path::PathBuf>,
        #[arg(long, help = "Overwrite the output file if it exists")]
        force: bool,
    },
    #[command(about = "Attach files to an entry")]
    Add {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            long,
            required = true,
            help = "File to attach (- for stdin); repeat for more",
            number_of_values = 1
        )]
        file: Vec<std::path::PathBuf>,
        #[arg(
            long,
            help = "Name to store the attachment under (default: the \
                file's name)"
        )]
        name: Option<String>,
    },
    #[command(about = "Delete an attachment", visible_alias = "rm")]
    Remove {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            long,
            help = "File name or id of the attachment (needed when there \
                is more than one)"
        )]
        name: Option<String>,
    },
}

#[derive(Debug, clap::Subcommand)]
enum PinCommand {
    #[command(about = "Choose a pin to unlock with (the agent must be \
        unlocked)")]
    Set,
    #[command(about = "Stop unlocking with a pin")]
    Clear,
}

#[derive(Debug, clap::Parser)]
#[command(version, about = "Unofficial Bitwarden CLI")]
enum Opt {
    #[command(about = "Get or set configuration options")]
    Config {
        #[command(subcommand)]
        config: Config,
    },

    #[command(
        about = "Register this device with the Bitwarden server",
        long_about = "Register this device with the Bitwarden server\n\n\
            The official Bitwarden server includes bot detection to prevent \
            brute force attacks. In order to avoid being detected as bot \
            traffic, you will need to use this command to log in with your \
            personal API key (instead of your password) first before regular \
            logins will work."
    )]
    Register,

    #[command(about = "Log in to the Bitwarden server")]
    Login,

    #[command(about = "Unlock the local Bitwarden database")]
    Unlock,

    #[command(about = "Check if the local Bitwarden database is unlocked")]
    Unlocked,

    #[command(
        about = "Show the agent's state without starting it or prompting"
    )]
    Status {
        #[arg(long, help = "Display output as JSON")]
        json: bool,
    },

    #[command(
        about = "Show how rbw locks and unlocks, and what this machine \
            supports",
        long_about = "Show how rbw locks and unlocks, and what this \
            machine supports\n\n\
            Like the official clients' security settings:\n\n  \
            rbw config set lock_timeout 1h|4h|90m|never   session timeout \
            (never: until the agent stops)\n  \
            rbw config set lock_on_sleep true             also when the \
            system wakes up\n  \
            rbw config set lock_on_idle true              also when the \
            session idles or the screen locks\n  \
            rbw config set timeout_action lock|forget     keep the keys \
            for a pin or system unlock, or need the master password\n  \
            rbw pin set                                   unlock with a \
            PIN\n  \
            rbw config set system_auth true               unlock through \
            polkit (face, fingerprint)\n  \
            rbw remember-password                         pin and system \
            unlock also after a restart"
    )]
    Security,

    #[command(about = "Set or clear the pin that unlocks rbw")]
    Pin {
        #[command(subcommand)]
        pin: PinCommand,
    },

    #[command(
        name = "remember-password",
        about = "Save the master password, so that pin and system unlock \
            also work for the first unlock after the agent starts",
        long_about = "Save the master password, so that pin and system \
            unlock also work for the first unlock after the agent \
            starts\n\n\
            Like unchecking \"require the master password on restart\" \
            in the official clients. The password is encrypted with \
            systemd-creds (tied to this machine, with the TPM2 when there \
            is one) or kept in the Secret Service. Any program running as \
            you can read it back: a pin or biometrics protect against \
            someone at the keyboard, not against malware."
    )]
    RememberPassword {
        #[arg(
            long,
            help = "Where to save it: systemd-creds or secret-service \
                (default: systemd-creds when it works)"
        )]
        store: Option<String>,
    },

    #[command(
        name = "forget-password",
        about = "Delete the saved master password"
    )]
    ForgetPassword,

    #[command(about = "Update the local copy of the Bitwarden database")]
    Sync,

    #[command(about = "Search the vault interactively and copy values")]
    Tui {
        #[arg(long, help = "Start on the security settings")]
        settings: bool,
    },

    #[command(
        about = "List all entries in the local Bitwarden database",
        visible_alias = "ls"
    )]
    List {
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder, type. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            use_value_delimiter = true
        )]
        fields: Vec<String>,
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
    },

    #[command(about = "Display the password for a given entry")]
    Get {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(short, long, help = "Field to get")]
        field: Option<String>,
        #[arg(long, help = "Display the notes in addition to the password")]
        full: bool,
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
        #[cfg(feature = "clipboard")]
        #[structopt(short, long, help = "Copy result to clipboard")]
        clipboard: bool,
        #[structopt(short, long, help = "List fields in this entry")]
        list_fields: bool,
    },

    #[command(about = "Search for entries")]
    Search {
        #[arg(help = "Search term to locate entries")]
        term: String,
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            use_value_delimiter = true
        )]
        fields: Vec<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
    },

    #[command(
        about = "Display the authenticator code for a given entry",
        visible_alias = "totp"
    )]
    Code {
        #[command(flatten)]
        find_args: FindArgs,
        #[cfg(feature = "clipboard")]
        #[structopt(long, help = "Copy result to clipboard")]
        clipboard: bool,
    },

    #[command(about = "Inject secrets into a template")]
    Inject {
        #[arg(
            short = 'i',
            long = "in-file",
            help = "Read the template from a file"
        )]
        input: Option<std::path::PathBuf>,
        #[arg(
            short = 'o',
            long = "out-file",
            help = "Write the rendered template to a file"
        )]
        output: Option<std::path::PathBuf>,
    },

    #[command(about = "Run a command with injected values")]
    Run {
        #[arg(
            long,
            default_value = "./.env",
            help = "Read environment bindings from an env file"
        )]
        env_file: std::path::PathBuf,
        #[arg(last = true, required = true, num_args = 1..)]
        command: Vec<OsString>,
    },

    #[command(
        about = "Add a new entry to the database",
        long_about = "Add a new entry to the database\n\n\
            Without any of the options that set values, this command opens \
            a text editor with every field of the new entry. The editor to \
            use is determined by the value of the $VISUAL or $EDITOR \
            environment variables.\n\n\
            When stdin is not a terminal and no values are given as \
            options, the first line of stdin is saved as the password and \
            the remainder as the notes."
    )]
    Add {
        #[arg(help = "Name of the password entry")]
        name: String,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(
            long,
            help = "URI for the password entry",
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the password entry")]
        folder: Option<String>,
        #[arg(long, help = "Create a secure note instead of a login")]
        secure_note: bool,
        #[arg(
            long = "type",
            value_name = "TYPE",
            conflicts_with = "secure_note",
            help = "Type of the new entry: login, note, card, identity or \
                ssh-key (a new ed25519 key is generated)"
        )]
        kind: Option<String>,
        #[arg(
            long,
            value_name = "NAME",
            help = "Create the entry in this organization (needs \
                --collection)"
        )]
        org: Option<String>,
        #[arg(
            long,
            value_name = "NAME",
            requires = "org",
            number_of_values = 1,
            help = "Collection of the organization to put the entry in"
        )]
        collection: Vec<String>,
        #[arg(
            long,
            help = "Don't open the editor, save the entry as given by the \
                options"
        )]
        no_edit: bool,
        #[arg(
            long,
            help = "Attach a file to the new entry",
            number_of_values = 1
        )]
        attach: Vec<std::path::PathBuf>,
        #[command(flatten)]
        values: ValueArgs,
    },

    #[command(
        about = "Generate a new password",
        long_about = "Generate a new password\n\n\
            If given a password entry name, also save the generated \
            password to the database.",
        visible_alias = "gen",
        group = clap::ArgGroup::new("password-type").args(&[
            "no_symbols",
            "only_numbers",
            "nonconfusables",
            "diceware",
        ])
    )]
    Generate {
        #[arg(help = "Length of the password to generate")]
        len: usize,
        #[arg(help = "Name of the password entry")]
        name: Option<String>,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(
            long,
            help = "URI for the password entry",
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the password entry")]
        folder: Option<String>,
        #[arg(
            long = "no-symbols",
            help = "Generate a password with no special characters"
        )]
        no_symbols: bool,
        #[arg(
            long = "only-numbers",
            help = "Generate a password consisting of only numbers"
        )]
        only_numbers: bool,
        #[arg(
            long,
            help = "Generate a password without visually similar \
                characters (useful for passwords intended to be \
                written down)"
        )]
        nonconfusables: bool,
        #[arg(
            long,
            help = "Generate a password of multiple dictionary \
                words chosen from the EFF word list. The len \
                parameter for this option will set the number \
                of words to generate, rather than characters."
        )]
        diceware: bool,
    },

    #[command(
        about = "Modify an existing entry",
        long_about = "Modify an existing entry\n\n\
            Without any of the options that change values, this command \
            opens a text editor with every field of the entry. The editor \
            to use is determined by the value of the $VISUAL or $EDITOR \
            environment variables.\n\n\
            Only the values that change are written back; everything else \
            about the entry (passkeys, attachments, favorite, ...) is kept."
    )]
    Edit {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(long, help = "New name for the entry")]
        rename: Option<String>,
        #[arg(long, help = "Move the entry to this folder (\"\" for none)")]
        move_to: Option<String>,
        #[arg(
            long,
            help = "Replace all URIs (repeat for more than one)",
            number_of_values = 1
        )]
        set_uri: Vec<String>,
        #[arg(long, help = "Add a URI", number_of_values = 1)]
        add_uri: Vec<String>,
        #[arg(
            long,
            help = "Remove the custom field with this name",
            number_of_values = 1
        )]
        remove_field: Vec<String>,
        #[arg(long, help = "Mark or unmark the entry as a favorite")]
        favorite: Option<bool>,
        #[command(flatten)]
        values: ValueArgs,
    },

    #[command(
        about = "Remove a given entry",
        long_about = "Remove a given entry\n\n\
            The entry is moved to the trash, from where `rbw restore` brings \
            it back.",
        visible_alias = "rm"
    )]
    Remove {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            long,
            help = "Delete the entry for good instead of moving it \
            to the trash"
        )]
        permanent: bool,
    },

    #[command(
        about = "Archive an entry",
        long_about = "Archive an entry\n\n\
            Archived entries are kept, but the official clients and `rbw \
            tui` show them only in the archive (`rbw list` and rofi-rbw \
            still list them). `rbw unarchive` brings them back."
    )]
    Archive {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "Bring an archived entry back into the vault")]
    Unarchive {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "List the entries in the trash")]
    Trash {
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
    },

    #[command(about = "Restore an entry from the trash")]
    Restore {
        #[arg(help = "Name or UUID of the entry in the trash")]
        needle: String,
    },

    #[command(about = "Manage folders")]
    Folder {
        #[command(subcommand)]
        folder: FolderCommand,
    },

    #[command(
        about = "Manage the attachments of an entry",
        visible_alias = "att"
    )]
    Attachment {
        #[command(subcommand)]
        attachment: AttachmentCommand,
    },

    #[command(about = "View the password history for a given entry")]
    History {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(
        about = "Lock the password database",
        long_about = "Lock the password database\n\n\
            With a pin or system unlock (and timeout_action lock) the \
            agent keeps the keys in memory and stops using them until one \
            of those unlocks; --hard drops them, so that the next unlock \
            needs the master password."
    )]
    Lock {
        #[arg(long, help = "Drop the keys from memory")]
        hard: bool,
    },

    #[command(about = "Remove the local copy of the password database")]
    Purge,

    #[command(name = "stop-agent", about = "Terminate the background agent")]
    StopAgent,

    #[command(
        name = "gen-completions",
        about = "Generate completion script for the given shell"
    )]
    GenCompletions { shell: CompletionShell },
}

impl Opt {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Config { config } => {
                format!("config {}", config.subcommand_name())
            }
            Self::Register => "register".to_string(),
            Self::Login => "login".to_string(),
            Self::Unlock => "unlock".to_string(),
            Self::Unlocked => "unlocked".to_string(),
            Self::Status { .. } => "status".to_string(),
            Self::Security => "security".to_string(),
            Self::Pin { .. } => "pin".to_string(),
            Self::RememberPassword { .. } => "remember-password".to_string(),
            Self::ForgetPassword => "forget-password".to_string(),
            Self::Sync => "sync".to_string(),
            Self::Tui { .. } => "tui".to_string(),
            Self::List { .. } => "list".to_string(),
            Self::Get { .. } => "get".to_string(),
            Self::Search { .. } => "search".to_string(),
            Self::Code { .. } => "code".to_string(),
            Self::Inject { .. } => "inject".to_string(),
            Self::Run { .. } => "run".to_string(),
            Self::Add { .. } => "add".to_string(),
            Self::Generate { .. } => "generate".to_string(),
            Self::Edit { .. } => "edit".to_string(),
            Self::Remove { .. } => "remove".to_string(),
            Self::Archive { .. } => "archive".to_string(),
            Self::Unarchive { .. } => "unarchive".to_string(),
            Self::Trash { .. } => "trash".to_string(),
            Self::Restore { .. } => "restore".to_string(),
            Self::Folder { .. } => "folder".to_string(),
            Self::Attachment { .. } => "attachment".to_string(),
            Self::History { .. } => "history".to_string(),
            Self::Lock { .. } => "lock".to_string(),
            Self::Purge => "purge".to_string(),
            Self::StopAgent => "stop-agent".to_string(),
            Self::GenCompletions { .. } => "gen-completions".to_string(),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Elvish,
    Nushell,
    Fig,
}

#[derive(Debug, clap::Parser)]
enum Config {
    #[command(about = "Show the values of all configuration settings")]
    Show,
    #[command(about = "Set a configuration option")]
    Set {
        #[arg(help = "Configuration key to set")]
        key: String,
        #[arg(help = "Value to set the configuration option to")]
        value: String,
    },
    #[command(about = "Reset a configuration option to its default")]
    Unset {
        #[arg(help = "Configuration key to unset")]
        key: String,
    },
}

impl Config {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Show => "show",
            Self::Set { .. } => "set",
            Self::Unset { .. } => "unset",
        }
        .to_string()
    }
}

fn main() {
    let opt = Opt::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .format(|buf, record| {
        if let Some((terminal_size::Width(w), _)) =
            terminal_size::terminal_size()
        {
            let out = format!("{}: {}", record.level(), record.args());
            writeln!(buf, "{}", textwrap::fill(&out, usize::from(w) - 1))
        } else {
            writeln!(buf, "{}: {}", record.level(), record.args())
        }
    })
    .init();

    let subcommand_name = opt.subcommand_name();
    let res = match opt {
        Opt::Config { config } => match config {
            Config::Show => commands::config_show(),
            Config::Set { key, value } => commands::config_set(&key, &value),
            Config::Unset { key } => commands::config_unset(&key),
        },
        Opt::Register => commands::register(),
        Opt::Login => commands::login(),
        Opt::Unlock => commands::unlock(),
        Opt::Unlocked => commands::unlocked(),
        Opt::Status { json } => commands::status(json),
        Opt::Security => commands::security(),
        Opt::Pin { pin } => match pin {
            PinCommand::Set => commands::pin_set(),
            PinCommand::Clear => commands::pin_clear(),
        },
        Opt::RememberPassword { store } => {
            commands::remember_password(store.as_deref())
        }
        Opt::ForgetPassword => commands::forget_password(),
        Opt::Sync => commands::sync(),
        Opt::Tui { settings } => tui::run(settings),
        Opt::List { fields, raw } => commands::list(&fields, raw),
        Opt::Get {
            find_args,
            field,
            full,
            raw,
            #[cfg(feature = "clipboard")]
            clipboard,
            list_fields,
        } => commands::get(
            find_args.needle.clone(),
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            field.as_deref(),
            full,
            raw,
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            find_args.ignorecase,
            list_fields,
        ),
        Opt::Search {
            term,
            fields,
            folder,
            raw,
        } => commands::search(&term, &fields, folder.as_deref(), raw),
        Opt::Code {
            find_args,
            #[cfg(feature = "clipboard")]
            clipboard,
        } => commands::code(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            find_args.ignorecase,
        ),
        Opt::Inject { input, output } => {
            commands::inject(input.as_deref(), output.as_deref())
        }
        Opt::Run { env_file, command } => commands::run(&env_file, &command)
            .map(|status| {
                if !status.success() {
                    #[cfg(unix)]
                    if let Some(signal) = status.signal() {
                        std::process::exit(128 + signal);
                    }
                    std::process::exit(status.code().unwrap_or(1));
                }
            }),
        Opt::Add {
            name,
            user,
            uri,
            folder,
            secure_note,
            kind,
            org,
            collection,
            no_edit,
            attach,
            values,
        } => (|| {
            let kind = match kind {
                Some(kind) => items::Kind::parse(&kind).ok_or_else(|| {
                    anyhow::anyhow!(
                        "unknown type '{kind}' (login, note, card, identity, \
                         ssh-key)"
                    )
                })?,
                None if secure_note => items::Kind::Note,
                None => items::Kind::Login,
            };
            let (org, collections) = match org {
                Some(org) => {
                    let (org, collections) =
                        items::resolve_collections(&org, &collection)?;
                    (Some(org), collections)
                }
                None => (None, vec![]),
            };
            items::add(&items::NewItem {
                name,
                username: user,
                uris: uri,
                folder,
                kind,
                org,
                collections,
                password: None,
                changes: values.changes(),
                no_edit,
                attach,
            })
        })(),
        Opt::Generate {
            len,
            name,
            user,
            uri,
            folder,
            no_symbols,
            only_numbers,
            nonconfusables,
            diceware,
        } => {
            let ty = if no_symbols {
                rbw::pwgen::Type::NoSymbols
            } else if only_numbers {
                rbw::pwgen::Type::Numbers
            } else if nonconfusables {
                rbw::pwgen::Type::NonConfusables
            } else if diceware {
                rbw::pwgen::Type::Diceware
            } else {
                rbw::pwgen::Type::AllChars
            };
            commands::generate(
                name.as_deref(),
                user.as_deref(),
                &uri.iter()
                    // XXX not sure what the ui for specifying the match type
                    // should be
                    .map(|uri| (uri.clone(), None))
                    .collect::<Vec<_>>(),
                folder.as_deref(),
                len,
                ty,
            )
        }
        Opt::Edit {
            find_args,
            rename,
            move_to,
            set_uri,
            add_uri,
            remove_field,
            favorite,
            values,
        } => {
            let mut changes = values.changes();
            changes.name = rename;
            changes.folder = move_to;
            changes.uris = if set_uri.is_empty() {
                None
            } else {
                Some(set_uri)
            };
            changes.add_uris = add_uri;
            changes.remove_fields = remove_field;
            changes.favorite = favorite;
            items::edit(
                find_args.needle,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.ignorecase,
                &changes,
            )
        }
        Opt::Remove {
            find_args,
            permanent,
        } => items::remove(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
            permanent,
        ),
        Opt::Archive { find_args } => items::archive(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
            true,
        ),
        Opt::Unarchive { find_args } => items::archive(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
            false,
        ),
        Opt::Trash { raw } => items::trash(raw),
        Opt::Restore { needle } => items::restore(&needle),
        Opt::Folder { folder } => match folder {
            FolderCommand::List { raw } => items::folder_list(raw),
            FolderCommand::Add { name } => items::folder_add(&name),
            FolderCommand::Rename { name, new_name } => {
                items::folder_rename(&name, &new_name)
            }
            FolderCommand::Remove { name } => items::folder_remove(&name),
        },
        Opt::Attachment { attachment } => match attachment {
            AttachmentCommand::List { find_args, raw } => {
                items::attachment_list(
                    find_args.needle,
                    find_args.user.as_deref(),
                    find_args.folder.as_deref(),
                    find_args.ignorecase,
                    raw,
                )
            }
            AttachmentCommand::Get {
                find_args,
                name,
                output,
                force,
            } => items::attachment_get(
                find_args.needle,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.ignorecase,
                name.as_deref(),
                output.as_deref(),
                force,
            ),
            AttachmentCommand::Add {
                find_args,
                file,
                name,
            } => items::attachment_add(
                find_args.needle,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.ignorecase,
                &file,
                name.as_deref(),
            ),
            AttachmentCommand::Remove { find_args, name } => {
                items::attachment_remove(
                    find_args.needle,
                    find_args.user.as_deref(),
                    find_args.folder.as_deref(),
                    find_args.ignorecase,
                    name.as_deref(),
                )
            }
        },
        Opt::History { find_args } => commands::history(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
        ),
        Opt::Lock { hard } => commands::lock(hard),
        Opt::Purge => commands::purge(),
        Opt::StopAgent => commands::stop_agent(),
        Opt::GenCompletions { shell } => {
            match shell {
                CompletionShell::Bash => {
                    clap_complete::generate(
                        clap_complete::Shell::Bash,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.bash"));
                }
                CompletionShell::Fish => {
                    clap_complete::generate(
                        clap_complete::Shell::Fish,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.fish"));
                }
                CompletionShell::Zsh => {
                    clap_complete::generate(
                        clap_complete::Shell::Zsh,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.zsh"));
                }
                CompletionShell::Powershell => {
                    clap_complete::generate(
                        clap_complete::Shell::PowerShell,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Elvish => {
                    clap_complete::generate(
                        clap_complete::Shell::Elvish,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Nushell => {
                    clap_complete::generate(
                        clap_complete_nushell::Nushell,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Fig => {
                    clap_complete::generate(
                        clap_complete_fig::Fig,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
            }
            Ok(())
        }
    }
    .with_context(|| format!("rbw {subcommand_name}"));

    if let Err(e) = res {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
