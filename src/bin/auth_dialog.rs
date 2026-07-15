// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Pegasus Heavy Industries LLC

//! GNOME auth-dialog helper for nm-openvpn-sso.
//!
//! Invoked directly by GNOME Shell's built-in NetworkManager secret-agent
//! (no nm-applet required) when a `requires-password` connection's
//! `NeedSecrets` D-Bus call requested the "vpn" setting. Implements
//! NetworkManager's standard VPN auth-dialog protocol: argv flags, a
//! DATA_KEY/DATA_VAL/SECRET_KEY/SECRET_VAL/DONE stdin format, and a
//! `key\nvalue\n`-pairs-then-blank-line stdout format.

use std::collections::HashMap;
use std::io::{BufRead, Write};

use clap::Parser;
use gtk4::{Box as GtkBox, Button, Orientation};
use libadwaita as adw;
use libadwaita::prelude::*;

#[derive(Parser, Debug)]
#[command(name = "nm-openvpn-sso-auth-dialog")]
struct Args {
    /// Reprompt for passwords (previous attempt failed)
    #[arg(short = 'r', long)]
    reprompt: bool,
    /// UUID of the VPN connection
    #[arg(short = 'u', long)]
    uuid: String,
    /// Display name of the VPN connection
    #[arg(short = 'n', long)]
    name: String,
    /// VPN service type
    #[arg(short = 's', long)]
    service: String,
    /// Allow interaction with the user
    #[arg(short = 'i', long)]
    allow_interaction: bool,
    /// Hints from the VPN plugin (repeatable, unused in this dialog)
    #[arg(short = 't', long = "hint")]
    hint: Vec<String>,
    /// External UI mode (not implemented — we always reject it)
    #[arg(long = "external-ui-mode")]
    external_ui_mode: bool,
}

#[derive(Debug, Default, PartialEq)]
struct StdinContext {
    data: HashMap<String, String>,
    secrets: HashMap<String, String>,
}

/// Parses NetworkManager's auth-dialog stdin format: alternating
/// `DATA_KEY=`/`DATA_VAL=` and `SECRET_KEY=`/`SECRET_VAL=` lines, terminated
/// by a `DONE` line (or EOF, which is treated the same as DONE).
fn parse_stdin_protocol<R: BufRead>(reader: R) -> StdinContext {
    let mut ctx = StdinContext::default();
    let mut pending: Option<(bool, String)> = None;

    for line in reader.lines().map_while(Result::ok) {
        if line == "DONE" {
            break;
        }
        if let Some(v) = line.strip_prefix("DATA_KEY=") {
            pending = Some((false, v.to_string()));
        } else if let Some(v) = line.strip_prefix("DATA_VAL=") {
            if let Some((false, k)) = pending.take() {
                ctx.data.insert(k, v.to_string());
            }
        } else if let Some(v) = line.strip_prefix("SECRET_KEY=") {
            pending = Some((true, v.to_string()));
        } else if let Some(v) = line.strip_prefix("SECRET_VAL=") {
            if let Some((true, k)) = pending.take() {
                ctx.secrets.insert(k, v.to_string());
            }
        }
    }

    ctx
}

/// Formats the collected secrets per NetworkManager's expected stdout
/// format: alternating `key\nvalue\n` lines, then a blank-line terminator.
fn format_secrets_output(username: &str, password: &str) -> String {
    format!("username\n{}\npassword\n{}\n\n", username, password)
}

fn main() {
    let args = Args::parse();

    // We only implement the simple stdin/stdout protocol; NM's external-ui
    // mode uses a different GKeyFile-based exchange we don't speak.
    if args.external_ui_mode {
        eprintln!("nm-openvpn-sso-auth-dialog: --external-ui-mode is not supported");
        std::process::exit(1);
    }

    let stdin_ctx = parse_stdin_protocol(std::io::stdin().lock());
    let known_username = stdin_ctx
        .secrets
        .get("username")
        .cloned()
        .or_else(|| stdin_ctx.data.get("username").cloned());

    let app = adw::Application::builder()
        .application_id("org.freedesktop.NetworkManager.openvpn-sso.AuthDialog")
        .flags(gtk4::gio::ApplicationFlags::NON_UNIQUE)
        .build();

    let connection_name = args.name.clone();
    let reprompt = args.reprompt;

    app.connect_activate(move |app| {
        build_window(app, &connection_name, reprompt, known_username.clone());
    });

    let exit_code = app.run_with_args::<&str>(&[]);
    std::process::exit(exit_code.get() as i32);
}

fn build_window(
    app: &adw::Application,
    connection_name: &str,
    reprompt: bool,
    known_username: Option<String>,
) {
    let username_row = adw::EntryRow::builder().title("Username").build();
    if let Some(ref u) = known_username {
        username_row.set_text(u);
    }

    let password_row = adw::PasswordEntryRow::builder().title("Password").build();

    let group = adw::PreferencesGroup::builder()
        .title(format!("Log in to {}", connection_name))
        .build();
    group.add(&username_row);
    group.add(&password_row);

    let content = GtkBox::new(Orientation::Vertical, 12);
    content.set_margin_top(12);
    content.set_margin_bottom(12);
    content.set_margin_start(12);
    content.set_margin_end(12);

    if reprompt {
        let banner = adw::Banner::builder()
            .title("Previous login attempt failed. Please try again.")
            .revealed(true)
            .build();
        content.append(&banner);
    }

    content.append(&group);

    let cancel_btn = Button::with_label("Cancel");
    let connect_btn = Button::with_label("Connect");
    connect_btn.add_css_class("suggested-action");

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&connect_btn);

    let toplevel = GtkBox::new(Orientation::Vertical, 0);
    toplevel.append(&header);
    toplevel.append(&content);

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title(format!("Authenticate {}", connection_name))
        .default_width(380)
        .content(&toplevel)
        .build();

    // Closing the window by any means other than "Connect" is a cancel:
    // exit non-zero with no stdout output, per the auth-dialog protocol.
    window.connect_close_request(|_| std::process::exit(1));
    cancel_btn.connect_clicked(|_| std::process::exit(1));

    connect_btn.connect_clicked(move |_| {
        let username = username_row.text();
        let password = password_row.text();
        let mut out = std::io::stdout().lock();
        let _ =
            out.write_all(format_secrets_output(username.as_str(), password.as_str()).as_bytes());
        let _ = out.flush();
        std::process::exit(0);
    });

    window.present();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_well_formed_stdin() {
        let input = "DATA_KEY=foo\nDATA_VAL=bar\nSECRET_KEY=username\nSECRET_VAL=alice\nDONE\n";
        let ctx = parse_stdin_protocol(input.as_bytes());
        assert_eq!(ctx.data.get("foo"), Some(&"bar".to_string()));
        assert_eq!(ctx.secrets.get("username"), Some(&"alice".to_string()));
    }

    #[test]
    fn stops_at_done_marker() {
        let input = "DATA_KEY=foo\nDATA_VAL=bar\nDONE\nDATA_KEY=ignored\nDATA_VAL=ignored\n";
        let ctx = parse_stdin_protocol(input.as_bytes());
        assert_eq!(ctx.data.len(), 1);
    }

    #[test]
    fn handles_missing_done_marker_at_eof() {
        let input = "DATA_KEY=foo\nDATA_VAL=bar\n";
        let ctx = parse_stdin_protocol(input.as_bytes());
        assert_eq!(ctx.data.get("foo"), Some(&"bar".to_string()));
    }

    #[test]
    fn ignores_unmatched_key_without_value() {
        let input = "DATA_KEY=foo\nSECRET_KEY=bar\nDONE\n";
        let ctx = parse_stdin_protocol(input.as_bytes());
        assert!(ctx.data.is_empty());
        assert!(ctx.secrets.is_empty());
    }

    #[test]
    fn handles_empty_input() {
        let ctx = parse_stdin_protocol("".as_bytes());
        assert!(ctx.data.is_empty());
        assert!(ctx.secrets.is_empty());
    }

    #[test]
    fn formats_secrets_output_with_terminator() {
        let out = format_secrets_output("alice", "s3cret");
        assert_eq!(out, "username\nalice\npassword\ns3cret\n\n");
    }

    #[test]
    fn cli_parses_realistic_invocation() {
        let args = Args::try_parse_from([
            "nm-openvpn-sso-auth-dialog",
            "-r",
            "-u",
            "1234-uuid",
            "-n",
            "My VPN",
            "-s",
            "org.freedesktop.NetworkManager.openvpn-sso",
            "-i",
            "-t",
            "hint-one",
            "-t",
            "hint-two",
        ])
        .unwrap();
        assert!(args.reprompt);
        assert_eq!(args.uuid, "1234-uuid");
        assert_eq!(args.name, "My VPN");
        assert_eq!(args.service, "org.freedesktop.NetworkManager.openvpn-sso");
        assert!(args.allow_interaction);
        assert_eq!(
            args.hint,
            vec!["hint-one".to_string(), "hint-two".to_string()]
        );
        assert!(!args.external_ui_mode);
    }

    #[test]
    fn cli_detects_external_ui_mode() {
        let args = Args::try_parse_from([
            "nm-openvpn-sso-auth-dialog",
            "-u",
            "uuid",
            "-n",
            "name",
            "-s",
            "service",
            "--external-ui-mode",
        ])
        .unwrap();
        assert!(args.external_ui_mode);
    }

    #[test]
    fn cli_requires_uuid_name_service() {
        let result = Args::try_parse_from(["nm-openvpn-sso-auth-dialog"]);
        assert!(result.is_err());
    }
}
