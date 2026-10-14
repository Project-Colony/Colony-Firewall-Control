//! English strings, the canonical ones. A new string starts here, then gets
//! its French twin in `fr.rs` under the same key.

pub(super) const STRINGS: &[(&str, &str)] = &[
    // Menu
    ("menu_pause", "Pause"),
    ("menu_resume_now", "Resume now"),
    ("menu_open", "Open Colony Firewall"),
    ("menu_quit", "Quit tray"),
    ("pause_5_min", "For 5 min"),
    ("pause_30_min", "For 30 min"),
    ("pause_1_h", "For 1 h"),
    ("pause_default", "Daemon default"),
    // Status line and tooltip
    ("status_connecting", "Connecting to colony-firewalld…"),
    ("status_unreachable", "Daemon unreachable: {hint}"),
    ("status_not_enforcing", "NOT enforcing - nft rule loaded?"),
    ("status_paused", "Paused"),
    ("status_paused_for", "Paused - resumes in {time}"),
    ("status_enforcing", "Enforcing"),
    ("status_prompt_waiting", "{count} prompt waiting"),
    ("status_prompts_waiting", "{count} prompts waiting"),
    (
        "hint_socket_missing",
        "daemon not running? (systemctl status colony-firewalld)",
    ),
    (
        "hint_permission_denied",
        "no socket access - join the colony-firewall group",
    ),
    (
        "hint_stale_socket",
        "stale socket - restart colony-firewalld",
    ),
    (
        "hint_connect_failed",
        "connection failed - is colony-firewalld healthy?",
    ),
    (
        "hint_read_only",
        "read-only - restart the tray, or use sudo cfc",
    ),
    ("hint_rpc_error", "daemon answered with an error"),
    // Prompt bubbles
    ("action_allow_once", "Allow once"),
    ("action_allow_always", "Always allow app"),
    ("action_deny", "Deny"),
    ("action_block", "Block app"),
    ("action_details", "Details"),
    ("notify_unknown_process", "An unknown process"),
    ("notify_wants_to_connect", "{name} wants to connect"),
    ("notify_unknown_address", "unknown"),
    ("notify_verified_hostname", "verified hostname"),
    ("notify_unverified_hostname", "unverified hostname"),
    ("notify_unknown_destination", "an unknown destination"),
    (
        "notify_allow_covers_all",
        "Always allow app covers all destinations until the rule is removed.",
    ),
    (
        "notify_pin_to_binary",
        "Allow will pin to this binary (user-writable path)",
    ),
    (
        "notify_no_hash",
        "Image hash unavailable; persistent allow cannot be saved",
    ),
    (
        "notify_undecided",
        "A rule may apply, but the program could not be fully identified; your answer \
         applies to this connection.",
    ),
    ("notify_verdict_needed", "Colony Firewall: verdict needed"),
    (
        "notify_pending_one",
        "{count} connection waiting for a verdict - open Colony Firewall",
    ),
    (
        "notify_pending_many",
        "{count} connections waiting for a verdict - open Colony Firewall",
    ),
    ("overflow_title", "Several connections are waiting"),
    (
        "overflow_one",
        "{count} more connection waiting. An open Colony Firewall window can answer it; \
         otherwise the default applies when it times out.",
    ),
    (
        "overflow_many",
        "{count} more connections waiting. An open Colony Firewall window can answer them; \
         otherwise the default applies when they time out.",
    ),
    // Follow-ups
    ("confirm_allow_always", "Rule created: allow {name} always"),
    ("confirm_deny_always", "Rule created: deny {name} always"),
    (
        "rule_not_saved",
        "{name}: the answer applied, but no lasting rule was saved",
    ),
    (
        "rule_not_saved_why",
        "{name}: the answer applied, but no lasting rule was saved ({reason})",
    ),
    (
        "fallback_allowed",
        "Allowed this time - no rule can be pinned to {name}, so you may be asked again",
    ),
    (
        "fallback_denied",
        "Denied this time - no rule can be pinned to {name}, so you may be asked again",
    ),
    ("verdict_refused", "Your answer was not accepted: {reason}"),
    (
        "verdict_too_late",
        "Too late - the daemon already applied its default",
    ),
    ("pause_denied", "Could not pause the firewall: {reason}"),
    ("pause_failed", "Could not pause the firewall ({error})"),
    ("resume_denied", "Could not resume the firewall: {reason}"),
    ("resume_failed", "Could not resume the firewall ({error})"),
    (
        "replaced_on_disk",
        "Colony Firewall was updated. Quit the tray from its menu and start it again, and \
         restart the app: until then the firewall refuses their answers and changes.",
    ),
    (
        "cannot_open_gui",
        "Cannot open Colony Firewall - {program} is not installed or not on PATH",
    ),
];
