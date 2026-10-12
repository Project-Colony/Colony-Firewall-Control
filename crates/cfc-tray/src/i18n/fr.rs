//! French strings. Same keys as `en.rs`, translated rather than glossed, and
//! addressed to the user as « vous ».

pub(super) const STRINGS: &[(&str, &str)] = &[
    // Menu
    ("menu_pause", "Mettre en pause"),
    ("menu_resume_now", "Reprendre maintenant"),
    ("menu_open", "Ouvrir Colony Firewall"),
    ("menu_quit", "Quitter l'icône"),
    ("pause_5_min", "Pendant 5 min"),
    ("pause_30_min", "Pendant 30 min"),
    ("pause_1_h", "Pendant 1 h"),
    ("pause_default", "Durée par défaut du démon"),
    // Status line and tooltip
    ("status_connecting", "Connexion à colony-firewalld…"),
    ("status_unreachable", "Démon injoignable : {hint}"),
    (
        "status_not_enforcing",
        "Filtrage INACTIF : règle nft chargée ?",
    ),
    ("status_paused", "En pause"),
    ("status_paused_for", "En pause : reprise dans {time}"),
    ("status_enforcing", "Filtrage actif"),
    ("status_prompt_waiting", "{count} demande en attente"),
    ("status_prompts_waiting", "{count} demandes en attente"),
    (
        "hint_socket_missing",
        "démon arrêté ? (systemctl status colony-firewalld)",
    ),
    (
        "hint_permission_denied",
        "pas d'accès au socket : rejoignez le groupe colony-firewall",
    ),
    (
        "hint_stale_socket",
        "socket périmé : redémarrez colony-firewalld",
    ),
    (
        "hint_connect_failed",
        "échec de la connexion : colony-firewalld fonctionne-t-il ?",
    ),
    (
        "hint_read_only",
        "lecture seule : redémarrez l'icône, ou utilisez sudo cfc",
    ),
    ("hint_rpc_error", "le démon a répondu par une erreur"),
    // Prompt bubbles
    ("action_allow_once", "Autoriser une fois"),
    ("action_allow_always", "Toujours autoriser"),
    ("action_deny", "Refuser"),
    ("action_block", "Toujours bloquer"),
    ("action_details", "Détails"),
    ("notify_unknown_process", "Un processus inconnu"),
    ("notify_wants_to_connect", "{name} veut se connecter"),
    ("notify_unknown_address", "inconnue"),
    ("notify_verified_hostname", "nom d'hôte vérifié"),
    ("notify_unverified_hostname", "nom d'hôte non vérifié"),
    ("notify_unknown_destination", "une destination inconnue"),
    (
        "notify_allow_covers_all",
        "« Toujours autoriser » couvre toutes les destinations jusqu'à la suppression de la \
         règle.",
    ),
    (
        "notify_pin_to_binary",
        "Autoriser sera lié à ce binaire (chemin modifiable par un utilisateur)",
    ),
    (
        "notify_no_hash",
        "Empreinte du binaire indisponible ; aucune autorisation permanente ne peut être \
         enregistrée",
    ),
    (
        "notify_undecided",
        "Une règle peut s'appliquer, mais le programme n'a pas pu être entièrement identifié ; \
         votre réponse s'applique à cette connexion.",
    ),
    ("notify_verdict_needed", "Colony Firewall : verdict requis"),
    (
        "notify_pending_one",
        "{count} connexion attend un verdict : ouvrez Colony Firewall",
    ),
    (
        "notify_pending_many",
        "{count} connexions attendent un verdict : ouvrez Colony Firewall",
    ),
    ("overflow_title", "Plusieurs connexions sont en attente"),
    (
        "overflow_one",
        "{count} autre connexion en attente. Une fenêtre Colony Firewall ouverte peut y \
         répondre ; sinon, le choix par défaut s'applique à son expiration.",
    ),
    (
        "overflow_many",
        "{count} autres connexions en attente. Une fenêtre Colony Firewall ouverte peut y \
         répondre ; sinon, le choix par défaut s'applique à leur expiration.",
    ),
    // Follow-ups
    (
        "confirm_allow_always",
        "Règle créée : toujours autoriser {name}",
    ),
    (
        "confirm_deny_always",
        "Règle créée : toujours refuser {name}",
    ),
    (
        "rule_not_saved",
        "{name} : la réponse a été appliquée, mais aucune règle durable n'a été enregistrée",
    ),
    (
        "rule_not_saved_why",
        "{name} : la réponse a été appliquée, mais aucune règle durable n'a été enregistrée \
         ({reason})",
    ),
    (
        "fallback_allowed",
        "Autorisé cette fois : aucune règle ne peut être liée à {name}, la question pourra \
         donc revenir",
    ),
    (
        "fallback_denied",
        "Refusé cette fois : aucune règle ne peut être liée à {name}, la question pourra donc \
         revenir",
    ),
    (
        "verdict_refused",
        "Votre réponse n'a pas été acceptée : {reason}",
    ),
    (
        "verdict_too_late",
        "Trop tard : le démon a déjà appliqué son choix par défaut",
    ),
    (
        "pause_denied",
        "Impossible de mettre le pare-feu en pause : {reason}",
    ),
    (
        "pause_failed",
        "Impossible de mettre le pare-feu en pause ({error})",
    ),
    (
        "resume_denied",
        "Impossible de réactiver le pare-feu : {reason}",
    ),
    (
        "resume_failed",
        "Impossible de réactiver le pare-feu ({error})",
    ),
    (
        "replaced_on_disk",
        "Colony Firewall a été mis à jour. Quittez l'icône depuis son menu puis relancez-la, \
         et redémarrez l'application : d'ici là, le pare-feu refuse leurs réponses et leurs \
         modifications.",
    ),
    (
        "cannot_open_gui",
        "Impossible d'ouvrir Colony Firewall : {program} n'est pas installé ou n'est pas dans \
         le PATH",
    ),
];
