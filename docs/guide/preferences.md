# Preferences

Click **Colony Firewall** at the top of the app's sidebar to open
Preferences; click it again, press Esc or use **Close** to go back. Every
change applies at once and is saved at once: there is no Save button.

## What you can set

| Category | Section | What it does |
|---|---|---|
| General | Language | English, French, or the system language (`LC_ALL`, then `LC_MESSAGES`, then `LANG`). The window switches at once; the tray follows the next time it starts. `cfc` stays in English. |
| Appearance | Theme, Colors, Typography, Effects, Preview | The shared Colony themes and accents, the text size, and visual effects. Parchment is the default theme. |
| Accessibility | Vision, Motion, Reading | High contrast, the OpenDyslexic font, reduced motion, and a text scale on top of the Typography size. |
| Prompts | When a prompt arrives | **Bring the window forward**: the first prompt of a burst shows the Prompts tab and raises the window. Off, only the sidebar badge counts it. |
| Prompts | Unanswered prompts | Shows what the daemon does with a prompt nobody answers. It is set in `/etc/colony-firewall/daemon.toml`, not here. |
| Notifications | Tray | **Show prompts as notifications**: the tray shows each prompt with Allow and Deny buttons. Off, the tray neither shows them nor subscribes to prompts, so with no app window open the daemon applies its policy at once. |
| About | | The app and daemon versions, whether the daemon accepts changes from this copy of the app, and the paths below. |

With reduced motion on (or effects off), the countdown bar on each prompt is
replaced by the seconds left, in text.

## Where they are saved

One JSON file, written whole through a temporary file and a rename, so a crash
never leaves half of it:

```
$XDG_CONFIG_HOME/Colony/Colony Firewall Control/preferences.json
```

`~/.config` stands in for `$XDG_CONFIG_HOME` when that is unset. The file holds
only these settings. Nothing in it leaves the machine, and the daemon never
reads it.

The tray reads two keys from the same file when it starts, `language` and
`tray_notifications`; quit it from its menu and start it again after changing
either. It never writes the file.

A value that is missing, unknown or of the wrong type falls back to its default
and the rest of the file is kept, so a file from a newer or older version, or
one edited by hand, never stops the app from starting. Deleting the file
resets every preference.

```json
{
  "selected_theme": "parchment",
  "selected_variant": "light",
  "auto_accent": false,
  "font_size": "default",
  "animations": true,
  "high_contrast": false,
  "dyslexia_font": false,
  "reduce_motion": false,
  "text_size_a11y": "default",
  "language": "system",
  "raise_on_prompt": true,
  "tray_notifications": true
}
```

`selected_accent` appears once an accent is picked. The first nine keys are the
ones every Colony program writes.
