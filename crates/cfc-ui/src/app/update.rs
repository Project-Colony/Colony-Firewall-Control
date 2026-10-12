//! How the application reacts to a message or a key press.

use cfc_client::proto;
use iced::{keyboard, Task};
use tracing::info;

use super::{
    delete_rule, fetch_rules, fetch_status, now_ms, prompt_attention, raise_window, set_paused,
    submit_verdict, upsert_rule, App, Attention, DaemonState, KeyPress, Message, PromptCard, Tab,
    DELETE_CONFIRM_MS, LIVE_CAP, RULES_REFRESH_EVERY_TICKS, STATUS_FAILURES_BEFORE_DEAD,
};
use crate::editor::{build_rule_from_editor, toggled_rule, RuleEditor};
use crate::format;
use crate::views::{self, prompts::PromptAction};

impl App {
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::TabSelected(t) => {
                self.tab = t;
                Task::none()
            }
            Message::Reconnect => {
                self.retry_attempts = 0;
                self.connect_task()
            }
            Message::HandshakeDone(Ok(data)) => {
                self.now_ms = now_ms();
                self.pause_shown_at_ms = self.now_ms;
                self.daemon = DaemonState::Connected;
                self.status = Some(data.status);
                self.rules = data.rules;
                self.status_failures = 0;
                self.retry_attempts = 0;
                self.retry_at_ms = None;
                self.stream_trouble = false;
                self.log.prune(self.now_ms);
                info!("connected to daemon");
                Task::none()
            }
            Message::HandshakeDone(Err(e)) => {
                self.mark_failed(e);
                Task::none()
            }
            Message::RulesLoaded(Ok(rules)) => {
                self.rules = rules;
                Task::none()
            }
            Message::RulesLoaded(Err(e)) => {
                self.log
                    .warn(format!("listing rules failed: {e}"), self.now_ms);
                Task::none()
            }
            Message::DeleteRule(id) => {
                // Two-step: the first click arms, the second (within
                // DELETE_CONFIRM_MS) actually deletes.
                let armed = self.pending_delete.as_ref().is_some_and(|(pending, at)| {
                    *pending == id && self.now_ms.saturating_sub(*at) <= DELETE_CONFIRM_MS
                });
                if !armed {
                    self.pending_delete = Some((id, self.now_ms));
                    return Task::none();
                }
                self.pending_delete = None;
                let socket = self.socket_path.clone();
                Task::perform(delete_rule(socket, id), Message::RuleDeleted)
            }
            Message::RuleDeleted(Ok((id, true))) => {
                self.rules.retain(|r| r.id != id);
                self.log.info("rule deleted", self.now_ms);
                Task::none()
            }
            Message::RuleDeleted(Ok((_, false))) => {
                self.log
                    .warn("rule was already gone on the daemon", self.now_ms);
                Task::none()
            }
            Message::RuleDeleted(Err(e)) => {
                self.log.error(format!("delete failed: {e}"), self.now_ms);
                Task::none()
            }
            Message::StatusLoaded(Ok(s)) => {
                // A timed pause ran out, or another client resumed.
                if self.status.as_ref().is_some_and(|old| old.paused) && !s.paused {
                    self.pause_shown_at_ms = self.now_ms;
                }
                self.status = Some(s);
                self.status_failures = 0;
                self.stream_trouble = false;
                Task::none()
            }
            Message::StatusLoaded(Err(e)) => {
                // A single miss is a hiccup; two in a row means the daemon
                // is gone and the "connected" badge would be a lie.
                self.status_failures = self.status_failures.saturating_add(1);
                if self.status_failures >= STATUS_FAILURES_BEFORE_DEAD {
                    self.mark_failed(e);
                }
                Task::none()
            }
            Message::StatusTick => {
                self.now_ms = now_ms();
                self.housekeeping();
                if !self.connected() {
                    return Task::none();
                }
                self.status_ticks = self.status_ticks.wrapping_add(1);
                let mut tasks = vec![Task::perform(
                    fetch_status(self.socket_path.clone()),
                    Message::StatusLoaded,
                )];
                if self.status_ticks.is_multiple_of(RULES_REFRESH_EVERY_TICKS) {
                    tasks.push(Task::perform(
                        fetch_rules(self.socket_path.clone()),
                        Message::RulesLoaded,
                    ));
                }
                Task::batch(tasks)
            }
            Message::DeadlineTick => {
                self.now_ms = now_ms();
                self.housekeeping();
                Task::none()
            }
            Message::RetryTick => {
                self.now_ms = now_ms();
                self.housekeeping();
                match self.retry_at_ms {
                    Some(at) if self.now_ms >= at => self.connect_task(),
                    _ => Task::none(),
                }
            }
            Message::StreamConnected => {
                self.stream_trouble = false;
                Task::none()
            }
            Message::LiveEvent(ev) => {
                self.stream_trouble = false;
                self.session.record(&ev);
                self.live.push_front(ev);
                while self.live.len() > LIVE_CAP {
                    self.live.pop_back();
                }
                if self.live_frozen.is_some() {
                    self.live_new = self.live_new.saturating_add(1);
                }
                Task::none()
            }
            Message::LiveStreamEnded(e) => {
                // cfc-client reconnects on its own with a capped backoff;
                // surface it once as connection state, not as footer spam.
                self.stream_trouble = true;
                info!("live stream interrupted: {e}");
                Task::none()
            }
            Message::PromptEvent(ev) => {
                // No desktop notification here: the tray owns prompt
                // notifications now - two bubbles per prompt would train
                // users to ignore them. The GUI shows its card either way.
                self.stream_trouble = false;
                // The arming deadline is measured from now, not from the
                // last tick, which can be two seconds old.
                self.now_ms = now_ms();
                // A prompt is a held-open connection with a deadline on it;
                // a card the user only sees if they happen to be looking at
                // the right tab is not an ask, it is a countdown they lose.
                let attention = prompt_attention(self.prompts.len(), self.editor.is_some());
                self.prompts.push(PromptCard::new(ev, self.now_ms));
                self.sync_key_target();
                match attention {
                    Attention::None => Task::none(),
                    Attention::TabAndRaise => {
                        self.tab = Tab::Prompts;
                        raise_window()
                    }
                }
            }
            Message::PromptStreamEnded(e) => {
                self.stream_trouble = true;
                self.prompts.clear();
                self.detach_orphaned_editor();
                info!("prompt stream interrupted: {e}");
                Task::none()
            }
            Message::CustomizePromptRule(prompt_id) => {
                let Some(card) = self.prompts.iter().find(|p| p.event.prompt_id == prompt_id)
                else {
                    return Task::none();
                };
                self.editor = Some(RuleEditor::from_prompt(&card.event));
                self.tab = Tab::Rules;
                Task::none()
            }
            Message::SubmitVerdict {
                prompt_id,
                action,
                scope,
                duration,
            } => {
                // One verdict per card at a time. The card stays, disabled,
                // until the daemon confirms (see `settle_card`).
                let Some(card) = self
                    .prompts
                    .iter_mut()
                    .find(|p| p.event.prompt_id == prompt_id && !p.submitting)
                else {
                    return Task::none();
                };
                card.submitting = true;
                self.sync_key_target();
                let socket = self.socket_path.clone();
                Task::perform(
                    submit_verdict(socket, prompt_id, action, scope, duration, false),
                    Message::VerdictSubmitted,
                )
            }
            Message::VerdictSubmitted(Ok((prompt_id, true, note))) => {
                self.settle_card(&prompt_id, true);
                // The daemon telling the user something true about the rule
                // it stored - today, that a user-writable binary was
                // hash-bound and a swapped file will prompt again. Shown in
                // the log line the verdict already earns; silence would
                // leave "always" quietly meaning less than it reads.
                if let Some(note) = note {
                    self.log.info(note, self.now_ms);
                }
                // A verdict may have persisted a rule; refresh so the Rules
                // tab shows it now rather than after some unrelated action.
                let socket = self.socket_path.clone();
                Task::perform(fetch_rules(socket), Message::RulesLoaded)
            }
            Message::VerdictSubmitted(Ok((prompt_id, false, _))) => {
                self.settle_card(&prompt_id, true);
                // The daemon had already answered this prompt itself. The
                // old code swallowed this, so the user believed they had
                // allowed something the timeout had actually decided.
                self.log.error(
                    "prompt already expired - the daemon answered it",
                    self.now_ms,
                );
                Task::none()
            }
            Message::VerdictSubmitted(Err(failure)) => {
                self.settle_card(&failure.prompt_id, failure.applied);
                let still = if failure.applied {
                    ""
                } else {
                    " - the prompt is still waiting for an answer"
                };
                self.log.error(
                    format!("verdict failed: {}{still}", failure.message),
                    self.now_ms,
                );
                Task::none()
            }
            Message::OpenEditor => {
                self.editor = Some(RuleEditor::default());
                Task::none()
            }
            Message::EditExistingRule(id) => {
                if let Some(rule) = self.rules.iter().find(|r| r.id == id) {
                    self.editor = Some(RuleEditor::from_existing(rule));
                }
                Task::none()
            }
            Message::CloseEditor => {
                self.editor = None;
                Task::none()
            }
            Message::ToggleRuleEnabled(id) => {
                let Some(rule) = self.rules.iter_mut().find(|r| r.id == id) else {
                    return Task::none();
                };
                let updated = toggled_rule(rule);
                // Optimistic: the row flips now, the next RulesLoaded (or
                // the RuleSaved error path) re-reads the daemon's truth.
                rule.enabled = updated.enabled;
                let socket = self.socket_path.clone();
                Task::perform(upsert_rule(socket, updated), Message::RuleSaved)
            }
            Message::RulesFilterChanged(s) => {
                self.rules_filter = s;
                Task::none()
            }
            Message::RulesSortBy(sort) => {
                self.rules_sort = sort;
                Task::none()
            }
            Message::LiveFilterChanged(s) => {
                self.live_filter = s;
                Task::none()
            }
            Message::LiveVerdictFilter(v) => {
                self.live_verdict = v;
                Task::none()
            }
            Message::ToggleLivePause => {
                if self.live_frozen.is_some() {
                    self.live_frozen = None;
                    self.live_new = 0;
                } else {
                    self.live_frozen = Some(self.live.iter().cloned().collect());
                    self.live_new = 0;
                }
                Task::none()
            }
            Message::MakeRuleFromEvent {
                exe,
                src_ip,
                dst_ip,
                dst_port,
                protocol,
                direction,
            } => {
                self.editor = Some(RuleEditor::from_observed(
                    &exe, &src_ip, &dst_ip, dst_port, protocol, direction,
                ));
                self.tab = Tab::Rules;
                Task::none()
            }
            Message::CopyText(s) => iced::clipboard::write(s),
            Message::DismissLogEntry(i) => {
                self.log.dismiss(i);
                Task::none()
            }
            Message::DismissAllLog => {
                self.log.clear();
                Task::none()
            }
            Message::Key(kp) => {
                self.now_ms = now_ms();
                self.handle_key(kp)
            }
            Message::TogglePaused => {
                let current = self.status.as_ref().map(|s| s.paused).unwrap_or(false);
                if self.pause_pending || (!current && !self.pause_armed()) {
                    return Task::none();
                }
                self.pause_pending = true;
                self.log
                    .info("Waiting for administrator authorization...", self.now_ms);
                let socket = self.socket_path.clone();
                Task::perform(set_paused(socket, !current), Message::PausedSet)
            }
            Message::PausedSet(Ok((paused, resume_at_unix_ms))) => {
                self.pause_pending = false;
                if !paused {
                    self.now_ms = now_ms();
                    self.pause_shown_at_ms = self.now_ms;
                }
                if let Some(s) = &mut self.status {
                    s.paused = paused;
                    s.resume_at_unix_ms = resume_at_unix_ms;
                }
                if paused {
                    self.log.warn(
                        format!(
                            "enforcement paused - {}",
                            format::format_resume_in(resume_at_unix_ms, self.now_ms)
                        ),
                        self.now_ms,
                    );
                } else {
                    self.log.info("enforcement resumed", self.now_ms);
                }
                Task::none()
            }
            Message::PausedSet(Err(e)) => {
                self.pause_pending = false;
                self.log.error(format!("pause failed: {e}"), self.now_ms);
                Task::none()
            }
            Message::EditorName(s) => {
                if let Some(ed) = &mut self.editor {
                    ed.name = s;
                }
                Task::none()
            }
            Message::EditorAction(a) => {
                if let Some(ed) = &mut self.editor {
                    ed.action = a;
                }
                Task::none()
            }
            Message::EditorDuration(d) => {
                if let Some(ed) = &mut self.editor {
                    ed.duration = d;
                    if d != proto::Duration::Seconds {
                        ed.duration_seconds = 0;
                    }
                }
                Task::none()
            }
            Message::EditorExe(s) => {
                if let Some(ed) = &mut self.editor {
                    ed.exe = s;
                }
                Task::none()
            }
            Message::EditorDstHost(s) => {
                if let Some(ed) = &mut self.editor {
                    ed.dst_host = s;
                }
                Task::none()
            }
            Message::EditorDstNet(s) => {
                if let Some(ed) = &mut self.editor {
                    ed.dst_net = s;
                }
                Task::none()
            }
            Message::EditorDstPort(s) => {
                if let Some(ed) = &mut self.editor {
                    ed.dst_port = s;
                }
                Task::none()
            }
            Message::EditorProtocol(p) => {
                if let Some(ed) = &mut self.editor {
                    ed.protocol = p;
                }
                Task::none()
            }
            Message::SaveRule => {
                // The prompt may have expired since the last tick.
                self.detach_orphaned_editor();
                let Some(editor) = &mut self.editor else {
                    return Task::none();
                };
                match build_rule_from_editor(editor) {
                    Ok(rule) => {
                        editor.validation = None;
                        let socket = self.socket_path.clone();
                        if let Some(prompt_id) = editor.prompt_id.clone() {
                            let action = editor.action;
                            let duration = editor.duration;
                            let scope = rule.scope;
                            // Held, not dropped, until the daemon answers:
                            // a dropped card closed this editor on the next
                            // tick and took a failed save's banner with it.
                            let Some(card) = self
                                .prompts
                                .iter_mut()
                                .find(|c| c.event.prompt_id == prompt_id && !c.submitting)
                            else {
                                return Task::none();
                            };
                            card.submitting = true;
                            self.sync_key_target();
                            Task::perform(
                                submit_verdict(socket, prompt_id, action, scope, duration, true),
                                Message::PromptRuleSaved,
                            )
                        } else {
                            Task::perform(upsert_rule(socket, rule), Message::RuleSaved)
                        }
                    }
                    Err(e) => {
                        // Also in the footer: the banner sits at the bottom
                        // of the form and can be below the fold, which made
                        // Save look like it did nothing.
                        self.log
                            .error(format!("saving rule failed: {e}"), self.now_ms);
                        editor.validation = Some(e);
                        Task::none()
                    }
                }
            }
            Message::PromptRuleSaved(Ok((id, true, note))) => {
                self.editor = None;
                self.update(Message::VerdictSubmitted(Ok((id, true, note))))
            }
            Message::PromptRuleSaved(Ok((id, false, _))) => {
                self.editor = None;
                self.update(Message::VerdictSubmitted(Ok((id, false, None))))
            }
            Message::PromptRuleSaved(Err(failure)) => {
                // The editor stays open with the error. If the answer was
                // applied the card is gone, and the editor then turns into a
                // plain new rule the user can save again.
                self.settle_card(&failure.prompt_id, failure.applied);
                self.detach_orphaned_editor();
                self.update(Message::RuleSaved(Err(failure.message)))
            }
            Message::RuleSaved(Ok(line)) => {
                // Say what was stored: closing the editor in silence read
                // as accepted whatever scope the rule ended up with.
                self.log.info(line, self.now_ms);
                self.editor = None;
                let socket = self.socket_path.clone();
                Task::perform(fetch_rules(socket), Message::RulesLoaded)
            }
            Message::RuleSaved(Err(e)) => {
                if let Some(ed) = &mut self.editor {
                    ed.validation = Some(e.clone());
                }
                self.log
                    .error(format!("saving rule failed: {e}"), self.now_ms);
                // The optimistic enable/disable toggle may now disagree
                // with the daemon; re-read the truth.
                let socket = self.socket_path.clone();
                Task::perform(fetch_rules(socket), Message::RulesLoaded)
            }
        }
    }

    /// Keyboard shortcuts. The subscription only delivers key presses no
    /// widget consumed, so a focused text input still swallows its own
    /// typing.
    pub(super) fn handle_key(&mut self, kp: KeyPress) -> Task<Message> {
        use keyboard::key::Named;

        // While the editor is open only Esc/Enter apply - everything else
        // would fire under the user's fingers mid-form.
        if self.editor.is_some() {
            return match kp.key {
                keyboard::Key::Named(Named::Escape) => self.update(Message::CloseEditor),
                keyboard::Key::Named(Named::Enter) => self.update(Message::SaveRule),
                _ => Task::none(),
            };
        }

        match kp.key {
            keyboard::Key::Named(Named::Escape) => {
                // Nothing to close: clear whatever is nagging in the footer.
                self.pending_delete = None;
                self.log.clear();
                Task::none()
            }
            keyboard::Key::Character(ref c) => {
                // Only bare keys and Shift are ours. Ctrl+A is "select all"
                // out of habit, and Alt and Super chords belong to the
                // desktop; none of them may answer a prompt.
                if kp.modifiers.control() || kp.modifiers.alt() || kp.modifiers.logo() {
                    return Task::none();
                }
                let shift = kp.modifiers.shift();
                let on_prompts = self.tab == Tab::Prompts;
                match c.to_lowercase().as_str() {
                    // The verdict keys only work where the card they answer
                    // is on screen.
                    "a" if on_prompts => self.answer_key_target(if shift {
                        PromptAction::AllowProgram
                    } else {
                        PromptAction::AllowOnce
                    }),
                    "d" if on_prompts => self.answer_key_target(if shift {
                        PromptAction::BlockProgram
                    } else {
                        PromptAction::BlockOnce
                    }),
                    "1" => self.update(Message::TabSelected(Tab::Prompts)),
                    "2" => self.update(Message::TabSelected(Tab::Rules)),
                    "3" => self.update(Message::TabSelected(Tab::Live)),
                    "4" => self.update(Message::TabSelected(Tab::Stats)),
                    _ => Task::none(),
                }
            }
            _ => Task::none(),
        }
    }

    /// Answers the top card, the one marked as the keyboard target, with
    /// the same verdict the matching button would submit. Does nothing while
    /// the target is disarmed (see [`App::sync_key_target`]).
    ///
    /// It used to answer the newest prompt, which is the bottom card and
    /// often below the fold: the user read the card at the top, pressed
    /// Shift+A, and wrote an always-allow rule for a program they never saw.
    ///
    /// A program-scoped choice on a flow with no executable path has no
    /// honest verdict (see `verdict_for`), so it degrades to the one-off
    /// answer of the same action rather than doing nothing: the user
    /// pressed Shift+D to stop a connection, and stopping it is the part
    /// that matters.
    fn answer_key_target(&mut self, choice: PromptAction) -> Task<Message> {
        self.sync_key_target();
        if !self
            .key_target
            .as_ref()
            .is_some_and(|(_, armed_at)| self.now_ms >= *armed_at)
        {
            return Task::none();
        }
        let Some(card) = self.key_target_card() else {
            return Task::none();
        };
        let ev = &card.event;
        let fallback = match choice {
            PromptAction::AllowProgram | PromptAction::AllowOnce => PromptAction::AllowOnce,
            PromptAction::BlockProgram | PromptAction::BlockOnce => PromptAction::BlockOnce,
        };
        let Some(verdict) = views::prompts::verdict_for(choice, ev)
            .or_else(|| views::prompts::verdict_for(fallback, ev))
        else {
            return Task::none();
        };
        let prompt_id = ev.prompt_id.clone();
        self.update(Message::SubmitVerdict {
            prompt_id,
            action: verdict.action,
            scope: verdict.scope,
            duration: verdict.duration,
        })
    }
}
