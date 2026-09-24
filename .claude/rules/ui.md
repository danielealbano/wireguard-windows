# Desktop UI Rules — ABSOLUTE RULES

These rules govern **native desktop user interfaces** (any toolkit, any language) in ANY project where
this file is present. They are **VERY STRICT and ABSOLUTELY NON-NEGOTIABLE**. They are AGNOSTIC:
project-specific details (the toolkit, the UI process model, the localization pipeline, the list of
UI surfaces that render configuration) live in `project.md` and the canonical docs it references.
Language specifics live in the language rule file (e.g. `go.md`); platform specifics in the platform
rule file (e.g. `windows.md`).

## 1) Architecture & Privilege — ABSOLUTE RULES

- The UI is a CLIENT. It MUST NOT perform privileged operations itself; every state change MUST go
  through the project's documented backend/IPC API, and the UI MUST handle the backend being
  unavailable, slow, or returning errors.
- UI-side validation is for user feedback ONLY — it is NEVER a security control. The privileged
  backend MUST re-validate everything it receives.
- Decision logic (parsing, validation, formatting, state derivation) MUST live in plain,
  toolkit-independent code that can be unit-tested without a display. Widget code MUST stay thin.

## 2) Threading & Responsiveness — ABSOLUTE RULES

- Widgets MUST be created, read, and mutated ONLY on the UI thread. Background work (I/O, IPC, network,
  sleeps) MUST NEVER run on the UI thread; results MUST be marshalled back through the toolkit's
  documented mechanism.
- Timers, pollers, subscriptions, and background workers owned by a view MUST stop when the view is
  closed or hidden as the project documents. No leaked threads/goroutines per view.

## 3) Strings, Localization & Accessibility — ABSOLUTE RULES

- EVERY user-facing string MUST go through the project's localization mechanism, with format
  placeholders instead of string concatenation. Message catalogs MUST be regenerated with the project's
  generator; translations are managed through the project's documented process — you MUST NOT
  hand-edit other languages unless `project.md` says so.
- Keyboard accessibility (tab order, mnemonics/accelerators, default/cancel buttons), accessible names
  for controls, DPI awareness, and system theme/high-contrast support MUST be preserved for every
  surface you add or change.

## 4) Secrets & Sensitive Data — ABSOLUTE RULES

- Secrets (private keys, preshared keys, bearer tokens, passwords, certificate private keys) MUST NOT be
  displayed unless the user explicitly asks AND the project's policy allows it for that viewer; in
  status/detail views they MUST be masked or shown as a presence indicator (e.g. "enabled"). Views for
  less-privileged viewers MUST show redacted data.
- The UI MUST NEVER write secrets to logs, and MUST NEVER place them on the clipboard without an
  explicit user action.
- Destructive actions (delete, overwrite, revoke) MUST ask for confirmation.

## 5) Editors, Validation & Transparency — ABSOLUTE RULES

- Editors MUST give immediate, precise feedback on invalid input (inline highlighting or messages) and
  MUST NOT allow saving invalid content. Error messages MUST be specific and actionable (what is
  wrong, where, how to fix it) and MUST NOT leak secrets.
- The UI MUST NEVER silently drop or alter user content. Any automatic transformation performed on
  save or import (normalization, copying referenced files, rewriting paths) MUST be disclosed to the
  user at the time it happens.
- Round-trip fidelity MUST be preserved per the project's documented serializer behaviour (e.g.
  comments and ordering kept where the serializer keeps them).
- When the configuration surface grows (new keys/fields), EVERY UI surface listed in `project.md` that
  renders, highlights, or validates configuration MUST be updated in the same change.

## 6) Consistency & Dependencies — ABSOLUTE RULES

- You MUST follow the existing toolkit, widgets, layout conventions, and dialog helpers of the project.
  You MUST NOT introduce a new UI framework, toolkit, embedded web view, or UI dependency without the
  user's explicit approval.
- Icons and other UI assets MUST go through the project's asset pipeline.

## 7) Testing & Quality Gates — ABSOLUTE RULES

- Toolkit-independent UI logic (see §1) MUST have automated tests per the language rule file.
- Behaviour that cannot be automated (rendering, dialogs, focus, DPI) MUST be covered by documented
  **Manual QA Steps**, executed on the target platform for every UI change and reported.
- A UI change is DONE only if: it builds with NO new warnings, all new strings are in the regenerated
  catalogs, the manual QA steps were executed on the target platform, accessibility (§3) is preserved,
  and every configuration-rendering surface listed in `project.md` is consistent with the change.
