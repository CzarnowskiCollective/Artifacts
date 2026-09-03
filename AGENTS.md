# AGENTS.md — Czarnowski Artifact Hub

This repo is a lightweight publishing surface: **one folder = one HTML artifact**,
served automatically by GitHub Pages. No build step, no framework, no branches.

## How publishing works

1. Create a folder at the repo root named for the artifact, **kebab-case**:
   `venue-mockup-v2/`, `q3-recap/`, `pitch-deck-html/`.
2. Put a complete, self-contained `index.html` inside it. Extra assets (css/js/images)
   go in the same folder; reference them with **relative paths** (`./style.css`, not `/style.css`).
3. Commit to `main`. The artifact is live in about 30–60 seconds at:

   `https://czarnowskicollective.github.io/artifacts/<folder-name>/`

## Rules for agents

- **Update the README index in the same commit.** The `## Artifacts` table in
  `README.md` must list every artifact folder with its live link. Add your row when
  you publish; remove it if you delete an artifact. The README is the directory —
  a stale index is a bug.
- **Never touch another artifact's folder** unless explicitly asked. Each folder is
  an independent deliverable.
- **Do not delete `.nojekyll`** (it makes Pages serve raw files without Jekyll processing).
- **This site is public.** No credentials, no client-confidential pricing or internal
  documents, nothing you wouldn't put on the open internet. When in doubt, ask before
  publishing.
- Keep artifacts self-contained: no CDN-hosted secrets, no APIs with embedded keys.
  Plain HTML/CSS/JS that works offline is the gold standard.
- Root files (`index.html`, `README.md`, `AGENTS.md`, `CLAUDE.md`, `.nojekyll`) are
  shared infrastructure — edit only to maintain the index or when asked.

## Quick reference

| Thing | Value |
|---|---|
| Hub root | https://czarnowskicollective.github.io/artifacts/ |
| Artifact URL pattern | `https://czarnowskicollective.github.io/artifacts/<folder>/` |
| Deploy trigger | any push to `main` |
| Deploy time | ~30–60 s (check with a hard refresh) |

## Password-gated artifacts

`rfp-assessment-calculator/` is locked: the real page is stored as an AES-256-GCM
ciphertext and the gate derives the key from the password with PBKDF2. Two rules
follow from that.

**Don't hand-edit a locked page.** Editing `index.html` directly will either
break the gate or silently drop your change (the visible file is the wrapper, not
the content). To change locked content, decrypt it, edit the plaintext, and
re-encrypt with `tools/rotate_gate_password.py`.

**The password rotates itself.** `.github/workflows/rotate-gate-password.yml`
runs each weekday and rotates the gate password every 10 US business days,
committing the re-encrypted page. Passwords are never stored: each one is derived
from the `GATE_MASTER_KEY` Actions secret plus the rotation index recorded in
`.gate-rotation/<artifact>.json`, which is public state and holds no secret. Leave
that file to the workflow.

| Thing | Value |
|---|---|
| Rotation engine | `tools/rotate_gate_password.py` |
| Rotation state | `.gate-rotation/rfp-assessment-calculator.json` |
| Interval | 10 US business days (federal holidays excluded) |
| Secret | `GATE_MASTER_KEY` (repo Actions secret, never rotated) |
| Manual run | Actions → *Rotate Artifact Gate Password* → Run workflow |
