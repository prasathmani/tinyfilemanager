# UI Modernization Mandate (Nemenna pravda)

Status: ACTIVE AND BINDING
Owner: DREMONT TinyFileManager team
Effective date: 2026-06-09

## Purpose

This document is the mandatory source of truth for frontend/UI evolution in this repository.
All future UI work MUST follow this mandate unless this file is explicitly revised by maintainers.

## Binding Rule

Any pull request that changes visual UI, layout, interaction, or frontend styles MUST satisfy this mandate.
If a proposal conflicts with this document, this document wins.

## Core Direction

The historical file/folder UI is functional but visually outdated.
The project direction is a modern Bootstrap-based interface with better clarity, hierarchy, and consistency.

## Non-Negotiable Principles

1. Keep backend behavior stable.
- UI modernization MUST NOT break auth, upload/download, permissions, settings, or file operations.

2. Improve UX without risky rewrites.
- Prefer incremental enhancements over full rewrites.
- Keep existing routes, request formats, and permission checks compatible.

3. Unify visual language.
- Main file manager UI should match the quality and polish level of the AI Assistant area.
- Avoid mixed-era styling patterns in one screen.

4. Accessibility and readability first.
- Improve spacing, contrast, typography, focus states, and control discoverability.
- Desktop and mobile usability are both required.

5. Bootstrap modernization required.
- Use modern Bootstrap 5 utilities/components consistently.
- Remove legacy-looking visual patterns where feasible.

## Approved Implementation Plan

### Phase 1 - Safe Facelift (low risk, mandatory first)

- Modernize header, toolbar, table/list shell, modal visuals, and spacing.
- Add cleaner visual hierarchy with cards, badges, and action grouping.
- Keep all existing backend endpoints and operation logic unchanged.

### Phase 2 - File Listing UX Upgrade

- Strengthen List/Grid view quality.
- Improve row hover states, file-type badges, breadcrumbs, and action readability.
- Preserve existing permissions and action semantics.

### Phase 3 - Interaction Polish

- Better toasts, loading states, disabled states, and inline feedback.
- Improve search/filter and bulk-action experience.
- Add subtle purposeful motion (not decorative noise).

### Phase 4 - Final Unification

- Ensure the same design system quality across File Manager + AI Assistant experiences.
- Remove visual inconsistencies that remain from older UI layers.

## Guardrails for Contributors

- Do not introduce destructive UI rewrites in one PR.
- Prefer small, testable, reversible changes.
- Document UX-impacting changes in PR description and changelog notes.
- Keep fallback behavior and operational reliability over visual novelty.

## Definition of Done for UI PRs

A UI PR is considered complete only if all statements below are true:

1. Existing file operations still work as before.
2. Auth/session/profile flows are unaffected.
3. UI is visibly more modern and consistent.
4. Mobile rendering is verified.
5. No accessibility regression is introduced.

## Change Control

This mandate can be changed only by explicit maintainer decision and a dedicated commit that updates this file.
Until then, this document is considered immutable project truth for UI direction.
