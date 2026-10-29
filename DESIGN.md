# ScanneX Design System
*Surface Mode: Operate (Security Engineering Dashboard — Greptile-Grade Aesthetic)*

## 1. Principles
- **Restraint Over Decoration**: The interface serves the security analyst's task. No neon halos, gratuitous rainbow gradients, or meaningless cards.
- **Greptile Developer Precision**: Deep obsidian-zinc dark theme (`#09090b` canvas, `#111216` card surfaces) paired with crisp hairline borders (`rgba(255, 255, 255, 0.08)` / `#27272a`), subtle dot-matrix canvas texture, and purposeful Emerald actions (`#10b981` / `#059669`).
- **Pristine, High-Contrast Light Mode**: Clean zinc-50 canvas (`#f9fafb`) paired with pure white surfaces (`#ffffff`) and hairline slate borders (`#e4e4e7`) for an effortless, non-glaring workspace.
- **High Contrast & Accessible**: Contrast ratio ≥ 4.5:1 on all text (primary text reaches 15+:1 in both themes; secondary text > 8:1) and clear, distinct semantic badges. Zero eye strain.
- **Honest Evidence Presentation**: Differentiates proven exploits (`confirmed_dynamic`) from unverified probes and disproved claims without hiding uncertainty.
- **Zero Flashy Emojis**: Crisp, clean text badges (`DOCKER`, `SUBPROCESS`) and refined monochrome vector SVGs replace informal emojis.

## 2. Color Palette & Token Architecture

### Light Mode (`[data-theme="light"]`)
```css
:root,
[data-theme="light"] {
  /* Surfaces */
  --bg-canvas: #ebedf1;               /* Distinct light-slate canvas for clear card separation */
  --bg-surface: #ffffff;              /* Clean white cards and panels that pop */
  --bg-surface-elevated: #e2e5ea;     /* 1-step elevated light neutral */
  --bg-surface-hover: #eceef2;        /* Subtle hover tone */
  --bg-inset: #f8fafc;                /* Inset backgrounds */
  --bg-code: #f1f5f9;                 /* Code block background */
  --bg-terminal: #090d12;             /* Terminal dark console */

  /* Terminal Log Tokens (WCAG AAA Ultra High Contrast on dark console) */
  --terminal-bg: #090d12;
  --terminal-text: #f1f5f9;           /* Slate-100 crisp text (17.9:1 contrast) */
  --terminal-text-dim: #94a3b8;       /* Slate-400 clean muted text (7.7:1 contrast) */
  --terminal-stage: #34d399;          /* Emerald-400 high-contrast stage pills (10.8:1 contrast) */
  --terminal-fixed: #34d399;          /* Emerald-400 verified fixed (10.8:1 contrast) */
  --terminal-canary: #fb7185;         /* Rose-400 critical exploit canary (8.0:1 contrast) */
  --terminal-error: #f87171;          /* Red-400 error text (8.1:1 contrast) */
  --terminal-extract: #38bdf8;        /* Sky-400 extraction text (9.7:1 contrast) */
  --terminal-semgrep: #38bdf8;        /* Sky-400 semgrep text (9.7:1 contrast) */
  --terminal-bandit: #fbbf24;         /* Amber-400 bandit text (11.8:1 contrast) */
  --terminal-malware: #c084fc;        /* Purple-400 malware text (8.4:1 contrast) */
  --terminal-border: #334155;         /* Crisp boundary framing the terminal */

  /* Borders */
  --border-subtle: #cbd5e1;           /* Crisp, clearly visible card perimeter border */
  --border-strong: #94a3b8;           /* High-contrast thick separator & dashed lines */
  --border-focus: #10b981;            /* Emerald focus border */
  --focus-ring: rgba(16, 185, 129, 0.25);

  /* Typography */
  --text-primary: #020617;            /* Deepest charcoal-slate (18:1 contrast) */
  --text-secondary: #1e293b;          /* High contrast mid-slate (13:1 contrast) */
  --text-muted: #475569;              /* High contrast muted text (7.5:1 contrast) */
  --text-action: #065f46;             /* Accessible emerald text (5.2:1 contrast on elevated) */
  --text-action-hover: #064e3b;

  /* Action Buttons */
  --accent-primary: #047857;          /* Emerald-700 (5.6:1 WCAG AA contrast against #ffffff) */
  --accent-primary-hover: #065f46;    /* Emerald-800 */
  --accent-primary-active: #064e3b;
  --accent-primary-text: #ffffff;
  --accent-primary-shadow: 0 1px 2px rgba(0, 0, 0, 0.08);

  --btn-sec-bg: #ffffff;
  --btn-sec-border: #cbd5e1;
  --btn-sec-text: #020617;
  --btn-sec-hover: #f1f5f9;

  /* Semantic Badges */
  --badge-fixed-bg: #ecfdf5;
  --badge-fixed-text: #047857;
  --badge-fixed-border: #a7f3d0;

  --badge-dynamic-bg: #fff1f2;
  --badge-dynamic-text: #be123c;
  --badge-dynamic-border: #fecdd3;

  --badge-static-bg: #fffbeb;
  --badge-static-text: #b45309;
  --badge-static-border: #fde68a;

  --badge-unverified-bg: #f1f5f9;
  --badge-unverified-text: #334155;
  --badge-unverified-border: #cbd5e1;

  --badge-rejected-bg: #faf5ff;
  --badge-rejected-text: #7e22ce;
  --badge-rejected-border: #e9d5ff;

  /* Severities */
  --sev-critical: #e11d48;
  --sev-high: #ea580c;
  --sev-medium: #d97706;
  --sev-low: #0284c7;

  /* Diff colors */
  --diff-add-bg: rgba(16, 185, 129, 0.14);
  --diff-add-text: #047857;
  --diff-del-bg: rgba(244, 63, 94, 0.12);
  --diff-del-text: #be123c;

  /* Depth & Interaction */
  --card-shadow: 0 4px 14px -2px rgba(15, 23, 42, 0.08), 0 1px 3px rgba(15, 23, 42, 0.04);
  --selection-bg: rgba(16, 185, 129, 0.2);
}
```

### Dark Mode (`[data-theme="dark"]`)
```css
[data-theme="dark"] {
  /* Surfaces */
  --bg-canvas: #08090b;               /* Deep Obsidian Pitch canvas */
  --bg-surface: #161820;              /* Distinct, elevated dark card surface that pops */
  --bg-surface-elevated: #20232c;     /* 1-step elevated tabs & header */
  --bg-surface-hover: #262935;        /* Noticeable hover surface */
  --bg-inset: #0c0d12;                /* Deep recessed dark inset */
  --bg-code: #0b0c10;                 /* Monospace code block */
  --bg-terminal: #07080a;             /* Console terminal background */

  /* Terminal Log Tokens (WCAG AAA Ultra High Contrast on dark console) */
  --terminal-bg: #07080a;
  --terminal-text: #f4f4f5;           /* Zinc-100 crisp text (18.5:1 contrast) */
  --terminal-text-dim: #a1a1aa;       /* Zinc-400 clean muted text (8.8:1 contrast) */
  --terminal-stage: #34d399;          /* Emerald-400 high-contrast stage pills (11.5:1 contrast) */
  --terminal-fixed: #34d399;          /* Emerald-400 verified fixed (11.5:1 contrast) */
  --terminal-canary: #fb7185;         /* Rose-400 critical exploit canary (8.5:1 contrast) */
  --terminal-error: #f87171;          /* Red-400 error text (8.5:1 contrast) */
  --terminal-extract: #38bdf8;        /* Sky-400 extraction text (10.2:1 contrast) */
  --terminal-semgrep: #38bdf8;        /* Sky-400 semgrep text (10.2:1 contrast) */
  --terminal-bandit: #fbbf24;         /* Amber-400 bandit text (12.2:1 contrast) */
  --terminal-malware: #c084fc;        /* Purple-400 malware text (8.8:1 contrast) */
  --terminal-border: rgba(255, 255, 255, 0.16); /* Crisp hairline edge */

  /* Borders */
  --border-subtle: rgba(255, 255, 255, 0.14); /* Crisp, visible card edges */
  --border-strong: rgba(255, 255, 255, 0.28); /* High-contrast dashed lines & dividers */
  --border-focus: #10b981;                    /* Emerald focus border */
  --focus-ring: rgba(16, 185, 129, 0.35);

  /* Typography */
  --text-primary: #ffffff;            /* Pure white maximum contrast (18:1 against cards) */
  --text-secondary: #e4e4e7;          /* Zinc-200 effortless readability (12:1 contrast) */
  --text-muted: #a1a1aa;              /* Zinc-400 clean muted text (6.8:1 contrast) */
  --text-action: #34d399;             /* Accessible emerald text in dark (9:1 contrast) */
  --text-action-hover: #6ee7b7;

  /* Action Buttons */
  --accent-primary: #10b981;          /* Emerald-500 */
  --accent-primary-hover: #059669;    /* Emerald-600 */
  --accent-primary-active: #047857;
  --accent-primary-text: #09090b;     /* High contrast dark text on bright emerald */
  --accent-primary-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);

  --btn-sec-bg: #20232c;
  --btn-sec-border: rgba(255, 255, 255, 0.16);
  --btn-sec-text: #ffffff;
  --btn-sec-hover: #2a2e3a;

  /* Semantic Badges */
  --badge-fixed-bg: rgba(16, 185, 129, 0.18);
  --badge-fixed-text: #34d399;
  --badge-fixed-border: rgba(16, 185, 129, 0.5);

  --badge-dynamic-bg: rgba(244, 63, 94, 0.18);
  --badge-dynamic-text: #fb7185;
  --badge-dynamic-border: rgba(244, 63, 94, 0.5);

  --badge-static-bg: rgba(245, 158, 11, 0.18);
  --badge-static-text: #fbbf24;
  --badge-static-border: rgba(245, 158, 11, 0.5);

  --badge-unverified-bg: rgba(161, 161, 170, 0.16);
  --badge-unverified-text: #f4f4f5;
  --badge-unverified-border: rgba(161, 161, 170, 0.45);

  --badge-rejected-bg: rgba(168, 85, 247, 0.18);
  --badge-rejected-text: #c084fc;
  --badge-rejected-border: rgba(168, 85, 247, 0.45);

  /* Severities */
  --sev-critical: #fb7185;
  --sev-high: #fb923c;
  --sev-medium: #fbbf24;
  --sev-low: #38bdf8;

  /* Diff colors */
  --diff-add-bg: rgba(16, 185, 129, 0.18);
  --diff-add-text: #34d399;
  --diff-del-bg: rgba(244, 63, 94, 0.18);
  --diff-del-text: #fb7185;

  /* Depth & Interaction */
  --card-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
  --selection-bg: rgba(16, 185, 129, 0.28);
}
```

## 3. Typography System & Type Scale

### Font Families
- **Primary Font Stack (`--font-sans`)**: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif`
- **Code & Diff Font Stack (`--font-mono`)**: `ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace`

### Scale & Tokens
- `--font-size-2xs`: 11px — Table headers, uppercase stage tags, micro-badges
- `--font-size-xs`: 12px — Monospace code, metadata, hints, terminal log
- `--font-size-sm`: 13px — Buttons, form controls, table cells, descriptions
- `--font-size-base`: 14px — Core body copy, dropzone prompt, status titles
- `--font-size-md`: 16px — Brand title, modal/dialog headers
- `--font-size-lg`: 18px — Section subheadings, empty state headers
- `--font-size-xl`: 20px — Primary card headings (`.card-title`)
- `--font-size-2xl`: 28px — Metric counters (`.metric-value`)

### Rhythms, Tracking & Measures
- **Heading Tracking**: `-0.02em` for headings and metric counters.
- **Line Wrapping**: `text-wrap: balance` on headings; `text-wrap: pretty` on prose.
- **Tabular Numerals**: `font-variant-numeric: tabular-nums` across metrics, container IDs, PID tags, and table cells.
- **Reading Measure**: Clamped to `68ch` for optimal scanning.

## 4. Components & Interactive States
- **Top Navigation Bar**: Sticky frosted glass header (`backdrop-filter: blur(12px)`), hairline bottom border, brand logo SVG, secondary utility quick launcher (`Demo CVE App`), and theme toggle.
- **Segmented Tabs**: Source choice tabs (ZIP, GitHub) with clean hairline borders and smooth active state, decoupled from demo sample launchers.
- **Dropzone & Staged File State**: Hairline dashed dropzone transitioning upon archive selection into a flat staged file row (`staged-file-row`) displaying file metadata, human-readable size, a "Ready for verification" badge, "Change File" control, and an explicit primary emerald "Start Pipeline Scan" trigger (`#btn-zip-scan`).
- **Verification Engine Toggle**: 3-way segmented button with crisp active highlight.
- **Rule Packs Checklist**: Interactive rule cards with subtle active border highlight.
- **Live Terminal & Activity Log**: Authentic developer console with deep background, monospaced logs, stage pills (`[STATIC]`, `[SANDBOX]`, `[PROBE]`, `[PATCH]`), dedicated high-contrast terminal tokens (WCAG AAA ≥ 7:1) ensuring crystal readability in both light and dark modes, and copy button.
- **Live Sandbox Monitor**: Clean `DOCKER` and `SUBPROCESS` text badges with pulsing status indicator.
- **Findings Table & Detail Drawer**: High contrast table rows, clean chevron expanders, code sink viewer, canary oracle evidence, and unified diff syntax highlighting.
