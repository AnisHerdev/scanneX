# ScanneX Design System
*Surface Mode: Operate (Security Engineering Dashboard)*

## 1. Principles
- **Restraint Over Decoration**: The interface serves the analyst's task. No neon halos, gratuitous gradients, or meaningless cards.
- **GitHub Solid Feel**: Structured containers with crisp 1px borders, subtle 6px border radii, high-contrast typography, and purposeful GitHub-grade solid green actions (`#1f883d` light / `#238636` dark).
- **Subtle Organic Green Undertone (Light Mode)**: A crisp pale sage-slate canvas (`#f4f7f5`) paired with pristine white surfaces (`#ffffff`) for a fresh, focused engineering workspace.
- **High Contrast & Accessible**: Contrast ratio ≥ 4.5:1 on all text (primary text reaches 14+:1 in both themes) and distinct semantic badges.
- **Honest Evidence Presentation**: Differentiates proven exploits (`confirmed_dynamic`) from unverified probes and disproved claims without hiding uncertainty.

## 2. Color Palette & Token Architecture

### Light Mode (`[data-theme="light"]`)
```css
:root,
[data-theme="light"] {
  /* Surfaces */
  --bg-canvas: #f4f7f5;               /* Pale sage-slate canvas with slight green freshness */
  --bg-surface: #ffffff;              /* Clean white cards and panels */
  --bg-surface-elevated: #eef4f0;     /* 1-step elevated sage-neutral */
  --bg-surface-hover: #eaf1ec;        /* Subtle green-tinted hover */
  --bg-inset: #f8faf8;                /* Inset backgrounds */
  --bg-code: #f3f7f4;                 /* Code block background */
  --bg-terminal: #0d1117;             /* Terminal dark console */

  /* Borders */
  --border-subtle: #d3ded7;           /* 1px clean border with subtle sage hint */
  --border-strong: #b9c9c0;           /* Clean stronger separator */
  --border-focus: #1f883d;            /* GitHub solid green focus border */
  --focus-ring: rgba(31, 136, 61, 0.25);

  /* Typography */
  --text-primary: #1b2420;            /* Deep forest-charcoal (14.8:1 contrast) */
  --text-secondary: #4d5b53;          /* Mid forest-slate (6.2:1 contrast) */
  --text-muted: #6f8076;              /* Muted text (4.5:1 contrast) */

  /* Action Buttons */
  --accent-primary: #1f883d;          /* GitHub primary green */
  --accent-primary-hover: #1a7f37;
  --accent-primary-active: #187333;
  --accent-primary-text: #ffffff;
  --btn-sec-bg: #f6faf7;
  --btn-sec-border: #d3ded7;
  --btn-sec-text: #1b2420;
  --btn-sec-hover: #eaf2ec;

  /* Semantic Badges */
  --badge-fixed-bg: #dafbe1;
  --badge-fixed-text: #116329;
  --badge-fixed-border: #aceebb;

  --badge-dynamic-bg: #ffebe9;
  --badge-dynamic-text: #cf222e;
  --badge-dynamic-border: #ffc1ba;

  --badge-static-bg: #fff8c5;
  --badge-static-text: #7a4d00;
  --badge-static-border: #f4cf64;

  --badge-unverified-bg: #eff2f5;
  --badge-unverified-text: #424a53;
  --badge-unverified-border: #d0d7de;

  --badge-rejected-bg: #fbefff;
  --badge-rejected-text: #6e3ab8;
  --badge-rejected-border: #e8deee;
}
```

### Dark Mode (`[data-theme="dark"]`)
```css
[data-theme="dark"] {
  /* Surfaces */
  --bg-canvas: #0d1117;               /* Authentic GitHub dark canvas */
  --bg-surface: #161b22;              /* GitHub dark cards/surfaces */
  --bg-surface-elevated: #21262d;     /* GitHub elevated header/tabs */
  --bg-surface-hover: #29303a;        /* GitHub surface hover */
  --bg-inset: #090d12;                /* Dark inset */
  --bg-code: #0b0f14;                 /* Code block dark */
  --bg-terminal: #070a0e;             /* Terminal console dark */

  /* Borders */
  --border-subtle: #30363d;           /* GitHub dark border subtle */
  --border-strong: #484f58;           /* GitHub dark border strong */
  --border-focus: #2ea043;            /* GitHub green focus border */
  --focus-ring: rgba(46, 160, 67, 0.35);

  /* Typography */
  --text-primary: #f0f6fc;            /* GitHub dark high contrast (14.1:1) */
  --text-secondary: #8b949e;          /* GitHub dark mid text (6.4:1) */
  --text-muted: #6e7681;              /* GitHub dark muted (4.5:1) */

  /* Action Buttons */
  --accent-primary: #238636;          /* GitHub Dark green button */
  --accent-primary-hover: #2ea043;
  --accent-primary-active: #29903b;
  --accent-primary-text: #ffffff;
  --btn-sec-bg: #21262d;
  --btn-sec-border: #30363d;
  --btn-sec-text: #c9d1d9;
  --btn-sec-hover: #30363d;

  /* Semantic Badges */
  --badge-fixed-bg: rgba(46, 160, 67, 0.15);
  --badge-fixed-text: #3fb950;
  --badge-fixed-border: rgba(46, 160, 67, 0.4);

  --badge-dynamic-bg: rgba(248, 81, 73, 0.15);
  --badge-dynamic-text: #ff7b72;
  --badge-dynamic-border: rgba(248, 81, 73, 0.4);

  --badge-static-bg: rgba(210, 153, 34, 0.15);
  --badge-static-text: #d29922;
  --badge-static-border: rgba(210, 153, 34, 0.4);

  --badge-unverified-bg: rgba(110, 118, 129, 0.15);
  --badge-unverified-text: #8b949e;
  --badge-unverified-border: rgba(110, 118, 129, 0.4);

  --badge-rejected-bg: rgba(163, 113, 247, 0.15);
  --badge-rejected-text: #bc8cff;
  --badge-rejected-border: rgba(163, 113, 247, 0.4);
}
```

## 3. Typography
- **Primary Font Stack**: `-apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji"`
- **Code & Diff Font Stack**: `ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace`
- **Scale**:
  - Headings: 1.5rem (24px), bold, tight line height
  - Subheadings: 1.125rem (18px), semi-bold
  - Body: 0.875rem (14px), 1.5 line height
  - Code/Tables: 0.8125rem (13px), 1.4 line height

## 4. Components & Interactive States
- **Top Navigation Bar**:
  - Sticky header with brand icon, title, mode tag, metadata, and theme toggle button (Sun/Moon).
  - Theme preference persisted in `localStorage` (`scannex-theme`) and synchronized with `prefers-color-scheme`.
- **Dropzone**:
  - Default: dashed border `var(--border-strong)`, background `var(--bg-inset)`, clean SVG icon.
  - Drag-over & Hover: border transitions to `var(--accent-primary)`, background shifts to `var(--bg-surface-elevated)`.
- **Segmented Tabs**:
  - ZIP and GitHub clone options with clean SVG icons, active background `var(--bg-surface-elevated)`, crisp border.
- **Pipeline Activity Feed**:
  - GitHub Actions-style terminal log with monospaced stream, timestamped stages (`[STATIC]`, `[SANDBOX]`, `[PROBE]`), and auto-scroll.
- **Findings Table**:
  - Clean GitHub issue/PR table layout with hover highlights, severity tags, and semantic status pills.
  - Expandable drawer with sink code preview, canary oracle proof, and unified diff syntax coloring (`.diff-add`, `.diff-del`).
