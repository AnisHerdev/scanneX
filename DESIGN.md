# ScanneX Design System
*Surface Mode: Operate (Security Engineering Dashboard)*

## 1. Principles
- **Restraint Over Decoration**: The interface serves the analyst's task. No neon halos, gratuitous gradients, or meaningless cards.
- **Earned Familiarity**: Standard security analyst workflows—instant drag-and-drop, clear status hierarchy, terminal-grade diff views.
- **High Contrast & Accessible**: Contrast ratio ≥ 4.5:1 on all text and badges.
- **Honest Evidence Presentation**: Differentiates proven exploits (`confirmed_dynamic`) from unverified probes and disproved claims without hiding uncertainty.

## 2. Color Palette (Dark Theme / Deep Slate)
```css
:root {
  /* Surfaces */
  --bg-canvas: #090d16;
  --bg-surface: #101726;
  --bg-surface-elevated: #162032;
  --bg-surface-hover: #1e293b;
  
  /* Borders */
  --border-subtle: #1e293b;
  --border-strong: #334155;
  --border-focus: #3b82f6;

  /* Typography */
  --text-primary: #f8fafc;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;

  /* Semantic Status Badges */
  --badge-fixed-bg: #064e3b;
  --badge-fixed-text: #34d399;
  --badge-fixed-border: #059669;

  --badge-dynamic-bg: #450a0a;
  --badge-dynamic-text: #f87171;
  --badge-dynamic-border: #dc2626;

  --badge-static-bg: #451a03;
  --badge-static-text: #fbbf24;
  --badge-static-border: #d97706;

  --badge-unverified-bg: #1e293b;
  --badge-unverified-text: #94a3b8;
  --badge-unverified-border: #475569;

  --badge-rejected-bg: #1e1b4b;
  --badge-rejected-text: #a5b4fc;
  --badge-rejected-border: #4338ca;
}
```

## 3. Typography
- **Primary Font Stack**: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", sans-serif`
- **Code & Diff Font Stack**: `"JetBrains Mono", "SF Mono", "Cascadia Code", Consolas, monospace`
- **Scale**:
  - Headings: 1.5rem (24px), bold, tight line height
  - Subheadings: 1.125rem (18px), semi-bold
  - Body: 0.875rem (14px), 1.5 line height
  - Code/Tables: 0.8125rem (13px), 1.4 line height

## 4. Components & Interactive States
- **Dropzone**:
  - Default: dashed border `#334155`, subtle icon, clean helper text.
  - Drag-over: border changes to `#3b82f6` with soft glow, background shifts to `#162032`.
  - Uploading: progress bar with pulse animation.
- **GitHub Input**:
  - Text input with git icon, URL placeholder, inline "Scan Repo" primary button.
- **Pipeline Activity Feed**:
  - Monospace event log with timestamp, stage badge (`[STATIC]`, `[SANDBOX]`, `[PROBE]`), and auto-scroll.
- **Findings Table**:
  - Compact table with severity pill, status pill, location, and proof snippet.
  - Expandable row detailing the code sink, canary probe spec, oracle evidence, and syntax-highlighted diff.
