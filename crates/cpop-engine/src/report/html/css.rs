// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::helpers::html_escape;
use crate::report::types::*;
use std::fmt::{self, Write};

pub(super) fn write_head(html: &mut String, r: &WarReport) -> fmt::Result {
    let report_id_escaped = html_escape(&r.report_id);
    write!(
        html,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CPOP Authorship Report — {report_id}</title>
<style>
:root {{
  --green: #16a34a;
  --green-light: #f0fdf4;
  --green-muted: #bbf7d0;
  --orange: #ea580c;
  --orange-light: #fff7ed;
  --red: #dc2626;
  --red-light: #fef2f2;
  --blue: #2563eb;
  --purple: #7c3aed;
  --gray-50: #fafafa;
  --gray-100: #f4f4f5;
  --gray-200: #e4e4e7;
  --gray-300: #d4d4d8;
  --gray-400: #a1a1aa;
  --gray-500: #71717a;
  --gray-600: #52525b;
  --gray-700: #3f3f46;
  --gray-800: #27272a;
  --gray-900: #18181b;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  color: var(--gray-800);
  background: var(--gray-50);
  line-height: 1.6;
  font-size: 14px;
  -webkit-font-smoothing: antialiased;
}}
.container {{ max-width: 720px; margin: 0 auto; padding: 48px 24px; }}
h1 {{ font-size: 24px; font-weight: 600; letter-spacing: -0.02em; margin-bottom: 2px; }}
h2 {{ font-size: 15px; font-weight: 600; margin: 40px 0 16px; color: var(--gray-500); text-transform: uppercase; letter-spacing: 0.05em; border: none; padding: 0; }}
h3 {{ font-size: 15px; font-weight: 600; margin: 16px 0 8px; color: var(--gray-800); }}
.sample-badge {{
  display: inline-block;
  background: var(--gray-400);
  color: #fff;
  font-size: 10px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 10px;
  vertical-align: middle;
  margin-left: 8px;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}}
.subtitle {{ color: var(--gray-500); font-size: 13px; margin-bottom: 32px; }}
hr {{ border: none; border-top: 1px solid var(--gray-200); margin: 32px 0; }}

/* Verdict — clean card with colored left border */
.verdict {{
  background: #fff;
  border: 1px solid var(--gray-200);
  border-left: 4px solid var(--green);
  border-radius: 8px;
  padding: 24px;
  margin: 24px 0;
  display: flex;
  align-items: center;
  gap: 24px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}}
.verdict-score {{
  font-size: 48px;
  font-weight: 700;
  line-height: 1;
  text-align: center;
  min-width: 72px;
}}
.verdict-score small {{ font-size: 14px; font-weight: 400; display: block; color: var(--gray-500); }}
.verdict-body {{ flex: 1; }}
.verdict-body h2 {{ color: var(--gray-900); border: none; margin: 0 0 4px; padding: 0; font-size: 18px; text-transform: none; letter-spacing: 0; }}
.verdict-body p {{ margin: 0; font-size: 13px; color: var(--gray-600); }}
.verdict-lr {{
  text-align: right;
  min-width: 100px;
}}
.verdict-lr .lr-value {{ font-size: 28px; font-weight: 700; color: var(--gray-800); }}
.verdict-lr .lr-label {{ font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--gray-500); }}
.verdict-lr .lr-tier {{ font-size: 12px; font-weight: 600; color: var(--gray-600); }}

/* ENFSI scale — slim bar */
.enfsi-scale {{ display: flex; gap: 2px; margin: 4px 0 24px; font-size: 10px; font-weight: 600; border-radius: 4px; overflow: hidden; }}
.enfsi-scale span {{
  flex: 1;
  text-align: center;
  padding: 4px 2px;
  color: #fff;
  opacity: 0.6;
}}
.enfsi-against {{ background: #ef4444; }}
.enfsi-weak {{ background: #f97316; }}
.enfsi-moderate {{ background: #eab308; color: var(--gray-800) !important; }}
.enfsi-modstrong {{ background: #22c55e; }}
.enfsi-strong {{ background: #16a34a; }}
.enfsi-vstrong {{ background: #15803d; }}
.enfsi-active {{ opacity: 1 !important; font-weight: 800; box-shadow: inset 0 -2px 0 rgba(0,0,0,0.2); }}

/* Info box — clean white card */
.info-box {{
  background: #fff;
  border: 1px solid var(--gray-200);
  border-radius: 8px;
  padding: 16px 20px;
  margin: 12px 0;
  box-shadow: 0 1px 2px rgba(0,0,0,0.03);
}}
.info-box table {{ width: 100%; }}
.info-box td {{ padding: 4px 0; vertical-align: top; font-size: 13px; }}
.info-box td:first-child {{ font-weight: 500; white-space: nowrap; padding-right: 16px; min-width: 180px; color: var(--gray-500); }}
.info-box td:last-child {{ color: var(--gray-700); font-family: "SF Mono", "Fira Code", "Cascadia Code", monospace; font-size: 12px; }}

/* Evidence cards — white cards with subtle border */
.evidence-grid {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin: 16px 0;
}}
.evidence-card {{
  background: #fff;
  border: 1px solid var(--gray-200);
  border-radius: 8px;
  padding: 16px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.03);
}}
.evidence-card h4 {{ font-size: 12px; font-weight: 600; margin-bottom: 8px; color: var(--gray-500); text-transform: uppercase; letter-spacing: 0.03em; }}
.evidence-card .metric {{ font-size: 20px; font-weight: 600; margin-bottom: 2px; color: var(--gray-900); }}
.evidence-card .note {{ font-size: 12px; color: var(--gray-500); }}

/* Tables — clean with thin borders */
table.data {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }}
table.data th {{
  text-align: left;
  padding: 8px 12px;
  background: transparent;
  font-weight: 500;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--gray-500);
  border-bottom: 2px solid var(--gray-200);
}}
table.data td {{ padding: 10px 12px; border-bottom: 1px solid var(--gray-100); color: var(--gray-700); }}
table.data tr:last-child td {{ border-bottom: none; }}
table.data td:first-child {{ font-weight: 500; color: var(--gray-800); }}

/* Checkpoint chain */
.checkpoint {{ display: flex; align-items: center; gap: 8px; padding: 6px 0; font-size: 12px; font-family: "SF Mono", "Fira Code", monospace; }}
.checkpoint .ord {{ font-weight: 600; min-width: 24px; color: var(--gray-800); }}
.checkpoint .hash {{ color: var(--gray-500); }}
.checkpoint .time {{ color: var(--gray-400); font-size: 11px; }}
.checkpoint-arrow {{ color: var(--gray-300); font-size: 14px; text-align: center; }}

/* Flags */
.flag-human {{ color: var(--green); font-weight: 500; }}
.flag-synthetic {{ color: var(--red); font-weight: 500; }}
.flag-neutral {{ color: var(--gray-400); font-weight: 500; }}

/* Session timeline */
.session-box {{
  background: #fff;
  border: 1px solid var(--gray-200);
  border-left: 3px solid var(--green);
  padding: 12px 16px;
  margin: 8px 0;
  border-radius: 0 8px 8px 0;
  box-shadow: 0 1px 2px rgba(0,0,0,0.03);
}}
.session-box h4 {{ margin-bottom: 2px; font-size: 14px; }}
.session-box p {{ font-size: 13px; color: var(--gray-600); margin: 0; }}

/* Forgery */
.forgery-bar {{
  height: 6px;
  border-radius: 3px;
  background: var(--gray-200);
  margin: 4px 0 2px;
}}
.forgery-fill {{ height: 100%; border-radius: 3px; }}

/* Scope */
.scope-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 16px 0; }}
.scope-grid ul {{ margin: 0; padding-left: 18px; font-size: 13px; color: var(--gray-600); }}
.scope-grid li {{ margin-bottom: 6px; }}

/* Analyzed text */
.analyzed-text {{
  background: #fff;
  border: 1px solid var(--gray-200);
  padding: 24px;
  border-radius: 8px;
  font-size: 14px;
  line-height: 1.8;
  column-count: 2;
  column-gap: 32px;
  margin: 16px 0;
}}

/* Category scores */
.category-scores {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
  margin: 16px 0;
}}
.score-bars {{ }}
.score-bar-row {{
  display: flex;
  align-items: center;
  margin-bottom: 10px;
}}
.score-bar-label {{ font-weight: 500; font-size: 13px; min-width: 90px; color: var(--gray-700); }}
.score-bar-track {{
  flex: 1;
  height: 8px;
  background: var(--gray-200);
  border-radius: 4px;
  overflow: hidden;
  margin: 0 10px;
}}
.score-bar-fill {{
  height: 100%;
  border-radius: 4px;
}}
.score-bar-value {{ font-weight: 600; min-width: 28px; text-align: right; font-size: 13px; color: var(--gray-700); }}
.composite-note {{ font-size: 12px; color: var(--gray-500); margin-top: 8px; }}

/* Writing flow */
.flow-chart {{
  position: relative;
  height: 100px;
  background: #fff;
  border: 1px solid var(--gray-200);
  border-radius: 8px;
  display: flex;
  align-items: flex-end;
  padding: 8px 4px;
  gap: 1px;
  overflow: hidden;
}}
.flow-bar {{
  flex: 1;
  min-width: 2px;
  border-radius: 2px 2px 0 0;
}}
.flow-labels {{
  display: flex;
  justify-content: space-between;
  font-size: 10px;
  color: var(--gray-400);
  margin-top: 4px;
}}
.flow-caption {{
  font-size: 11px;
  color: var(--gray-500);
  margin-top: 6px;
}}

/* Dimension analysis */
.dimension-card {{
  background: #fff;
  border: 1px solid var(--gray-200);
  border-radius: 8px;
  padding: 16px 20px;
  margin: 12px 0;
  position: relative;
  box-shadow: 0 1px 2px rgba(0,0,0,0.03);
}}
.dimension-card h3 {{
  font-size: 15px;
  margin: 0 0 8px;
  text-transform: none;
  letter-spacing: 0;
}}
.dimension-badge {{
  position: absolute;
  top: 16px;
  right: 20px;
  width: 32px;
  height: 32px;
  border-radius: 6px;
  color: #fff;
  font-weight: 600;
  font-size: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
}}
.dimension-detail {{ font-size: 13px; margin-bottom: 4px; color: var(--gray-600); }}
.dimension-detail strong {{ font-weight: 500; color: var(--gray-800); }}

/* Methodology */
.methodology-grid {{
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 12px;
  margin: 16px 0;
}}
.methodology-card {{
  background: #fff;
  border: 1px solid var(--gray-200);
  border-radius: 8px;
  padding: 14px 16px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.03);
}}
.methodology-card h4 {{ font-size: 12px; font-weight: 600; margin-bottom: 6px; color: var(--gray-500); text-transform: uppercase; letter-spacing: 0.03em; }}
.methodology-card p {{ font-size: 12px; color: var(--gray-600); margin: 0; }}

/* LR table confidence bar */
.confidence-bar {{
  display: inline-block;
  height: 6px;
  border-radius: 3px;
  min-width: 40px;
  max-width: 100px;
}}

/* Footer */
.report-footer {{
  border-top: 1px solid var(--gray-200);
  padding-top: 16px;
  margin-top: 48px;
  font-size: 11px;
  color: var(--gray-400);
  text-align: center;
}}

@media print {{
  body {{ font-size: 12px; background: #fff; }}
  .container {{ padding: 20px; }}
  .verdict {{ break-inside: avoid; }}
  .evidence-grid {{ break-inside: avoid; }}
  h2 {{ break-after: avoid; }}
  .session-box {{ break-inside: avoid; }}
}}
@media (max-width: 600px) {{
  .evidence-grid {{ grid-template-columns: 1fr; }}
  .scope-grid {{ grid-template-columns: 1fr; }}
  .analyzed-text {{ column-count: 1; }}
  .verdict {{ flex-direction: column; text-align: center; }}
  .methodology-grid {{ grid-template-columns: 1fr; }}
}}
</style>
</head>
<body>
<div class="container">
"#,
        report_id = report_id_escaped
    )
}
