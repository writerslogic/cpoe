// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::helpers::html_escape;
use crate::report::types::*;
use std::fmt::{self, Write};

const CSS_BASE: &str = include_str!("templates/base.css");
const CSS_COMPONENTS: &str = include_str!("templates/components.css");
const CSS_LAYOUT: &str = include_str!("templates/layout.css");

/// Write the `<!DOCTYPE>` through opening `<div class="pop-report">`, including
/// `<style>`, `<meta>` anchor tags, JSON-LD structured data, embedded proof
/// references, and print running header.
pub(super) fn write_head(html: &mut String, r: &WarReport) -> fmt::Result {
    let report_id = html_escape(&r.report_id);
    let doc_hash = html_escape(&r.document_hash);
    let schema = html_escape(&r.schema_version);
    let alg = html_escape(&r.algorithm_version);
    let key_fp = html_escape(&r.signing_key_fingerprint);
    let ts_iso = r.generated_at.to_rfc3339();
    let score = r.score;
    let lr_log10 = if r.likelihood_ratio > 0.0 {
        r.likelihood_ratio.log10()
    } else {
        0.0
    };

    write!(
        html,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Forensic Authorship Examination Report — {report_id}</title>

<!-- Cryptographic anchor tags (machine-readable, for automated verification) -->
<meta name="pop-report-id" content="{report_id}">
<meta name="pop-schema" content="{schema}">
<meta name="pop-root-hash" content="{doc_hash}">
<meta name="pop-algorithm" content="{alg}">
<meta name="pop-generated" content="{ts_iso}">
<meta name="pop-key-fingerprint" content="{key_fp}">
<meta name="pop-score" content="{score}">
<meta name="pop-log-lr" content="{lr_log10:.4}">
<meta name="pop-enfsi-tier" content="{enfsi}">
<meta name="pop-checkpoints" content="{cp_count}">
<meta name="report-version" content="1.0">
<meta name="protocol-version" content="pop-v1">

<!-- Structured data for search engines and academic indexers -->
<script type="application/ld+json">
{{
  "@context": "https://schema.org",
  "@type": "DigitalDocument",
  "name": "Forensic Authorship Examination Report",
  "identifier": "{report_id}",
  "dateCreated": "{ts_iso}",
  "encodingFormat": "text/html",
  "creator": {{
    "@type": "SoftwareApplication",
    "name": "CPOP Forensic Engine",
    "version": "{alg}",
    "url": "https://writerslogic.com"
  }},
  "about": {{
    "@type": "CreativeWork",
    "identifier": "{doc_hash}",
    "additionalType": "ForensicExamination"
  }},
  "isPartOf": {{
    "@type": "DefinedTermSet",
    "name": "ENFSI Verbal Equivalence Scale",
    "url": "https://enfsi.eu/documents/external-publications/"
  }}
}}
</script>

<style>
{css_base}
{css_components}
{css_layout}
</style>
</head>
<body class="pop-report">
<div class="report">
"#,
        css_base = CSS_BASE,
        css_components = CSS_COMPONENTS,
        css_layout = CSS_LAYOUT,
        enfsi = r.enfsi_tier.label(),
        cp_count = r.checkpoints.len(),
    )
}
