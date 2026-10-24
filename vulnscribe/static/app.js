(() => {
  "use strict";

  const byId = (id) => document.getElementById(id);
  const state = { result: null, busy: false };
  const bugReportUrl = "https://github.com/BeyondSpace1/VulnScribe/issues/new?template=bug_report.yml";

  function setStatus(title, message, kind = "success", busy = false) {
    const region = byId("activity");
    region.classList.remove("hidden");
    byId("activity-title").textContent = title;
    byId("activity-message").textContent = message;
    byId("activity-icon").textContent = kind === "error" ? "!" : kind === "loading" ? "…" : "✓";
    byId("activity-icon").classList.toggle("error", kind === "error");
    byId("spinner").classList.toggle("hidden", !busy);
  }

  function make(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  }

  function makeDownload(data, mime, filename) {
    const blob = new Blob([data], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.hidden = true;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function safeFilename(value) {
    return String(value || "scan").replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 80) || "scan";
  }

  function renderSummary(summary, findings) {
    const grid = byId("summary-grid");
    grid.replaceChildren();
    const total = findings.length;
    const entries = [["TOTAL", total], ...Object.entries(summary || {})];
    for (const [severity, count] of entries) {
      const card = make("div", "summary-card");
      card.dataset.severity = severity;
      card.append(make("span", "", severity === "TOTAL" ? "CANDIDATES" : severity));
      card.append(make("strong", "", count));
      grid.append(card);
    }
  }

  function renderWarnings(warnings) {
    const box = byId("warnings");
    box.replaceChildren();
    if (!Array.isArray(warnings) || warnings.length === 0) {
      box.classList.add("hidden");
      return;
    }
    box.classList.remove("hidden");
    box.append(make("h3", "", "Context & limitations"));
    const list = make("ul");
    for (const warning of warnings) list.append(make("li", "", warning));
    box.append(list);
  }

  function renderFinding(finding) {
    const details = make("details", "finding");
    const summary = make("summary");
    const severity = make("span", "severity-pill severity-" + String(finding.severity || "INFO"));
    severity.textContent = finding.severity || "INFO";
    const titleGroup = make("span");
    titleGroup.append(make("span", "finding-title", finding.title || "Untitled candidate"));
    const line = finding.line_start ? ":" + finding.line_start + (finding.line_end && finding.line_end !== finding.line_start ? "-" + finding.line_end : "") : "";
    titleGroup.append(make("span", "finding-meta", (finding.rule_id || "Unknown rule") + " · " + (finding.affected_component || "unknown input") + line));
    summary.append(severity, titleGroup, make("span", "", ""));
    details.append(summary);

    const body = make("div", "finding-body");
    body.append(make("p", "finding-description", finding.description || "No description supplied."));
    const grid = make("div", "detail-grid");
    const evidenceBox = make("section", "detail-box");
    evidenceBox.append(make("h4", "", "Evidence"));
    evidenceBox.append(make("pre", "", finding.evidence || "No evidence string was supplied."));
    const remediationBox = make("section", "detail-box");
    remediationBox.append(make("h4", "", "Suggested remediation"));
    remediationBox.append(make("p", "", finding.remediation || "Review the rule and input context."));
    grid.append(evidenceBox, remediationBox);
    body.append(grid);

    const footer = make("div", "finding-footer");
    footer.append(make("span", "", "Confidence: " + (finding.confidence || "unspecified")));
    footer.append(make("span", "", "Validation: " + (finding.validation_status || "needs_review")));
    if (finding.cwe_id) footer.append(make("span", "", finding.cwe_id));
    if (Array.isArray(finding.references)) {
      for (const reference of finding.references) {
        try {
          const parsed = new URL(reference, window.location.origin);
          if (parsed.protocol === "https:" || parsed.protocol === "http:") {
            const link = make("a", "", "Reference ↗");
            link.href = parsed.href;
            link.target = "_blank";
            link.rel = "noopener noreferrer";
            footer.append(link);
          }
        } catch (_) {
          // Unparseable reference values are omitted from the interactive UI.
        }
      }
    }
    body.append(footer);
    details.append(body);
    return details;
  }

  function renderResult(result) {
    state.result = result;
    byId("results").classList.remove("hidden");
    byId("result-caption").textContent =
      "Scan " + (result.scan_id || "completed") + " · " +
      ((result.target && result.target.filename) || "input") +
      " · All findings need human validation.";
    const findings = Array.isArray(result.findings) ? result.findings : [];
    renderSummary(result.summary, findings);
    renderWarnings(result.warnings);
    const list = byId("findings-list");
    list.replaceChildren();
    if (findings.length === 0) {
      const empty = make("div", "empty-state");
      empty.append(make("strong", "", "No candidates emitted by enabled checks"));
      empty.append(make("p", "", "This is not proof that the input is secure. Review scanner coverage and limitations before drawing conclusions."));
      list.append(empty);
    } else {
      for (const finding of findings) list.append(renderFinding(finding));
    }
    byId("download-json").disabled = false;
    byId("download-markdown").disabled = false;
    byId("results").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function submitScan(url, payload, button) {
    if (state.busy) return;
    state.busy = true;
    button.disabled = true;
    setStatus("Scanning supplied input", "Sending text to the local VulnScribe API…", "loading", true);
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify(payload),
        credentials: "same-origin",
        cache: "no-store",
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        const message = data.detail
          ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail))
          : "The request failed with HTTP " + response.status + ".";
        throw new Error(message);
      }
      renderResult(data);
      setStatus("Scan complete", findingsMessage(data), "success", false);
    } catch (error) {
      setStatus("Scan failed", error instanceof Error ? error.message : "Unexpected error.", "error", false);
    } finally {
      state.busy = false;
      button.disabled = false;
    }
  }

  function findingsMessage(result) {
    const count = Array.isArray(result.findings) ? result.findings.length : 0;
    return count + " candidate finding(s). Results are not confirmed vulnerabilities.";
  }

  for (const tab of document.querySelectorAll("[data-tab]")) {
    tab.addEventListener("click", () => {
      const mode = tab.dataset.tab;
      for (const candidate of document.querySelectorAll("[data-tab]")) {
        const active = candidate === tab;
        candidate.classList.toggle("active", active);
        candidate.setAttribute("aria-selected", active ? "true" : "false");
      }
      byId("panel-code").classList.toggle("hidden", mode !== "code");
      byId("panel-http").classList.toggle("hidden", mode !== "http");
    });
  }

  byId("source").addEventListener("input", () => {
    byId("source-count").textContent = byId("source").value.length.toLocaleString() + " characters";
  });
  byId("raw-response").addEventListener("input", () => {
    byId("http-count").textContent = byId("raw-response").value.length.toLocaleString() + " characters";
  });

  byId("source-file").addEventListener("change", async (event) => {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    if (file.size > 500000) {
      event.target.value = "";
      setStatus("File too large", "Choose a text file no larger than 500 KB.", "error");
      return;
    }
    try {
      const text = await file.text();
      if (text.length > 500000) throw new Error("Decoded file text exceeds 500,000 characters.");
      byId("source").value = text;
      byId("source-count").textContent = text.length.toLocaleString() + " characters";
      byId("filename").value = file.name.slice(0, 255);
      const extension = file.name.toLowerCase().split(".").pop();
      const byExtension = { php: "php", phtml: "php", py: "python", js: "javascript", jsx: "javascript", ts: "typescript", tsx: "typescript", go: "go" };
      if (byExtension[extension]) byId("language").value = byExtension[extension];
      setStatus("Local file loaded", file.name + " is in the editor. It has not been sent to the API yet.", "success");
    } catch (error) {
      setStatus("Could not read file", error instanceof Error ? error.message : "The selected file could not be read.", "error");
    }
  });

  byId("code-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const source = byId("source").value;
    const filename = byId("filename").value.trim() || "pasted-code.txt";
    if (!source.trim()) return setStatus("Source required", "Paste or load source text before scanning.", "error");
    if (source.length > 500000) return setStatus("Source too large", "The current limit is 500,000 characters.", "error");
    const language = byId("language").value || null;
    await submitScan("/api/v1/scans/code?format=json", { filename, language, source }, event.submitter);
  });

  byId("http-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const raw_response = byId("raw-response").value;
    if (!raw_response.trim()) return setStatus("HTTP response required", "Paste the raw response first.", "error");
    if (raw_response.length > 200000) return setStatus("Response too large", "The current limit is 200,000 characters.", "error");
    const payload = {
      target_label: byId("http-label").value.trim() || "pasted-http-response",
      raw_response,
    };
    const scheme = byId("transport-scheme").value;
    if (scheme === "http" || scheme === "https") payload.transport_scheme = scheme;
    await submitScan("/api/v1/scans/http?format=json", payload, event.submitter);
  });

  byId("download-json").addEventListener("click", () => {
    if (!state.result) return;
    makeDownload(JSON.stringify(state.result, null, 2), "application/json;charset=utf-8", safeFilename(state.result.scan_id) + ".json");
  });

  byId("download-markdown").addEventListener("click", async (event) => {
    if (!state.result || state.busy) return;
    const button = event.currentTarget;
    state.busy = true;
    button.disabled = true;
    try {
      const response = await fetch("/api/v1/reports/markdown", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "text/markdown" },
        body: JSON.stringify(state.result),
        credentials: "same-origin",
        cache: "no-store",
      });
      if (!response.ok) {
        const body = await response.text();
        throw new Error(body || "Could not generate the Markdown report.");
      }
      makeDownload(await response.text(), "text/markdown;charset=utf-8", safeFilename(state.result.scan_id) + ".md");
      setStatus("Markdown report ready", "Downloaded report for " + state.result.scan_id + ".", "success");
    } catch (error) {
      setStatus("Export failed", error instanceof Error ? error.message : "Could not export Markdown.", "error");
    } finally {
      state.busy = false;
      button.disabled = false;
    }
  });

  fetch("/health", { credentials: "same-origin", cache: "no-store" })
    .then((response) => {
      if (!response.ok) throw new Error("Health endpoint unavailable");
      return response.json();
    })
    .then((data) => {
      const version = data.version || "development";
      byId("version-label").textContent = "v" + version;
      byId("footer-version").textContent = "v" + version;
    })
    .catch(() => {
      byId("version-label").textContent = "local preview";
      byId("footer-version").textContent = "local preview";
    });

  const expectedBugUrl = new URL(bugReportUrl);
  if (expectedBugUrl.protocol === "https:") {
    for (const link of document.querySelectorAll('a[href*="issues/new"]')) link.href = expectedBugUrl.href;
  }
})();
