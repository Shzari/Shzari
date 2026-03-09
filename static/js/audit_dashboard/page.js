(() => {
  const tableWrap = document.getElementById("auditTableContainer");
  const tableBody = document.getElementById("auditTableBody");
  const loadState = document.getElementById("auditLoadState");
  if (!tableWrap || !tableBody || !loadState) return;

  const apiUrl = String(tableWrap.dataset.apiUrl || "").trim();
  const pageSize = Number(tableWrap.dataset.pageSize || "100") || 100;
  let nextOffset = Number(tableWrap.dataset.initialCount || "0") || 0;
  let hasMore = String(tableWrap.dataset.hasMore || "false").toLowerCase() === "true";
  let loading = false;

  function esc(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function appendRows(items) {
    const emptyRow = document.getElementById("noAuditLogsRow");
    if (emptyRow) emptyRow.remove();
    for (const item of items) {
      const tr = document.createElement("tr");
      tr.innerHTML =
        "<td>" + esc(item.id) + "</td>" +
        "<td>" + esc(item.created_at) + "</td>" +
        "<td>" + esc(item.action) + "</td>" +
        "<td>" + esc(item.requester) + "</td>" +
        "<td>" + esc(item.approver) + "</td>" +
        "<td>" + esc(item.device_name) + "</td>" +
        "<td>" + esc(item.summary) + "</td>";
      tableBody.appendChild(tr);
    }
  }

  async function loadMoreLogs() {
    if (loading || !hasMore || !apiUrl) return;
    loading = true;
    loadState.textContent = "Loading more logs...";
    try {
      const url = apiUrl + "?offset=" + encodeURIComponent(nextOffset) + "&limit=" + encodeURIComponent(pageSize);
      const res = await fetch(url, { headers: { "Accept": "application/json" } });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const data = await res.json();
      if (!data || !data.ok || !Array.isArray(data.logs)) throw new Error("Bad response");
      appendRows(data.logs);
      nextOffset = Number(data.next_offset || (nextOffset + data.logs.length));
      hasMore = Boolean(data.has_more);
      loadState.textContent = hasMore ? "Scroll down to load more..." : "All logs loaded.";
    } catch (_err) {
      loadState.textContent = "Failed to load more logs.";
    } finally {
      loading = false;
    }
  }

  if (hasMore) {
    loadState.textContent = "Scroll down to load more...";
  } else {
    loadState.textContent = tableBody.querySelectorAll("tr").length ? "All logs loaded." : "";
  }

  tableWrap.addEventListener("scroll", () => {
    if (!hasMore || loading) return;
    const remaining = tableWrap.scrollHeight - tableWrap.scrollTop - tableWrap.clientHeight;
    if (remaining < 120) loadMoreLogs();
  });
})();
