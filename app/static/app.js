/* VaultGuard SDMS Client-Side UX Enhancements (CSP-strict, zero inline scripts) */

(function () {
  "use strict";

  // 1. Password visibility toggles
  document.querySelectorAll("[data-pw-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var targetId = btn.getAttribute("data-pw-toggle");
      var input = document.getElementById(targetId);
      if (!input) return;
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "Hide" : "Show";
    });
  });

  // 2. Real-time password strength checker (register & recover)
  var pwInput = document.querySelector("[data-pw-strength]");
  if (pwInput) {
    var fill = document.getElementById("pw-meter-fill");
    var chips = {
      len: document.getElementById("chk-len"),
      up: document.getElementById("chk-up"),
      low: document.getElementById("chk-low"),
      num: document.getElementById("chk-num"),
      sym: document.getElementById("chk-sym"),
    };
    var evaluate = function () {
      var v = pwInput.value || "";
      var rules = {
        len: v.length >= 10,
        up: /[A-Z]/.test(v),
        low: /[a-z]/.test(v),
        num: /[0-9]/.test(v),
        sym: /[^A-Za-z0-9]/.test(v),
      };
      var passed = 0;
      Object.keys(rules).forEach(function (k) {
        if (rules[k]) passed += 1;
        if (chips[k]) {
          chips[k].classList.toggle("ok", rules[k]);
        }
      });
      if (fill) {
        var pct = (passed / 5) * 100;
        fill.style.width = pct + "%";
        fill.style.background =
          passed <= 2 ? "#f87171" : passed <= 4 ? "#fbbf24" : "#34d399";
      }
    };
    pwInput.addEventListener("input", evaluate);
    evaluate();
  }

  // 3. Drag-and-drop file upload dropzone
  var dropzone = document.getElementById("upload-dropzone");
  var fileInput = document.getElementById("file");
  var fileLabel = document.getElementById("dropzone-filename");
  if (dropzone && fileInput) {
    var updateFileDisplay = function () {
      if (fileInput.files && fileInput.files.length > 0) {
        var f = fileInput.files[0];
        var kb = (f.size / 1024).toFixed(1);
        if (fileLabel) {
          fileLabel.textContent = f.name + " (" + kb + " KB) — Ready to encrypt";
        }
      }
    };
    dropzone.addEventListener("click", function () {
      fileInput.click();
    });
    fileInput.addEventListener("change", updateFileDisplay);
    dropzone.addEventListener("dragover", function (e) {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
    dropzone.addEventListener("dragleave", function () {
      dropzone.classList.remove("dragover");
    });
    dropzone.addEventListener("drop", function (e) {
      e.preventDefault();
      dropzone.classList.remove("dragover");
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        fileInput.files = e.dataTransfer.files;
        updateFileDisplay();
      }
    });
  }

  // 4. Dashboard & Admin live search / filter pills
  var filterTable = function (tableId, searchId, attrName) {
    var table = document.getElementById(tableId);
    if (!table) return;
    var rows = Array.prototype.slice.call(table.querySelectorAll("tbody tr"));
    var searchEl = document.getElementById(searchId);
    var activeFilter = "all";

    var apply = function () {
      var q = searchEl ? searchEl.value.trim().toLowerCase() : "";
      rows.forEach(function (tr) {
        var text = (tr.textContent || "").toLowerCase();
        var tag = (tr.getAttribute(attrName) || "").toLowerCase();
        var matchText = !q || text.indexOf(q) !== -1;
        var matchRole = activeFilter === "all" || tag === activeFilter;
        tr.style.display = matchText && matchRole ? "" : "none";
      });
    };

    if (searchEl) {
      searchEl.addEventListener("input", apply);
    }
    document.querySelectorAll('[data-filter-target="' + tableId + '"]').forEach(function (pill) {
      pill.addEventListener("click", function () {
        document
          .querySelectorAll('[data-filter-target="' + tableId + '"]')
          .forEach(function (p) {
            p.classList.remove("active");
          });
        pill.classList.add("active");
        activeFilter = (pill.getAttribute("data-filter-val") || "all").toLowerCase();
        apply();
      });
    });
  };
  filterTable("vault-table", "vault-search", "data-role");
  filterTable("audit-table", "audit-search", "data-outcome");

  // 5. Copy-to-clipboard buttons
  document.querySelectorAll("[data-copy-text]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var text = btn.getAttribute("data-copy-text") || "";
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(text).then(function () {
        var old = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(function () {
          btn.textContent = old;
        }, 1400);
      });
    });
  });

  // 6. Share expiry quick presets
  document.querySelectorAll("[data-exp-hours]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById("expires_in_hours");
      if (!input) return;
      input.value = btn.getAttribute("data-exp-hours") || "";
    });
  });

  // 7. Inline two-step Delete confirmation (zero native alert/confirm)
  var delInit = document.getElementById("delete-init-btn");
  var delConfirmWrap = document.getElementById("delete-confirm-wrap");
  var delCancel = document.getElementById("delete-cancel-btn");
  if (delInit && delConfirmWrap) {
    delInit.addEventListener("click", function () {
      delInit.classList.add("hidden");
      delConfirmWrap.classList.remove("hidden");
    });
    if (delCancel) {
      delCancel.addEventListener("click", function () {
        delConfirmWrap.classList.add("hidden");
        delInit.classList.remove("hidden");
      });
    }
  }
})();
