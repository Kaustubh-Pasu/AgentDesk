/* Progressive enhancement only: adds a "Copy" button next to values marked [data-copy].
   Without this script (or without clipboard access) the values still select whole on one click. */
(function () {
  "use strict";
  if (!navigator.clipboard || !window.isSecureContext) return;
  document.querySelectorAll("[data-copy]").forEach(function (holder) {
    var code = holder.querySelector("code");
    if (!code) return;
    var button = document.createElement("button");
    button.type = "button";
    button.className = "secondary small";
    button.textContent = "Copy";
    var status = document.createElement("span");
    status.className = "copy-status visually-hidden";
    status.setAttribute("role", "status");
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(code.textContent).then(function () {
        button.textContent = "Copied";
        status.textContent = "Copied to clipboard";
        window.setTimeout(function () { button.textContent = "Copy"; status.textContent = ""; }, 1600);
      }).catch(function () { button.textContent = "Select and copy"; });
    });
    holder.appendChild(button);
    holder.appendChild(status);
  });
})();
