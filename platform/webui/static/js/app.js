function toggleTheme() {
  const root = document.documentElement;
  root.classList.toggle("dark");
  localStorage.theme = root.classList.contains("dark") ? "dark" : "light";
}

function filterList(input) {
  const query = input.value.toLowerCase();
  const root = input.parentElement;
  root.querySelectorAll(".filterable").forEach((item) => {
    item.style.display = item.textContent.toLowerCase().includes(query) ? "" : "none";
  });
}

function openImage(src) {
  const modal = document.getElementById("image-modal");
  const img = document.getElementById("image-modal-img");
  img.src = src;
  modal.classList.remove("hidden");
}

function closeImage() {
  document.getElementById("image-modal").classList.add("hidden");
}

document.body.addEventListener("htmx:beforeRequest", (event) => {
  const button = event.target.closest ? event.target.closest("[data-pdf-button]") : null;
  if (!button) return;
  const card = button.closest(".pdf-card");
  if (!card) return;
  card.classList.add("is-busy");
  const error = card.querySelector("[data-pdf-error]");
  if (error) error.textContent = "";
});

document.body.addEventListener("htmx:afterRequest", (event) => {
  const button = event.target.closest ? event.target.closest("[data-pdf-button]") : null;
  if (!button) return;
  const card = button.closest(".pdf-card");
  if (card) card.classList.remove("is-busy");
});

window.addEventListener("DOMContentLoaded", () => {
  const status = document.getElementById("scan-status");
  if (!status) return;
  const match = window.location.pathname.match(/\/scan\/(\d+)/);
  if (!match) return;
  const refresh = async () => {
    const current = document.getElementById("scan-status");
    if (!current || current.dataset.done === "true") return;
    const message = document.getElementById("scan-refresh-message");
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(`/scan/${match[1]}/status`, {
        headers: { "x-requested-with": "fetch" },
        cache: "no-store",
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const fragment = new DOMParser().parseFromString(await response.text(), "text/html");
      const next = fragment.getElementById("scan-status");
      if (!next) throw new Error("Missing scan status");
      current.replaceWith(next);
      if (message) message.textContent = "";
    } catch (error) {
      if (message) message.textContent = "Progress connection interrupted. Retrying automatically…";
    } finally {
      window.clearTimeout(timeout);
      window.setTimeout(refresh, 2000);
    }
  };
  refresh();
});
