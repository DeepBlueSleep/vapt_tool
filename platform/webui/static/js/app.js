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
  if (window.htmx) return;
  const status = document.getElementById("scan-status");
  if (!status) return;
  const match = window.location.pathname.match(/\/scan\/(\d+)/);
  if (!match) return;
  const refresh = async () => {
    const current = document.getElementById("scan-status");
    if (!current || current.dataset.done === "true") return;
    const response = await fetch(`/scan/${match[1]}/status`, { headers: { "x-requested-with": "fetch" } });
    if (!response.ok) return;
    current.outerHTML = await response.text();
  };
  refresh();
  window.setInterval(refresh, 2000);
});
