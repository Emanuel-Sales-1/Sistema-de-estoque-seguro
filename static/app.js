document.addEventListener("change", (e) => {
  if (e.target.matches("select[data-autosubmit]")) e.target.form.requestSubmit();
});
document.addEventListener("submit", (e) => {
  const msg = e.target.dataset.confirm;
  if (msg && !confirm(msg)) e.preventDefault();
});
document.querySelectorAll("[data-js-hide]").forEach((el) => (el.hidden = true));
