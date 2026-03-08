const LAST_USERNAME_KEY = "nettool_last_username";

window.addEventListener("DOMContentLoaded", () => {
  const usernameInput = document.getElementById("loginUsername");
  const form = document.getElementById("loginForm");
  if (!usernameInput || !form) return;

  const remembered = localStorage.getItem(LAST_USERNAME_KEY) || "";
  if (remembered && !usernameInput.value) {
    usernameInput.value = remembered;
  }

  form.addEventListener("submit", () => {
    const value = usernameInput.value.trim();
    if (value) localStorage.setItem(LAST_USERNAME_KEY, value);
  });
});
