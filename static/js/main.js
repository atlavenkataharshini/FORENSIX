document.addEventListener("DOMContentLoaded", () => {
  const menuToggle = document.getElementById("menuToggle");
  const sidebar = document.getElementById("sidebar");
  if (menuToggle && sidebar) {
    menuToggle.addEventListener("click", () => sidebar.classList.toggle("open"));
  }

  document.querySelectorAll(".flash-close").forEach((button) => {
    button.addEventListener("click", () => button.parentElement.remove());
  });

  document.querySelectorAll("[data-password-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      const input = document.getElementById(button.dataset.passwordToggle);
      if (!input) return;
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      button.textContent = show ? "Hide" : "Show";
      button.setAttribute("aria-label", show ? "Hide password" : "Show password");
    });
  });

  const dataNode = document.getElementById("chartData");
  const canvas = document.getElementById("evidenceChart");
  if (dataNode && canvas) {
    const rows = JSON.parse(dataNode.textContent);
    const largest = Math.max(...rows.map((row) => row.count), 1);
    rows.forEach((row) => {
      const line = document.createElement("div");
      line.className = "chart-row";
      const label = document.createElement("span");
      label.className = "chart-label";
      label.textContent = row.event_type;
      const track = document.createElement("span");
      track.className = "chart-track";
      const fill = document.createElement("span");
      fill.className = "chart-fill";
      fill.style.display = "block";
      fill.style.width = `${(row.count / largest) * 100}%`;
      track.append(fill);
      const value = document.createElement("span");
      value.className = "chart-value";
      value.textContent = row.count;
      line.append(label, track, value);
      canvas.append(line);
    });
  }
});
