(() => {
  const themes = {
    midnight: "Midnight", arctic: "Arctic", aurora: "Aurora", emerald: "Emerald",
    sapphire: "Sapphire", amethyst: "Amethyst", rose: "Rose Quartz", graphite: "Graphite",
    solar: "Solar Flare", ocean: "Deep Ocean", cyber: "Cyberpunk", carbon: "Carbon",
    obsidian: "Obsidian", cobalt: "Cobalt", lunar: "Lunar Silver", crimson: "Crimson Noir",
    jade: "Jade Empire", ultraviolet: "Ultraviolet", glacier: "Glacier", copper: "Copper Luxe",
    swiss: "Swiss Clarity", paper: "Paper & Ink", terminal: "Terminal CRT", material: "Material 3",
    academia: "Dark Academia", eink: "E-Ink Paper", frutiger: "Frutiger Aero", editorial: "Editorial Noir"
  };
  const storageKey = "vtls-glass-theme";
  const apply = (name) => {
    const theme = themes[name] ? name : "midnight";
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem(storageKey, theme); } catch (_) {}
    const label = document.getElementById("currentThemeLabel");
    if (label) label.textContent = themes[theme];
    document.querySelectorAll(".theme-option").forEach((button) => {
      const active = button.dataset.theme === theme;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    });
  };
  let saved = "midnight";
  try { saved = localStorage.getItem(storageKey) || "midnight"; } catch (_) {}
  apply(saved);
  document.querySelectorAll(".theme-trigger").forEach((trigger) => {
    trigger.addEventListener("click", () => {
      const palette = document.getElementById("themePalette");
      if (!palette) return;
      const open = palette.hidden;
      palette.hidden = !open;
      trigger.setAttribute("aria-expanded", String(open));
      trigger.classList.toggle("open", open);
    });
  });
  document.querySelectorAll(".theme-option").forEach((button) => {
    button.addEventListener("click", () => {
      apply(button.dataset.theme);
      const palette = document.getElementById("themePalette");
      const trigger = document.querySelector(".theme-trigger");
      if (palette) palette.hidden = true;
      if (trigger) {
        trigger.setAttribute("aria-expanded", "false");
        trigger.classList.remove("open");
      }
    });
  });
})();