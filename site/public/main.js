/* Dependency-free presentation. The browser never evaluates a DCP certificate. */
document.documentElement.classList.add("js");

const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
const finePointer = matchMedia("(hover: hover) and (pointer: fine)");
let motionPaused = reducedMotion.matches;
const motionButton = document.querySelector(".motion-toggle");
const scene = document.querySelector("#orbital-map");
const toast = document.querySelector(".toast");
let toastTimer;

function notify(message) {
  toast.textContent = message;
  toast.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("visible"), 2200);
}

const descriptions = {
  start: [
    "01",
    "Freeze the model, starting material, evaluator, and budgets before the research run.",
  ],
  experiment: [
    "02",
    "The agent proposes an artifact, runs a task experiment, and measures its outcome.",
  ],
  feedback: [
    "03",
    "Experimental feedback guides the next proposal. DCP later tests this channel with paired controls.",
  ],
  record: [
    "04",
    "Capture the adaptive history and allowed Web responses. Frozen evidence becomes the input to the audit.",
  ],
};
for (const button of document.querySelectorAll("[data-stage]")) {
  button.addEventListener("click", () => {
    document.querySelectorAll("[data-stage]").forEach((node) => {
      const active = node === button;
      node.classList.toggle("is-active", active);
      node.setAttribute("aria-pressed", String(active));
    });
    const [index, description] = descriptions[button.dataset.stage];
    document.querySelector("#scene-index").textContent = index;
    document.querySelector("#scene-description").textContent = description;
  });
}

const revealObserver = new IntersectionObserver(
  (entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        entry.target.classList.add("is-visible");
        revealObserver.unobserve(entry.target);
      }
    }
  },
  { threshold: 0.08 },
);
document
  .querySelectorAll(".reveal")
  .forEach((element) => revealObserver.observe(element));

for (const card of document.querySelectorAll("[data-glow]")) {
  card.addEventListener("pointermove", (event) => {
    if (!finePointer.matches || motionPaused) return;
    const rect = card.getBoundingClientRect();
    card.style.setProperty("--mx", `${event.clientX - rect.left}px`);
    card.style.setProperty("--my", `${event.clientY - rect.top}px`);
  });
}

const tabs = [...document.querySelectorAll("[role=tab]")];
function activateTab(tab, focus = false) {
  for (const item of tabs) {
    const selected = tab === item;
    item.setAttribute("aria-selected", String(selected));
    item.tabIndex = selected ? 0 : -1;
    document.getElementById(item.getAttribute("aria-controls")).hidden =
      !selected;
  }
  if (focus) tab.focus();
}
tabs.forEach((tab, index) => {
  tab.addEventListener("click", () => activateTab(tab));
  tab.addEventListener("keydown", (event) => {
    let next;
    if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
    if (event.key === "ArrowLeft")
      next = (index + tabs.length - 1) % tabs.length;
    if (event.key === "Home") next = 0;
    if (event.key === "End") next = tabs.length - 1;
    if (next !== undefined) {
      event.preventDefault();
      activateTab(tabs[next], true);
    }
  });
});

for (const button of document.querySelectorAll("[data-copy]")) {
  button.addEventListener("click", async () => {
    const source = document.getElementById(button.dataset.copy);
    try {
      await navigator.clipboard.writeText(source.textContent.trim());
      notify(
        button.dataset.copy === "citation"
          ? "BibTeX copied"
          : "Copied to clipboard",
      );
    } catch {
      const selection = getSelection();
      const range = document.createRange();
      range.selectNodeContents(source);
      selection.removeAllRanges();
      selection.addRange(range);
      notify("Text selected. Press Ctrl+C or ⌘C to copy.");
    }
  });
}

/* A slowly rotating evidence constellation. Orbit paths convey iteration;
   connections react to the pointer. These particles contain no result data. */
const canvas = document.querySelector("#research-particles");
const ctx = canvas.getContext("2d");
let width = 0,
  height = 0,
  frameId = 0,
  time = 0,
  lastTime = 0;
let inView = true;
const pointer = { x: 0, y: 0, active: false };
const TAU = Math.PI * 2;
const points = Array.from({ length: 170 }, (_, i) => {
  const y = 1 - (i / 169) * 2;
  const r = Math.sqrt(1 - y * y);
  const angle = i * Math.PI * (3 - Math.sqrt(5));
  return { x: Math.cos(angle) * r, y, z: Math.sin(angle) * r, ring: i % 3 };
});

function project(point, rotation, radius) {
  const cos = Math.cos(rotation),
    sin = Math.sin(rotation);
  const x = point.x * cos - point.z * sin;
  const z = point.x * sin + point.z * cos;
  const tilt = 0.25 + (pointer.active ? pointer.y * 0.08 : 0);
  const y = point.y * Math.cos(tilt) - z * Math.sin(tilt);
  const depth = point.y * Math.sin(tilt) + z * Math.cos(tilt);
  const scale = 3.4 / (3.4 - depth * 0.4);
  return {
    x: width / 2 + x * radius * scale,
    y: height / 2 + y * radius * 0.9 * scale,
    z: depth,
  };
}

function draw() {
  if (!ctx || !width || !height) return;
  ctx.clearRect(0, 0, width, height);
  const radius = Math.min(width * 0.39, height * 0.4);
  const rotation = time * 0.000095 + (pointer.active ? pointer.x * 0.12 : 0);
  const dots = points.map((point) => project(point, rotation, radius));
  const glow = ctx.createRadialGradient(
    width / 2,
    height / 2,
    radius * 0.25,
    width / 2,
    height / 2,
    radius * 1.35,
  );
  glow.addColorStop(0, "#6974ef07");
  glow.addColorStop(0.65, "#6974ef0b");
  glow.addColorStop(1, "#6974ef00");
  ctx.fillStyle = glow;
  ctx.fillRect(0, 0, width, height);
  const mouseX = width * (0.5 + pointer.x * 0.5),
    mouseY = height * (0.5 + pointer.y * 0.5);
  for (let i = 0; i < dots.length; i++) {
    const a = dots[i];
    for (let j = i + 1; j < dots.length; j++) {
      const b = dots[j],
        distance = Math.hypot(a.x - b.x, a.y - b.y);
      if (distance > radius * 0.29 || Math.abs(a.z - b.z) > 0.7) continue;
      const proximity = pointer.active
        ? Math.max(0, 1 - Math.hypot(a.x - mouseX, a.y - mouseY) / 130)
        : 0;
      const alpha =
        (0.035 + proximity * 0.28) *
        Math.max(0.15, (a.z + 1.3) / 2.3) *
        (1 - distance / (radius * 0.32));
      ctx.strokeStyle = `rgba(145,170,255,${alpha})`;
      ctx.lineWidth = 0.65;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();
    }
    const front = (a.z + 1) / 2;
    const near = pointer.active
      ? Math.max(0, 1 - Math.hypot(a.x - mouseX, a.y - mouseY) / 90)
      : 0;
    ctx.fillStyle = `rgba(${i % 3 === 0 ? "171,146,245" : "138,182,250"},${0.12 + front * 0.42 + near * 0.4})`;
    ctx.beginPath();
    ctx.arc(a.x, a.y, 0.6 + front * 0.9 + near, 0, TAU);
    ctx.fill();
  }
  for (let ring = 0; ring < 3; ring++) {
    const angle = (ring * TAU) / 3 + 0.25;
    const ca = Math.cos(angle),
      sa = Math.sin(angle);
    ctx.beginPath();
    for (let i = 0; i <= 180; i++) {
      const theta = (i / 180) * TAU;
      const x = Math.cos(theta) * radius * 1.1,
        y = Math.sin(theta) * radius * 0.48;
      const px = width / 2 + x * ca - y * sa,
        py = height / 2 + x * sa + y * ca;
      if (i === 0) ctx.moveTo(px, py);
      else ctx.lineTo(px, py);
    }
    ctx.strokeStyle = ["#789eff2b", "#b891fa26", "#74d9ce20"][ring];
    ctx.lineWidth = 0.85;
    ctx.stroke();
    const phase = time * 0.00025 + ring * 2.1;
    const x = Math.cos(phase) * radius * 1.1,
      y = Math.sin(phase) * radius * 0.48;
    const px = width / 2 + x * ca - y * sa,
      py = height / 2 + x * sa + y * ca;
    ctx.shadowColor = ["#7cafff", "#b99bff", "#81ddce"][ring];
    ctx.shadowBlur = 12;
    ctx.fillStyle = ctx.shadowColor;
    ctx.beginPath();
    ctx.arc(px, py, 2.2, 0, TAU);
    ctx.fill();
    ctx.shadowBlur = 0;
  }
}

function animate(now) {
  frameId = 0;
  if (!ctx || motionPaused || !inView || document.hidden) {
    lastTime = 0;
    return;
  }
  const elapsed = now - lastTime;
  if (elapsed >= 1000 / 30) {
    time += Math.min(elapsed, 45);
    lastTime = now;
    draw();
  }
  frameId = requestAnimationFrame(animate);
}
function resume() {
  if (ctx && !frameId && !motionPaused && inView && !document.hidden)
    frameId = requestAnimationFrame(animate);
}
function resize() {
  const rect = scene.getBoundingClientRect();
  width = rect.width;
  height = rect.height;
  const ratio = Math.min(devicePixelRatio || 1, 2);
  canvas.width = Math.round(width * ratio);
  canvas.height = Math.round(height * ratio);
  ctx?.setTransform(ratio, 0, 0, ratio, 0, 0);
  draw();
}
function setMotion(paused) {
  motionPaused = paused;
  document.documentElement.classList.toggle("motion-paused", paused);
  motionButton.setAttribute("aria-pressed", String(paused));
  motionButton.setAttribute(
    "aria-label",
    paused ? "Resume visual motion" : "Pause visual motion",
  );
  if (paused) {
    cancelAnimationFrame(frameId);
    frameId = 0;
    lastTime = 0;
    scene.style.setProperty("--rx", "0deg");
    scene.style.setProperty("--ry", "0deg");
  } else resume();
}
scene.addEventListener("pointermove", (event) => {
  if (!finePointer.matches || motionPaused) return;
  const rect = scene.getBoundingClientRect();
  pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
  pointer.y = ((event.clientY - rect.top) / rect.height) * 2 - 1;
  pointer.active = true;
  scene.style.setProperty("--rx", `${-pointer.y * 9}deg`);
  scene.style.setProperty("--ry", `${pointer.x * 9}deg`);
});
scene.addEventListener("pointerleave", () => {
  pointer.active = false;
  scene.style.setProperty("--rx", "0deg");
  scene.style.setProperty("--ry", "0deg");
});
motionButton.addEventListener("click", () => setMotion(!motionPaused));
reducedMotion.addEventListener("change", (event) => setMotion(event.matches));
document.addEventListener("visibilitychange", resume);
new IntersectionObserver((entries) => {
  inView = entries[0].isIntersecting;
  resume();
}).observe(scene);
new ResizeObserver(resize).observe(scene);
if (ctx) scene.classList.add("canvas-ready");
resize();
setMotion(motionPaused);
