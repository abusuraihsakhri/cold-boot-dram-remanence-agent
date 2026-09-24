"use strict";
const $ = (id) => document.getElementById(id);
const KB = 8.617333262145e-5;
const EA = 0.65;
const T0 = 298.15;
const TAU0 = 2.5;

function binaryEntropy(p) {
  if (p === 0) return 0;
  if (Math.abs(p - 0.5) < 1e-12) return 1;
  return -p * Math.log2(p) - (1 - p) * Math.log2(1 - p);
}

function formatSeconds(value) {
  return value >= 1e6
    ? value.toExponential(2) + " s"
    : value.toLocaleString(undefined, { maximumFractionDigits: 2 }) + " s";
}

function render() {
  const error = $("error");
  error.hidden = true;

  try {
    const temp = Number($("temp").value);
    const elapsed = Number($("elapsed").value);
    const bits = Number($("keyBits").value);

    if (!Number.isFinite(temp) || temp <= -273.15) {
      throw new Error("Temperature must be above absolute zero.");
    }
    if (!Number.isFinite(elapsed) || elapsed < 0) {
      throw new Error("Elapsed time must be zero or greater.");
    }

    const kelvin = temp + 273.15;
    const exponent = Math.min(60, Math.max(-20, (EA / KB) * (1 / kelvin - 1 / T0)));
    const tau = TAU0 * Math.exp(exponent);
    const retention = Math.exp(-Math.min(elapsed / tau, 50));
    const ber = 0.5 * (1 - retention);
    const h = binaryEntropy(ber);
    const retainedBits = bits * (1 - h);
    const uncertaintyBits = bits * h;
    const corruptionBand =
      ber < 0.02 ? "LOW CORRUPTION" :
      ber <= 0.07 ? "MODERATE CORRUPTION" :
      ber <= 0.15 ? "HIGH CORRUPTION" : "SEVERE CORRUPTION";

    const weights = [30, 30, 20, 10, 10];
    const boxes = [...document.querySelectorAll(".checks input")];
    const score = boxes.reduce((sum, box, i) => sum + (box.checked ? weights[i] : 0), 0);
    const controlBand = score >= 80 ? "STRONG CONTROLS" : score >= 50 ? "PARTIAL CONTROLS" : "LIMITED CONTROLS";

    $("retention").textContent = (retention * 100).toFixed(2) + "%";
    $("ber").textContent = (ber * 100).toFixed(2) + "%";
    $("uncertainty").textContent = uncertaintyBits.toFixed(1) + " bits";
    $("defense").textContent = score + "/100";
    $("tau").textContent = formatSeconds(tau);
    $("window").textContent = formatSeconds(-tau * Math.log(0.7));
    $("retainedBits").textContent = retainedBits.toFixed(1) + " bits";
    $("controlBand").textContent = controlBand;
    $("band").textContent = corruptionBand;
  } catch (err) {
    error.textContent = err instanceof Error ? err.message : String(err);
    error.hidden = false;
  }
}

$("simForm").addEventListener("submit", (event) => {
  event.preventDefault();
  render();
});
document.querySelectorAll("input,select").forEach((element) => element.addEventListener("change", render));

const savedTheme = localStorage.getItem("dram-theme");
if (savedTheme) document.documentElement.dataset.theme = savedTheme;
$("themeToggle").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("dram-theme", next);
});

render();
