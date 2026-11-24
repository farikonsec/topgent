// Brand marks for agents and the companies they connect to: the brand colour
// and a simple mark drawn here, built with createElementNS so no markup is
// ever parsed. Unknown names fall back to a neutral tile with an initial.

const NS = "http://www.w3.org/2000/svg";

function svg(children, viewBox = "0 0 24 24") {
  const root = document.createElementNS(NS, "svg");
  root.setAttribute("viewBox", viewBox);
  root.setAttribute("aria-hidden", "true");
  for (const [tag, attrs] of children) {
    const node = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    root.append(node);
  }
  return root;
}

// A burst of rays: the shape of the Claude mark.
const spark = () => svg(Array.from({ length: 12 }, (_, i) => {
  const a = (i * Math.PI) / 6;
  const r = i % 2 ? 7.5 : 10;
  return ["line", { x1: 12, y1: 12, x2: (12 + r * Math.cos(a)).toFixed(2), y2: (12 + r * Math.sin(a)).toFixed(2), stroke: "currentColor", "stroke-width": 2.4, "stroke-linecap": "round" }];
}));
// A four-point star: the shape of the Gemini mark.
const star = () => svg([["path", { d: "M12 2C12.6 7.4 16.6 11.4 22 12C16.6 12.6 12.6 16.6 12 22C11.4 16.6 7.4 12.6 2 12C7.4 11.4 11.4 7.4 12 2Z", fill: "currentColor" }]]);
// Six petals around a ring: a stand-in for the OpenAI knot.
const knot = () => svg(Array.from({ length: 6 }, (_, i) => ["ellipse", { cx: 12, cy: 7, rx: 3, ry: 5.2, fill: "none", stroke: "currentColor", "stroke-width": 1.8, transform: `rotate(${i * 60} 12 12)` }]));
// A cloud: Cloudflare and other cloud hosts.
const cloud = () => svg([["path", { d: "M7 18a5 5 0 0 1-.6-9.96A6 6 0 0 1 18 9.5 4.25 4.25 0 0 1 17.5 18Z", fill: "currentColor" }]]);
// A smile arrow: the shape under the Amazon wordmark.
const smile = () => svg([
  ["path", { d: "M4 13c4.5 3.2 11 3.2 16 0", fill: "none", stroke: "currentColor", "stroke-width": 2.2, "stroke-linecap": "round" }],
  ["path", { d: "M17 11.5l3 1.5-1.2 3", fill: "none", stroke: "currentColor", "stroke-width": 2.2, "stroke-linecap": "round", "stroke-linejoin": "round" }],
]);
// Four squares: the Microsoft mark, in its four colours.
const windows = () => svg([
  ["rect", { x: 3, y: 3, width: 8.4, height: 8.4, fill: "#F25022" }],
  ["rect", { x: 12.6, y: 3, width: 8.4, height: 8.4, fill: "#7FBA00" }],
  ["rect", { x: 3, y: 12.6, width: 8.4, height: 8.4, fill: "#00A4EF" }],
  ["rect", { x: 12.6, y: 12.6, width: 8.4, height: 8.4, fill: "#FFB900" }],
]);
// A triangle: Vercel.
const triangle = () => svg([["path", { d: "M12 4l9 16H3Z", fill: "currentColor" }]]);

// key → [background, foreground, mark (function) or letter]
const BRANDS = {
  claude: ["#D97757", "#fff", spark],
  openai: ["#0F0F0F", "#fff", knot],
  gemini: ["#EEF2FF", "#4E6CF5", star],
  google: ["#FFFFFF", "#4285F4", "G"],
  ollama: ["#0F0F0F", "#fff", "O"],
  cursor: ["#0F0F0F", "#fff", "C"],
  github: ["#181717", "#fff", "GH"],
  qwen: ["#615CED", "#fff", "Q"],
  kimi: ["#0F0F0F", "#fff", "K"],
  zhipu: ["#3859FF", "#fff", "Z"],
  aider: ["#14B014", "#fff", "A"],
  goose: ["#0F0F0F", "#fff", "G"],
  cline: ["#0F0F0F", "#fff", "C"],
  roo: ["#0F0F0F", "#fff", "R"],
  continue: ["#0F0F0F", "#fff", "C"],
  windsurf: ["#0B100F", "#58E5BB", "W"],
  amp: ["#F34E3F", "#fff", "A"],
  crush: ["#6B50FF", "#fff", "C"],
  opencode: ["#0F0F0F", "#fff", "OC"],
  unsloth: ["#16A34A", "#fff", "U"],
  llamacpp: ["#1F2937", "#fff", "LL"],
  lmstudio: ["#4338CA", "#fff", "LM"],
  aws: ["#232F3E", "#FF9900", smile],
  cloudflare: ["#FFF1E6", "#F38020", cloud],
  microsoft: ["#FFFFFF", "#000", windows],
  fastly: ["#FF282D", "#fff", "F"],
  akamai: ["#0096D6", "#fff", "A"],
  digitalocean: ["#0080FF", "#fff", "DO"],
  vercel: ["#0F0F0F", "#fff", triangle],
  contabo: ["#1F3A68", "#fff", "C"],
};

const FAMILY_BRAND = {
  "claude-code": "claude", "claude-desktop": "claude", codex: "openai", "codex-cli": "openai", "chatgpt-desktop": "openai", "chatgpt-vscode": "openai", "gemini-cli": "gemini", ollama: "ollama", cursor: "cursor",
  "qwen-code": "qwen", "kimi-code": "kimi", zcode: "zhipu", "copilot-cli": "github", "github-copilot-cli": "github", "copilot-chat": "github", aider: "aider",
  goose: "goose", cline: "cline", "roo-code": "roo", continue: "continue", windsurf: "windsurf",
  amp: "amp", crush: "crush", opencode: "opencode", unsloth: "unsloth", "llama-cpp": "llamacpp", "lm-studio": "lmstudio",
};

const COMPANY_BRAND = {
  Anthropic: "claude", OpenAI: "openai", Google: "google", "Google Cloud": "google",
  "Amazon Web Services": "aws", Cloudflare: "cloudflare", Microsoft: "microsoft", GitHub: "github",
  Fastly: "fastly", Akamai: "akamai", DigitalOcean: "digitalocean", Vercel: "vercel", Contabo: "contabo",
};

/** The brand key for an agent family or a company name, or null. */
export function brandKey({ family, company } = {}) {
  if (family && FAMILY_BRAND[family]) return FAMILY_BRAND[family];
  if (company && COMPANY_BRAND[company]) return COMPANY_BRAND[company];
  return null;
}

/** A square brand tile. `size` is "sm", "md" or "lg". */
export function logo({ family, company, name }, size = "md") {
  const key = brandKey({ family, company });
  const tile = document.createElement("span");
  tile.className = `s-logo s-logo-${size}`;
  tile.title = name ?? company ?? "";
  const brand = key ? BRANDS[key] : null;
  if (!brand) {
    tile.classList.add("s-logo-plain");
    tile.textContent = (name ?? company ?? "?").charAt(0).toUpperCase();
    return tile;
  }
  const [bg, fg, mark] = brand;
  tile.style.background = bg;
  tile.style.color = fg;
  if (typeof mark === "function") tile.append(mark());
  else { tile.textContent = mark; if (mark.length > 1) tile.classList.add("s-logo-two"); }
  return tile;
}
