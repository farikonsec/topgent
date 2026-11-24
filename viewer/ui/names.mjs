// Agent product names, shared by the overview, alerts and notifications.

export const FAMILY_NAMES = {
  "claude-code": "Claude Code", "claude-desktop": "Claude Desktop", codex: "Codex", "codex-cli": "Codex", "chatgpt-desktop": "ChatGPT", "gemini-cli": "Gemini CLI", opencode: "OpenCode",
  aider: "Aider", goose: "Goose", ollama: "Ollama", cursor: "Cursor", "qwen-code": "Qwen Code",
  "kimi-code": "Kimi Code", zcode: "ZCode", cline: "Cline", "roo-code": "Roo Code", continue: "Continue",
  windsurf: "Windsurf", unsloth: "Unsloth", "llama-cpp": "llama.cpp", "lm-studio": "LM Studio", "copilot-cli": "Copilot CLI", amp: "Amp", crush: "Crush",
};

/** An agent's name as a person reads it. */
export function agentName(agent) {
  if (!agent?.family) return "Unknown agent";
  return FAMILY_NAMES[agent.family] ?? agent.family.replace(/[-_]/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

