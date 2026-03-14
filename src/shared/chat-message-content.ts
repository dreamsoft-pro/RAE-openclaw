import { globalGuard } from "../rae-enterprise-guard.js";

export function extractFirstTextBlock(message: unknown): string | undefined {
  if (!message || typeof message !== "object") {
    return undefined;
  }
  const content = (message as { content?: unknown }).content;
  if (!Array.isArray(content) || content.length === 0) {
    return undefined;
  }
  const first = content[0];
  if (!first || typeof first !== "object") {
    return undefined;
  }
  const text = (first as { text?: unknown }).text;
  if (typeof text !== "string") {
    return undefined;
  }
  
  // SEC-02: Prompt Injection Scrubber
  return globalGuard.scrubPrompt(text);
}
