import crypto from "node:crypto";

// RAE Enterprise Guard & Memory Bridge for Node.js (TypeScript)
// Hardened version with Domain White-listing and Prompt-Injection scrubbing logic

export interface GuardAuditOptions {
  operationName: string;
  impactLevel: "low" | "medium" | "high" | "critical";
  infoClass?: "public" | "internal" | "confidential" | "restricted" | "critical";
}

export class RAEEnterpriseFoundation {
  private moduleName: string;
  private projectName: string;
  private tenantId: string;
  private apiUrl: string;
  
  // SEC-01: Exfiltration White-list
  private allowedDomains = [
    "github.com",
    "api.openai.com",
    "api.anthropic.com",
    "api.firecrawl.dev",
    "localhost",
    "127.0.0.1",
    "100.68.166.117" // Node 1 (Lumina)
  ];

  constructor(moduleName: string) {
    this.moduleName = moduleName;
    this.projectName = process.env.RAE_PROJECT_NAME || "rae-open-claw";
    this.tenantId = process.env.RAE_TENANT_ID || "53717286-fe94-4c8f-baf9-c4d2758eb672"; 
    this.apiUrl = process.env.RAE_API_URL || "http://rae-api-dev:8000";
  }

  /**
   * SEC-02: Prompt Injection Scrubber
   * Removes known jailbreak attempts and instruction overrides.
   */
  public scrubPrompt(text: string): string {
    const dangerousPatterns = [
      /\bignore all previous instructions\b/gi,
      /\byou are now a\b/gi,
      /\bforget everything\b/gi,
      /\bsystem override\b/gi,
      /<\|.*?\|>/g // Special tokens
    ];
    
    let cleaned = text;
    dangerousPatterns.forEach(pattern => {
      cleaned = cleaned.replace(pattern, "[CLEANED_BY_RAE_GUARD]");
    });
    return cleaned;
  }

  public async logEvent(content: string, humanLabel: string, metadata: Record<string, any> = {}, layer: string = "reflective") {
    if (this.tenantId === "00000000-0000-0000-0000-000000000000") return;

    const payload = {
      content,
      project: this.projectName,
      human_label: humanLabel,
      metadata: { ...metadata, origin: "rae-open-claw", module: this.moduleName },
      importance: 0.8,
      layer
    };

    try {
      // Background telemetry
      fetch(`${this.apiUrl}/v2/memories/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Tenant-Id": this.tenantId
        },
        body: JSON.stringify(payload)
      }).catch(() => {});
    } catch (e) {}
  }

  public enforceHardFrames(target: string, options: GuardAuditOptions) {
    // 1. Block interactive shell commands
    const isInteractive = target.match(/\b(nano|vim|top|htop|ssh|ftp|telnet)\b/i);
    if (isInteractive) {
      throw new Error(`[RAE GUARD] FATAL: Interactive command detected. VIOLATION of NO_INTERACTIVE_COMMANDS contract.`);
    }

    // 2. SEC-01: Exfiltration Control
    if (target.startsWith("fetch") || target.startsWith("scrape") || target.includes("http")) {
      try {
        const urlMatch = target.match(/https?:\/\/[^\s]+/);
        if (urlMatch) {
          const url = new URL(urlMatch[0]);
          const isAllowed = this.allowedDomains.some(domain => url.hostname.endsWith(domain));
          
          if (!isAllowed && options.infoClass !== "public") {
            throw new Error(`[RAE GUARD] FATAL: Exfiltration attempt blocked. Domain '${url.hostname}' is not in the whitelist for ${options.infoClass} data.`);
          }
        }
      } catch (e: any) {
        if (e.message.includes("RAE GUARD")) throw e;
        // Ignore URL parsing errors for non-URL commands
      }
    }

    if (options.infoClass === "critical" && options.impactLevel !== "high" && options.impactLevel !== "critical") {
      throw new Error(`[RAE GUARD] FATAL: Critical information class requires high impact execution framework.`);
    }
  }

  public async auditedOperation<T>(
    options: GuardAuditOptions,
    operation: () => Promise<T> | T
  ): Promise<T> {
    const startMs = Date.now();
    const formattedName = options.operationName.toUpperCase().replace(/_/g, " ");
    
    await this.logEvent(
      `Starting operation ${options.operationName}`,
      `[OPENCLAW] Operation: ${formattedName} (START)`,
      { status: "started", impact: options.impactLevel, info_class: options.infoClass }
    );

    try {
      const result = await operation();
      const durationMs = Date.now() - startMs;
      
      await this.logEvent(
        `Completed operation ${options.operationName}`,
        `[OPENCLAW] Operation: ${formattedName} (TELEMETRY: SUCCESS)`,
        { status: "success", duration_ms: durationMs }
      );
      
      return result;
    } catch (error: any) {
      await this.logEvent(
        `Failed operation ${options.operationName}: ${error.message}`,
        `[OPENCLAW] Operation: ${formattedName} (CRITICAL: FAILURE)`,
        { status: "failed", error: error.message }
      );
      throw error;
    }
  }
}

export const globalGuard = new RAEEnterpriseFoundation("agent-core");
