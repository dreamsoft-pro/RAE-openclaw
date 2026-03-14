import crypto from "node:crypto";

// RAE Enterprise Guard & Memory Bridge for Node.js (TypeScript)
// Hardened version with Intelligent Context Detection (RAEContextLocator Port)

export interface GuardAuditOptions {
  operationName: string;
  impactLevel: "low" | "medium" | "high" | "critical";
  infoClass?: "public" | "internal" | "confidential" | "restricted" | "critical";
}

const TENANT_MAP: Record<string, string> = {
  "screenwatcher_project": "66435998-b1d9-5521-9481-55a9fd10e014",
  "dreamsoft_factory": "53717286-fe94-4c8f-baf9-c4d2758eb672",
  "billboard-splitter": "67694908-0b76-58a9-979d-3db20071e34a",
  "RAE-agentic-memory": "00000000-0000-0000-0000-000000000000",
  "RAE-Suite": "00000000-0000-0000-0000-000000000000"
};

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
    this.projectName = this.detectProjectName();
    this.tenantId = this.detectTenantId(this.projectName);
    this.apiUrl = process.env.RAE_API_URL || "http://rae-api-dev:8000";
  }

  private detectProjectName(): string {
    if (process.env.RAE_PROJECT_NAME) return process.env.RAE_PROJECT_NAME;
    
    const cwd = process.cwd();
    for (const folder of Object.keys(TENANT_MAP)) {
      if (cwd.includes(folder)) return folder;
    }
    return "unnamed_rae_module";
  }

  private detectTenantId(projName: string): string {
    if (process.env.RAE_TENANT_ID) return process.env.RAE_TENANT_ID;
    
    if (TENANT_MAP[projName]) {
      return TENANT_MAP[projName];
    }
    
    const cwd = process.cwd();
    for (const [folder, uuid] of Object.entries(TENANT_MAP)) {
      if (cwd.includes(folder)) return uuid;
    }
    
    return "00000000-0000-0000-0000-000000000000";
  }

  /**
   * SEC-02: Prompt Injection Scrubber
   */
  public scrubPrompt(text: string): string {
    const dangerousPatterns = [
      /\bignore all previous instructions\b/gi,
      /\byou are now a\b/gi,
      /\bforget everything\b/gi,
      /\bsystem override\b/gi,
      /<\|.*?\|>/g 
    ];
    
    let cleaned = text;
    dangerousPatterns.forEach(pattern => {
      cleaned = cleaned.replace(pattern, "[CLEANED_BY_RAE_GUARD]");
    });
    return cleaned;
  }

  /**
   * SEC-03: Lean Model Selector
   */
  public getLeanModel(task: string): { modelId: string, tier: number } {
    const isArchitectural = task.match(/\b(architecture|refactor|design|security|critical)\b/i);
    const isComplex = task.length > 500 || task.includes("logic") || task.includes("bug");

    if (isArchitectural) {
      return { modelId: "premium_anthropic", tier: 3 }; 
    }
    if (isComplex) {
      return { modelId: "local_llama", tier: 2 }; 
    }
    return { modelId: "local_qwen", tier: 1 }; 
  }

  public async logEvent(content: string, humanLabel: string, metadata: Record<string, any> = {}, layer: string = "reflective") {
    if (this.tenantId === "00000000-0000-0000-0000-000000000000" && !this.projectName.includes("RAE")) return;

    const payload = {
      content,
      project: this.projectName,
      human_label: humanLabel,
      metadata: { ...metadata, origin: "rae-open-claw", module: this.moduleName },
      importance: 0.8,
      layer
    };

    try {
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
    const isInteractive = target.match(/\b(nano|vim|top|htop|ssh|ftp|telnet)\b/i);
    if (isInteractive) {
      throw new Error(`[RAE GUARD] FATAL: Interactive command detected. VIOLATION of NO_INTERACTIVE_COMMANDS contract.`);
    }

    if (target.startsWith("fetch") || target.startsWith("scrape") || target.includes("http")) {
      try {
        const urlMatch = target.match(/https?:\/\/[^\s]+/);
        if (urlMatch) {
          const url = new URL(urlMatch[0]);
          const isAllowed = this.allowedDomains.some(domain => url.hostname.endsWith(domain));
          
          if (!isAllowed && options.infoClass !== "public") {
            throw new Error(`[RAE GUARD] FATAL: Exfiltration attempt blocked. Domain '${url.hostname}' is not in the whitelist.`);
          }
        }
      } catch (e: any) {
        if (e.message.includes("RAE GUARD")) throw e;
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
