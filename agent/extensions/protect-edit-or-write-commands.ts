import type { ExtensionAPI } from "@mariozechner/pi-coding-agent"
import { isToolCallEventType } from "@mariozechner/pi-coding-agent"
import * as path from "node:path" 

/**
 * Protects sensitive paths from writes (.env, node_modules, .git, jj)
 */
export default function (pi: ExtensionAPI) {
  const protectedPaths = [
    { pattern: /\.dev\.vars($|\.[^/]+$)/, desc: "dev vars file" }, // .dev.vars
    { pattern: /node_modules\//, desc: "node_modules" }, // node_modules/
    { pattern: /^\.git\/|\/\.git\//, desc: "git directory" }, // .git/
    { pattern: /^\.jj\/|\/\.jj\//, desc: "jj directory" }, // .jj/
    { pattern: /\.pem$|\.key$/, desc: "private key file" }, // *.pem, *.key
    { pattern: /id_rsa|id_ed25519|id_ecdsa/, desc: "SSH key" }, // id_rsa, id_ed25519
    { pattern: /\.ssh\//, desc: ".ssh directory" }, // .ssh/
    { pattern: /secrets?\.(json|ya?ml|toml)$/i, desc: "secrets file" }, // secrets.json, secret.yaml
    { pattern: /(?:^|\/)credentials(?:\.[^/]+)?$/i, desc: "credentials file" }, // credentials, credentials.json (filename only, not source files containing the word)
  ];

  const softProtectedPaths = [
    { pattern: /\.env($|\.(?!example))/i, desc: "environment file" }, // .env, .env.local (but not .env.example or .env.EXAMPLE)
    { pattern: /package-lock\.json$/, desc: "package-lock.json" },
    { pattern: /yarn\.lock$/, desc: "yarn.lock" },
    { pattern: /pnpm-lock\.yaml$/, desc: "pnpm-lock.yaml" },
  ];

  /*
   * Ensure that write or edit command isn't writing to something we want to protect.  If it's suspicious, ask for
   * permission.
   */
  pi.on("tool_call", async (event, ctx) => {
    if (isToolCallEventType("write", event) || isToolCallEventType("edit", event)) {
      const filePath = event.input.path;
      if (typeof filePath !== "string" || !filePath) return undefined;
      const normalizedPath = path.normalize(filePath.replace(/^@/, ""));

      for (const { pattern, desc } of protectedPaths) {
        if (pattern.test(normalizedPath)) {
          ctx.ui.notify(`🛡️ Blocked write to ${desc}: ${filePath}`, "warning");
          return { block: true, reason: `Protected path: ${desc}` };
        }
      }

      for (const { pattern, desc } of softProtectedPaths) {
        if (pattern.test(normalizedPath)) {
          if (!ctx.hasUI) {
            return { block: true, reason: `Protected path (no UI): ${desc}` };
          }

          const ok = await ctx.ui.confirm(
              `⚠️ Modifying ${desc}`,
              `Are you sure you want to modify ${filePath}?`,
          );

          if (!ok) {
            return { block: true, reason: `User blocked write to ${desc}` };
          }
          break;
        }
      }
    }

    return undefined;
  });
}
