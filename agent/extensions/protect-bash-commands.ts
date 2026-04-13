import type { ExtensionAPI } from "@mariozechner/pi-coding-agent"
import { isToolCallEventType } from "@mariozechner/pi-coding-agent"

/**
 * Security hook:
 *
 * - Blocks dangerous bash commands (rm -rf, sudo, chmod 777, etc.)
 * - Blocks bash writes to sensitive files (.dev.vars, .pem, .key)
 * - Prompts for confirmation on suspicious bash writes to .env files
 *
 * Note: regex-based blocking cannot catch encoded/eval'd commands (e.g.
 * `bash -c "rm -rf /"`). This is a known limitation.
 *
 * This is my first extension I'm writing (really customizing) for pi.  It is
 * HEAVILY inspired by https://github.com/michalvavra/agents/blob/main/agents/pi/extensions/security.ts
 * (revision e9b00e3). The main changes I've made are:
 *
 * - jj directory protection
 * - Make env files soft protected instead of protected
 */
export default function (pi: ExtensionAPI) {
  const dangerousCommands = [
    { pattern: /\brm\s+(-[^\s]*r|--recursive)/, desc: "recursive delete" }, // rm -rf, rm -r, rm --recursive
    { pattern: /\bsudo\b/, desc: "sudo command" }, // sudo anything
    { pattern: /\b(chmod|chown)\b.*777/, desc: "dangerous permissions" }, // chmod 777, chown 777
    { pattern: /\bmkfs\b/, desc: "filesystem format" }, // mkfs.ext4, mkfs.xfs
    { pattern: /\bdd\b.*\bof=\/dev\//, desc: "raw device write" }, // dd if=x of=/dev/sda
    { pattern: />\s*\/dev\/sd[a-z]/, desc: "raw device overwrite" }, // echo x > /dev/sda
    { pattern: /\bkill\s+-9\s+-1\b/, desc: "kill all processes" }, // kill -9 -1
    { pattern: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/, desc: "fork bomb" }, // :(){:|:&};:    
  ];

  const shellPath = (filePattern: string) =>
    `(?:["'][^"']*${filePattern}[^"']*["']|(?:\\.?\\/)?(?:[^\\s"'|;&]+\\/)*${filePattern})`;

  const redirectWrite = (filePattern: string) => new RegExp(`>>?\\s*${shellPath(filePattern)}`);
  const teeWrite = (filePattern: string) => new RegExp(`\\btee\\b(?:\\s+-\\S+)*\\s+${shellPath(filePattern)}`);
  const copyOrMoveWrite = (command: "cp" | "mv", filePattern: string) =>
    new RegExp(`\\b${command}\\b(?:\\s+-\\S+)*\\s+.+\\s+${shellPath(filePattern)}(?=\\s*(?:$|[|;&]))`);

  const dangerousBashWrites = [
    redirectWrite(`\\.dev\\.vars(?:\\b|$)`),
    redirectWrite(`[^\\s"'|;&]*\\.pem(?:\\b|$)`),
    redirectWrite(`[^\\s"'|;&]*\\.key(?:\\b|$)`),
    teeWrite(`\\.dev\\.vars(?:\\b|$)`),
    teeWrite(`[^\\s"'|;&]*\\.pem(?:\\b|$)`),
    teeWrite(`[^\\s"'|;&]*\\.key(?:\\b|$)`),
    copyOrMoveWrite("cp", `\\.dev\\.vars(?:\\b|$)`),
    copyOrMoveWrite("cp", `[^\\s"'|;&]*\\.pem(?:\\b|$)`),
    copyOrMoveWrite("cp", `[^\\s"'|;&]*\\.key(?:\\b|$)`),
    copyOrMoveWrite("mv", `\\.dev\\.vars(?:\\b|$)`),
    copyOrMoveWrite("mv", `[^\\s"'|;&]*\\.pem(?:\\b|$)`),
    copyOrMoveWrite("mv", `[^\\s"'|;&]*\\.key(?:\\b|$)`),
  ];

  const suspiciousBashWrites = [
    { pattern: redirectWrite(`\\.env(?!\\.example)(?:\\.[^\\s"'|;&]+)*`), desc: "write to .env file" },
    { pattern: teeWrite(`\\.env(?!\\.example)(?:\\.[^\\s"'|;&]+)*`), desc: "write to .env file" },
    { pattern: copyOrMoveWrite("cp", `\\.env(?!\\.example)(?:\\.[^\\s"'|;&]+)*`), desc: "write to .env file" },
    { pattern: copyOrMoveWrite("mv", `\\.env(?!\\.example)(?:\\.[^\\s"'|;&]+)*`), desc: "write to .env file" },
  ];

  /*
   * Ensure that the bash command isn't in our list of blocked or suspicious commands.  If
   * it is suspicious, raise a dialog to make sure it can be run.
   */
  pi.on("tool_call", async (event, ctx) => {
    if (isToolCallEventType("bash", event)) {
      const command = event.input.command as string;

      for (const {pattern, desc} of dangerousCommands) {
        if (pattern.test(command)) {
          return {block: true, reason: `Blocked ${desc} by user`};
          break;
        }
      }

      for (const {pattern, desc} of suspiciousBashWrites) {
        if (pattern.test(command)) {
          if (!ctx.hasUI) {
            return {block: true, reason: `Blocked ${desc} (no UI to confirm)`};
          }

          const ok = await ctx.ui.confirm(`⚠️ Dangerous command: ${desc}`, command);

          if (!ok) {
            return {block: true, reason: `Blocked ${desc} by user`};
          }

          break;
        }
      }

      for (const pattern of dangerousBashWrites) {
        if (pattern.test(command)) {
          if (!ctx.hasUI) {
            return {block: true, reason: "Bash command writes to protected path"};
          }

          ctx.ui.notify(`🛡️ Blocked bash write to protected path`, "warning");
          return {block: true, reason: "Bash command writes to protected path"};
        }
      }

      return undefined;
    }
  });
}
