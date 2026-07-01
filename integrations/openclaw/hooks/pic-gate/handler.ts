/**
 * pic-gate — PIC Standard pre-execution gate for OpenClaw.
 *
 * Hook: before_tool_call (priority 100)
 *
 * Sends the tool call (including any __pic proposal in params) to the PIC
 * HTTP bridge for verification.
 *
 * - allowed  → strips __pic from params, tool proceeds
 * - blocked  → returns { block: true, blockReason } — NEVER throws
 * - bridge unreachable → blocked (fail-closed)
 *
 * IMPORTANT: Config comes from pluginConfig closure (captured in register()),
 * NOT from ctx.pluginConfig (which doesn't exist in hook contexts).
 */

import { verifyToolCall } from "../../lib/pic-client.js";
import type { PICPluginConfig } from "../../lib/types.js";
import { DEFAULT_CONFIG } from "../../lib/types.js";

/** Real shape of before_tool_call event (from OpenClaw src/plugins/types.ts). */
interface BeforeToolCallEvent {
    toolName: string;
    params: Record<string, unknown>;
}

/** Real return type for before_tool_call hook. */
type BeforeToolCallReturn =
    { block: true; blockReason: string } | { params: Record<string, unknown> } | void;

/**
 * Resolve plugin config from captured pluginConfig (closure from register()).
 */
function resolveConfig(pluginConfig: Record<string, unknown>): PICPluginConfig {
    return {
        bridge_url:
            typeof pluginConfig.bridge_url === "string"
                ? pluginConfig.bridge_url
                : DEFAULT_CONFIG.bridge_url,
        bridge_timeout_ms:
            typeof pluginConfig.bridge_timeout_ms === "number"
                ? pluginConfig.bridge_timeout_ms
                : DEFAULT_CONFIG.bridge_timeout_ms,
        log_level:
            pluginConfig.log_level === "debug" ||
            pluginConfig.log_level === "info" ||
            pluginConfig.log_level === "warn"
                ? pluginConfig.log_level
                : DEFAULT_CONFIG.log_level,
    };
}

/**
 * Factory: creates the before_tool_call handler with captured plugin config.
 */
export function createPicGateHandler(
    pluginConfig: Record<string, unknown>
): (event: BeforeToolCallEvent, ctx: Record<string, unknown>) => Promise<BeforeToolCallReturn> {
    return async function handler(
        event: BeforeToolCallEvent,
        _ctx: Record<string, unknown>
    ): Promise<BeforeToolCallReturn> {
        const config = resolveConfig(pluginConfig);

        // Defensive: ensure params is an object (fail-closed if malformed event)
        const params = event.params ?? {};
        if (typeof params !== "object" || params === null) {
            return { block: true, blockReason: "PIC gate: malformed event (params not an object)" };
        }

        // Defensive: ensure toolName is a non-empty string
        const toolName = event.toolName;
        if (typeof toolName !== "string" || toolName.trim() === "") {
            return {
                block: true,
                blockReason: "PIC gate: malformed event (toolName missing or empty)",
            };
        }

        // ── Verify against PIC bridge ──────────────────────────────────────
        const result = await verifyToolCall(toolName, params, config);

        // ── Blocked ────────────────────────────────────────────────────────
        if (!result.allowed) {
            const reason = result.error?.message ?? "PIC contract violation (no details)";

            if (config.log_level === "debug" || config.log_level === "info") {
                console.log(`[pic-gate] BLOCKED tool=${toolName} reason="${reason}"`);
            }

            return { block: true, blockReason: reason };
        }

        // ── Allowed — strip __pic metadata before tool executes ────────────
        const { __pic, __pic_request_id, ...cleanParams } = params as Record<string, unknown> & {
            __pic?: unknown;
            __pic_request_id?: unknown;
        };

        if (config.log_level === "debug") {
            console.debug(`[pic-gate] ALLOWED tool=${toolName} eval_ms=${result.eval_ms}`);
        }

        return { params: cleanParams };
    };
}
