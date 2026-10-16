/**
 * PIC HTTP Bridge client – fail-closed HTTP client for the PIC verifier.
 *
 * Calls POST /verify on the Python-side bridge and returns a typed response.
 * On ANY failure (timeout, connection refused, malformed response) the client
 * returns { allowed: false } — never throws.
 */

import type {
    PICErrorCode,
    PICError,
    PICVerifyResponse,
    PICVerifyRequest,
    PICPluginConfig,
} from "./types.js";
import { DEFAULT_CONFIG } from "./types.js";

/** Valid PIC error codes for runtime validation. */
const VALID_ERROR_CODES: readonly PICErrorCode[] = [
    "PIC_INVALID_REQUEST",
    "PIC_LIMIT_EXCEEDED",
    "PIC_SCHEMA_INVALID",
    "PIC_DUPLICATE_ID",
    "PIC_VERIFIER_FAILED",
    "PIC_TOOL_BINDING_MISMATCH",
    "PIC_ARG_BINDING_MISMATCH",
    "PIC_EVIDENCE_REQUIRED",
    "PIC_EVIDENCE_FAILED",
    "PIC_POLICY_VIOLATION",
    "PIC_INTERNAL_ERROR",
    "PIC_BRIDGE_UNREACHABLE",
];

// TODO: Future telemetry hook point
// - count of failed bridge calls
// - average eval_ms
// - distribution of error.code values

/**
 * Verify a tool call against the PIC HTTP bridge.
 *
 * @param toolName  - The tool being invoked (e.g. "exec", "write_file").
 * @param toolArgs  - Full tool arguments (should include __pic if the agent provided one).
 * @param config    - Plugin configuration (bridge URL, timeout).
 * @returns           PICVerifyResponse — always resolves, never rejects.
 */
export async function verifyToolCall(
    toolName: string,
    toolArgs: Record<string, unknown>,
    config: PICPluginConfig = DEFAULT_CONFIG
): Promise<PICVerifyResponse> {
    const body: PICVerifyRequest = {
        tool_name: toolName,
        tool_args: toolArgs,
    };

    if (config.log_level === "debug") {
        console.debug(`[pic-client] POST ${config.bridge_url}/verify tool=${toolName}`);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.bridge_timeout_ms);

    try {
        const resp = await fetch(`${config.bridge_url}/verify`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
            signal: controller.signal,
        });

        // Fail-closed on HTTP errors (5xx, 4xx, etc.)
        if (!resp.ok) {
            return failClosed(`Bridge returned HTTP ${resp.status}`);
        }

        const json = (await resp.json()) as Record<string, unknown>;

        // Sanity-check the response shape
        if (typeof json.allowed !== "boolean") {
            console.warn(`[pic-client] Malformed response: ${JSON.stringify(json)}`);
            return failClosed("Malformed bridge response: missing 'allowed'");
        }

        // Normalize eval_ms
        const eval_ms = typeof json.eval_ms === "number" ? json.eval_ms : 0;

        if (json.allowed === true) {
            // Success case: allowed: true, error: null
            if (config.log_level === "debug") {
                console.debug(`[pic-client] result: allowed=true eval_ms=${eval_ms}`);
            }
            return { allowed: true, error: null, eval_ms };
        }

        // Denial case: allowed: false, error: PICError
        const error = json.error as Record<string, unknown> | null | undefined;
        if (!error || typeof error.code !== "string") {
            console.warn(`[pic-client] Malformed denial response: ${JSON.stringify(json)}`);
            return failClosed("Malformed bridge response: denial missing error code");
        }
        if (!VALID_ERROR_CODES.includes(error.code as PICErrorCode)) {
            console.warn(`[pic-client] Unknown error code: ${error.code}`);
            return failClosed(`Malformed bridge response: unknown error code '${error.code}'`);
        }

        const picError: PICError = {
            code: error.code as PICErrorCode,
            message: typeof error.message === "string" ? error.message : "Unknown error",
            details:
                typeof error.details === "object"
                    ? (error.details as Record<string, unknown>)
                    : undefined,
        };

        if (config.log_level === "debug") {
            console.debug(
                `[pic-client] result: allowed=false eval_ms=${eval_ms} code=${picError.code}`
            );
        }

        return { allowed: false, error: picError, eval_ms };
    } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Unknown bridge error";
        return failClosed(message);
    } finally {
        clearTimeout(timeout);
    }
}

/**
 * Fail-closed helper: returns a block response when the bridge is unreachable
 * or returns garbage.  This ensures the plugin never silently allows a tool
 * call just because the bridge is down.
 */
function failClosed(reason: string): PICVerifyResponse {
    return {
        allowed: false,
        error: {
            code: "PIC_BRIDGE_UNREACHABLE",
            message: `PIC bridge error: ${reason}`,
        },
        eval_ms: 0,
    };
}
