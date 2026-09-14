/**
 * PIC Standard – TypeScript types for the HTTP bridge protocol.
 *
 * These mirror the Python-side contracts defined in:
 *   sdk-python/pic_standard/integrations/http_bridge.py
 *   sdk-python/pic_standard/errors.py         (PICErrorCode)
 *
 * Verification logic lives in sdk-python/pic_standard/pipeline.py
 */

// -----------------------------------------------------------------
// Error codes (from sdk-python/pic_standard/errors.py)
// -----------------------------------------------------------------

/**
 * Error codes exposed to TypeScript consumers.
 *
 * Mirrors PICErrorCode enum in sdk-python/pic_standard/errors.py.
 * See docs/ERRORS.md in the pic-standard repo for the authoritative
 * reference (retryability, HTTP mapping, example wire shape).
 *
 * PIC_BRIDGE_UNREACHABLE is a client-side-only value emitted by this
 * package when the HTTP bridge cannot be reached at all (network or
 * socket layer). It is NOT emitted by the Python guard; do not treat
 * it as a PIC protocol error.
 *
 * When PICErrorCode gains a new value in Python, add the matching
 * string literal here in the same PR.
 */
export type PICErrorCode =
    | "PIC_INVALID_REQUEST"
    | "PIC_LIMIT_EXCEEDED"
    | "PIC_SCHEMA_INVALID"
    | "PIC_VERIFIER_FAILED"
    | "PIC_TOOL_BINDING_MISMATCH"
    | "PIC_EVIDENCE_REQUIRED"
    | "PIC_EVIDENCE_FAILED"
    | "PIC_POLICY_VIOLATION"
    | "PIC_INTERNAL_ERROR"
    | "PIC_BRIDGE_UNREACHABLE"; // Client-side error (not from Python)

// -----------------------------------------------------------------
// Bridge request / response
// -----------------------------------------------------------------

/** Body sent to POST /verify on the PIC HTTP bridge. */
export interface PICVerifyRequest {
    tool_name: string;
    tool_args: Record<string, unknown>;
}

/** Structured error returned when allowed === false. */
export interface PICError {
    code: PICErrorCode;
    message: string;
    details?: Record<string, unknown>; // only present when PIC_DEBUG=1
}

/**
 * Response from POST /verify. Always 200 — decision is in `allowed`.
 *
 * Modeled as a discriminated union to match the wire format:
 * - allowed: true  → error: null
 * - allowed: false → error: PICError
 */
export type PICVerifyResponse =
    | { allowed: true; error: null; eval_ms: number }
    | { allowed: false; error: PICError; eval_ms: number };

// -----------------------------------------------------------------
// Plugin configuration
// -----------------------------------------------------------------

/** Configuration for the pic-guard OpenClaw plugin. */
export interface PICPluginConfig {
    /** URL of the PIC HTTP bridge (default: "http://127.0.0.1:7580"). */
    bridge_url: string;

    /** HTTP timeout in milliseconds (default: 500). */
    bridge_timeout_ms: number;

    /** Log level: "debug" | "info" | "warn" (default: "info"). */
    log_level: "debug" | "info" | "warn";
}

/** Sensible defaults matching PICEvaluateLimits on the Python side. */
export const DEFAULT_CONFIG: PICPluginConfig = {
    bridge_url: "http://127.0.0.1:7580",
    bridge_timeout_ms: 500,
    log_level: "info",
};
