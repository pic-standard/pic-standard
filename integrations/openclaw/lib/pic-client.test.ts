/**
 * Tests for pic-client.ts — the fail-closed HTTP client.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { verifyToolCall } from "./pic-client.js";
import { DEFAULT_CONFIG } from "./types.js";

describe("verifyToolCall", () => {
    beforeEach(() => {
        vi.stubGlobal("fetch", vi.fn());
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it("returns allowed: true when bridge approves", async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({ allowed: true, error: null, eval_ms: 5 }),
        };
        vi.mocked(fetch).mockResolvedValue(mockResponse as Response);

        const result = await verifyToolCall("test_tool", { arg: "value" }, DEFAULT_CONFIG);

        expect(result.allowed).toBe(true);
        expect(result.eval_ms).toBe(5);
    });

    it("returns allowed: false when bridge denies", async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({
                allowed: false,
                error: { code: "PIC_POLICY_VIOLATION", message: "Denied" },
                eval_ms: 3,
            }),
        };
        vi.mocked(fetch).mockResolvedValue(mockResponse as Response);

        const result = await verifyToolCall("test_tool", { arg: "value" }, DEFAULT_CONFIG);

        expect(result.allowed).toBe(false);
        expect(result.error?.code).toBe("PIC_POLICY_VIOLATION");
    });

    it("fails closed when bridge returns HTTP error", async () => {
        const mockResponse = {
            ok: false,
            status: 500,
        };
        vi.mocked(fetch).mockResolvedValue(mockResponse as Response);

        const result = await verifyToolCall("test_tool", { arg: "value" }, DEFAULT_CONFIG);

        expect(result.allowed).toBe(false);
        expect(result.error?.code).toBe("PIC_BRIDGE_UNREACHABLE");
        expect(result.error?.message).toContain("HTTP 500");
    });

    it("fails closed when fetch throws (network error)", async () => {
        vi.mocked(fetch).mockRejectedValue(new Error("Connection refused"));

        const result = await verifyToolCall("test_tool", { arg: "value" }, DEFAULT_CONFIG);

        expect(result.allowed).toBe(false);
        expect(result.error?.code).toBe("PIC_BRIDGE_UNREACHABLE");
        expect(result.error?.message).toContain("Connection refused");
    });

    it("fails closed when response is malformed (missing allowed)", async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({ eval_ms: 5 }), // missing 'allowed'
        };
        vi.mocked(fetch).mockResolvedValue(mockResponse as Response);

        const result = await verifyToolCall("test_tool", { arg: "value" }, DEFAULT_CONFIG);

        expect(result.allowed).toBe(false);
        expect(result.error?.code).toBe("PIC_BRIDGE_UNREACHABLE");
        expect(result.error?.message).toContain("missing 'allowed'");
    });

    it("fails closed when denial is missing error code", async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({ allowed: false, eval_ms: 5 }), // missing error.code
        };
        vi.mocked(fetch).mockResolvedValue(mockResponse as Response);

        const result = await verifyToolCall("test_tool", { arg: "value" }, DEFAULT_CONFIG);

        expect(result.allowed).toBe(false);
        expect(result.error?.code).toBe("PIC_BRIDGE_UNREACHABLE");
        expect(result.error?.message).toContain("denial missing error code");
    });

    it("defaults eval_ms to 0 when not a number", async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({ allowed: true, error: null, eval_ms: "not-a-number" }),
        };
        vi.mocked(fetch).mockResolvedValue(mockResponse as Response);

        const result = await verifyToolCall("test_tool", { arg: "value" }, DEFAULT_CONFIG);

        expect(result.allowed).toBe(true);
        expect(result.eval_ms).toBe(0);
    });

    it("defaults eval_ms to 0 when eval_ms is numeric string", async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({ allowed: true, error: null, eval_ms: "5" }),
        };
        vi.mocked(fetch).mockResolvedValue(mockResponse as Response);

        const result = await verifyToolCall("test_tool", { arg: "value" }, DEFAULT_CONFIG);

        expect(result.allowed).toBe(true);
        expect(result.eval_ms).toBe(0); // "5" is not typeof number, so defaults to 0
    });

    it("fails closed when denial has unknown error code", async () => {
        const mockResponse = {
            ok: true,
            json: async () => ({
                allowed: false,
                error: { code: "UNKNOWN_CODE", message: "Some error" },
                eval_ms: 5,
            }),
        };
        vi.mocked(fetch).mockResolvedValue(mockResponse as Response);

        const result = await verifyToolCall("test_tool", { arg: "value" }, DEFAULT_CONFIG);

        expect(result.allowed).toBe(false);
        expect(result.error?.code).toBe("PIC_BRIDGE_UNREACHABLE");
        expect(result.error?.message).toContain("unknown error code");
    });

    it.each(["PIC_ARG_BINDING_MISMATCH", "PIC_DUPLICATE_ID"])(
        "accepts mirrored denial error code %s (not remapped to bridge-unreachable)",
        async (code) => {
            const mockResponse = {
                ok: true,
                json: async () => ({
                    allowed: false,
                    error: { code, message: "Denied" },
                    eval_ms: 4,
                }),
            };
            vi.mocked(fetch).mockResolvedValue(mockResponse as Response);

            const result = await verifyToolCall("test_tool", { arg: "value" }, DEFAULT_CONFIG);

            expect(result.allowed).toBe(false);
            expect(result.error?.code).toBe(code);
        }
    );
});
