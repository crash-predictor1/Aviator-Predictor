// Minimal placeholder for sha.d.ts to satisfy Rollup in CI.
// Replace with real type declarations later.

export type HashInput = string | Uint8Array;
export function sha256(input: HashInput): string;
export function sha1(input: HashInput): string;
export function sha512(input: HashInput): string;
