import { getStrConverter, getOutputConverter } from "./converters";

import {
  FormatType,
  EncodingType,
  FixedLengthOptionsEncodingType,
  FixedLengthOptionsNoEncodingType,
  FormatNoTextType,
  packedValue,
  GenericInputType,
} from "./custom_types";

export const TWO_PWR_32 = 4294967296;

/* SHA-2 constant table */
export const SHA2_K = (() => {
  // Cloned list to prevent accidental mutations
  const table = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  return table.slice();
})();

/* Initial values for truncated variants */
export const H_trunc = [
  0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
  0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
];

/* Initial values for full SHA-256/512 families */
export const H_full = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

export const sha_variant_error = "Chosen SHA variant is not supported";
export const mac_rounds_error = "Cannot set numRounds with MAC";

/**
 * Joins two packed arrays in little-endian. Mutates the first array.
 *
 * @param a First packed value.
 * @param b Second packed value.
 * @returns Combined structure (a + b).
 */
export function packedLEConcat(a: packedValue, b: packedValue): packedValue {
  let i, arrOffset;
  const aBytes = a.binLen >>> 3;
  const bBytes = b.binLen >>> 3;
  const leftShift = aBytes << 3;
  const rightShift = (4 - aBytes) << 3;

  // Fast path: simple concat when byte alignment matches
  if (aBytes % 4 !== 0) {
    for (i = 0; i < bBytes; i += 4) {
      arrOffset = (aBytes + i) >>> 2;
      a.value[arrOffset] |= b.value[i >>> 2] << leftShift;
      a.value.push(0);
      a.value[arrOffset + 1] |= b.value[i >>> 2] >>> rightShift;
    }

    // Trim last word if unnecessary
    if ((a.value.length << 2) - 4 >= bBytes + aBytes) {
      a.value.pop();
    }

    return { value: a.value, binLen: a.binLen + b.binLen };
  }

  return { value: a.value.concat(b.value), binLen: a.binLen + b.binLen };
}

/**
 * Ensures output formatting object contains valid fields.
 *
 * @param options Output formatting preferences.
 */
export function getOutputOpts(options?: {
  outputUpper?: boolean;
  b64Pad?: string;
  shakeLen?: number;
  outputLen?: number;
}): { outputUpper: boolean; b64Pad: string; outputLen: number } {
  const normalized = { outputUpper: false, b64Pad: "=", outputLen: -1 };
  const user = options || {};
  const lenErr = "Output length must be a multiple of 8";

  normalized.outputUpper = user.outputUpper || false;

  if (user.b64Pad) normalized.b64Pad = user.b64Pad;

  if (user.outputLen) {
    if (user.outputLen % 8 !== 0) throw new Error(lenErr);
    normalized.outputLen = user.outputLen;
  } else if (user.shakeLen) {
    if (user.shakeLen % 8 !== 0) throw new Error(lenErr);
    normalized.outputLen = user.shakeLen;
  }

  if (typeof normalized.outputUpper !== "boolean") {
    throw new Error("Invalid outputUpper formatting option");
  }
  if (typeof normalized.b64Pad !== "string") {
    throw new Error("Invalid b64Pad formatting option");
  }

  return normalized;
}

/**
 * Convert external input constructor into packed format.
 */
export function parseInputOption(
  key: string,
  value: GenericInputType | undefined,
  endian: -1 | 1,
  fallback?: packedValue
): packedValue {
  const err = key + " must include a value and format";

  if (!value) {
    if (!fallback) throw new Error(err);
    return fallback;
  }

  if (value.value === undefined || !value.format) {
    throw new Error(err);
  }

  return getStrConverter(
    value.format,
    (value as any).encoding || "UTF8",
    endian
  )(value.value);
}

export abstract class jsSHABase<StateT, VariantT> {
  protected readonly shaVariant: VariantT;
  protected readonly inputFormat: FormatType;
  protected readonly utfType: EncodingType;
  protected readonly numRounds: number;

  protected abstract intermediateState: StateT;
  protected keyWithIPad: number[];
  protected keyWithOPad: number[];
  protected remainder: number[];
  protected remainderLen: number;
  protected updateCalled: boolean;
  protected processedLen: number;
  protected macKeySet: boolean;

  protected abstract readonly variantBlockSize: number;
  protected abstract readonly bigEndianMod: -1 | 1;
  protected abstract readonly outputBinLen: number;
  protected abstract readonly isVariableLen: boolean;
  protected abstract readonly HMACSupported: boolean;

  protected abstract readonly converterFunc: (
    input: any,
    existingBin: number[],
    existingBinLen: number
  ) => packedValue;

  protected abstract readonly roundFunc: (
    block: number[],
    H: StateT
  ) => StateT;

  protected abstract readonly finalizeFunc: (
    remainder: number[],
    remainderBinLen: number,
    processedBinLen: number,
    H: StateT,
    outputLen: number
  ) => number[];

  protected abstract readonly stateCloneFunc: (state: StateT) => StateT;
  protected abstract readonly newStateFunc: (variant: VariantT) => StateT;
  protected abstract readonly getMAC: ((options: { outputLen: number }) => number[]) | null;

  protected constructor(variant: VariantT, inputFormat: "TEXT", options?: FixedLengthOptionsEncodingType);
  protected constructor(variant: VariantT, inputFormat: FormatNoTextType, options?: FixedLengthOptionsNoEncodingType);
  protected constructor(variant: any, inputFormat: any, options?: any) {
    const inputOpts = options || {};
    this.inputFormat = inputFormat;
    this.utfType = inputOpts.encoding || "UTF8";
    this.numRounds = inputOpts.numRounds || 1;

    if (isNaN(this.numRounds) || this.numRounds !== parseInt(this.numRounds, 10) || this.numRounds < 1) {
      throw new Error("numRounds must a integer >= 1");
    }

    this.shaVariant = variant;
    this.remainder = [];
    this.remainderLen = 0;
    this.updateCalled = false;
    this.processedLen = 0;
    this.macKeySet = false;
    this.keyWithIPad = [];
    this.keyWithOPad = [];
  }

  /**
   * Process as many chunks as possible from input and save remainder.
   */
  update(src: string | ArrayBuffer | Uint8Array): this {
    let consumed = 0;
    const step = this.variantBlockSize >>> 5;

    const converted = this.converterFunc(src, this.remainder, this.remainderLen);
    const totalBits = converted.binLen;
    const chunk = converted.value;
    const chunkInts = totalBits >>> 5;

    for (let i = 0; i < chunkInts; i += step) {
      if (consumed + this.variantBlockSize <= totalBits) {
        this.intermediateState = this.roundFunc(chunk.slice(i, i + step), this.intermediateState);
        consumed += this.variantBlockSize;
      }
    }

    this.processedLen += consumed;
    this.remainder = chunk.slice(consumed >>> 5);
    this.remainderLen = totalBits % this.variantBlockSize;
    this.updateCalled = true;

    return this;
  }

  /**
   * Produce final hash value.
   */
  // Overloads left unchanged
  getHash(format: any, options?: any): any {
    let i;
    let finalState;
    let outLen = this.outputBinLen;

    const outOpts = getOutputOpts(options);

    if (this.isVariableLen) {
      if (outOpts.outputLen === -1) throw new Error("Output length must be specified in options");
      outLen = outOpts.outputLen;
    }

    const outFunc = getOutputConverter(format, outLen, this.bigEndianMod, outOpts);

    if (this.macKeySet && this.getMAC) {
      return outFunc(this.getMAC(outOpts));
    }

    finalState = this.finalizeFunc(
      this.remainder.slice(),
      this.remainderLen,
      this.processedLen,
      this.stateCloneFunc(this.intermediateState),
      outLen
    );

    for (i = 1; i < this.numRounds; i++) {
      if (this.isVariableLen && outLen % 32 !== 0) {
        finalState[finalState.length - 1] &= 0x00ffffff >>> (24 - (outLen % 32));
      }
      finalState = this.finalizeFunc(
        finalState,
        outLen,
        0,
        this.newStateFunc(this.shaVariant),
        outLen
      );
    }

    return outFunc(finalState);
  }

  /**
   * Configure HMAC key — must be called before update().
   */
  setHMACKey(key: any, inputFormat: any, options?: any): void {
    if (!this.HMACSupported) throw new Error("Variant does not support HMAC");
    if (this.updateCalled) throw new Error("Cannot set MAC key after calling update");

    const keyOpts = options || {};
    const conv = getStrConverter(inputFormat, keyOpts.encoding || "UTF8", this.bigEndianMod);

    this._setHMACKey(conv(key));
  }

  protected _setHMACKey(key: packedValue): void {
    const blockBytes = this.variantBlockSize >>> 3;
    const lastIdx = blockBytes / 4 - 1;

    if (this.numRounds !== 1) throw new Error(mac_rounds_error);
    if (this.macKeySet) throw new Error("MAC key already set");

    if (blockBytes < key.binLen / 8) {
      key.value = this.finalizeFunc(
        key.value,
        key.binLen,
        0,
        this.newStateFunc(this.shaVariant),
        this.outputBinLen
      );
    }

    while (key.value.length <= lastIdx) key.value.push(0);

    for (let i = 0; i <= lastIdx; i++) {
      this.keyWithIPad[i] = key.value[i] ^ 0x36363636;
      this.keyWithOPad[i] = key.value[i] ^ 0x5c5c5c5c;
    }

    this.intermediateState = this.roundFunc(this.keyWithIPad, this.intermediateState);
    this.processedLen = this.variantBlockSize;
    this.macKeySet = true;
  }

  /**
   * Return HMAC result using previously-set key.
   */
  getHMAC(format: any, options?: any): any {
    const opts = getOutputOpts(options);
    const f = getOutputConverter(format, this.outputBinLen, this.bigEndianMod, opts);
    return f(this._getHMAC());
  }

  protected _getHMAC(): number[] {
    if (!this.macKeySet) throw new Error("Cannot call getHMAC without first setting MAC key");

    const first = this.finalizeFunc(
      this.remainder.slice(),
      this.remainderLen,
      this.processedLen,
      this.stateCloneFunc(this.intermediateState),
      this.outputBinLen
    );

    let out = this.roundFunc(this.keyWithOPad, this.newStateFunc(this.shaVariant));
    out = this.finalizeFunc(first, this.outputBinLen, this.variantBlockSize, out, this.outputBinLen);

    return out;
  }
}
