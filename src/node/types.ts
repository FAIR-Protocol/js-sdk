import type { Token } from "../common/types";
export interface NodeToken extends Token {
  getPublicKey(): string | Buffer;
}
