import CryptoJS from "crypto-js";
import { Stack } from "./stack.js";
import secp256k1 from "secp256k1";

export function verifyP2PKHScript(
  prevout,
  scriptsig,
  scriptsig_asm,
  messageHash
) {
  const stack = new Stack();
  const { scriptpubkey_asm } = prevout;

  const prevoutScriptAsm = scriptpubkey_asm.split(" ");
  const scriptSigAsm = scriptsig_asm.split(" ");

  const signatureHex = scriptSigAsm[1];
  const publicKeyHex = scriptSigAsm[3];

  stack.push(signatureHex);
  stack.push(publicKeyHex);
  let flag = false;
  prevoutScriptAsm.forEach((instruction, index) => {
    if (instruction === "OP_DUP") {
      stack.push(stack.peek());
    } else if (instruction === "OP_HASH160") {
      const value = stack.pop();
      const SHA256hash = CryptoJS.SHA256(
        CryptoJS.enc.Hex.parse(value)
      ).toString();
      const RIPEMD160hash = CryptoJS.RIPEMD160(
        CryptoJS.enc.Hex.parse(SHA256hash)
      ).toString();

      stack.push(RIPEMD160hash);
    } else if (instruction === "OP_EQUALVERIFY") {
      const hash1 = stack.pop();
      const hash2 = stack.pop();
      if (hash1 !== hash2) {
        throw new Error("Hashes do not match");
      }
    } else if (instruction === "OP_CHECKSIG") {
      const publicKeyHex = stack.pop();
      const DEREncodedSignatureHex = stack.pop();

      const publicKeyBuffer = Buffer.from(publicKeyHex, "hex");
      const { r, s } = derToRS(DEREncodedSignatureHex);
      if (r === undefined || s === undefined) {
        return false;
      }
      let signature = Buffer.from(r + s, "hex");
      if (signature.length !== 64) {
        signature = Buffer.concat([
          Buffer.alloc(64 - signature.length, 0),
          signature,
        ]);
      }
      const result = secp256k1.ecdsaVerify(
        signature,
        Buffer.from(messageHash, "hex"),
        publicKeyBuffer
      );

      if (!result) {
        // console.log("Signature is invalid");
        return flag=false
      } else {
        stack.push("1");
        // console.log("Signature is valid");
        return flag=true
      }
    } else if (instruction.startsWith("OP_PUSHBYTES_")) {
      index++;
      const value = prevoutScriptAsm[index];
      stack.push(value);
    }
    // console.log(stack.size(), instruction, stack.printStack());
  });
  return flag
}

export function derToRS(DEREncodedSignatureHex) {
  let r, s;
  if (DEREncodedSignatureHex.length === 144) {
    r = DEREncodedSignatureHex.substr(10, 64);
    s = DEREncodedSignatureHex.substr(78, 64);
  }
  if (DEREncodedSignatureHex.length === 142) {
    r = DEREncodedSignatureHex.substr(8, 64);
    s = DEREncodedSignatureHex.substr(76, 64);
  }
  // implement for 71 bytes also
  if (r !== undefined && s !== undefined) {
    r = BigInt(`0x${r}`).toString(16);
    s = BigInt(`0x${s}`).toString(16);
    return { r, s };
  } else {
    return { r: undefined, s: undefined };
  }
}
