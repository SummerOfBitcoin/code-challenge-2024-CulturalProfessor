import CryptoJS from "crypto-js";
import { Stack } from "./stack.js";
import secp256k1 from "secp256k1";

export function verifyP2PKHScript(
  scriptpubkey_asm,
  signatureHex,
  publicKeyHex,
  messageHash
) {
  const stack = new Stack();
  const prevoutScriptAsm = scriptpubkey_asm.split(" ");

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
      const signatureBuffer = Buffer.from(DEREncodedSignatureHex, "hex");
      const sigDEC = secp256k1.signatureImport(
        signatureBuffer.slice(0, signatureBuffer.byteLength - 1)
      );

      const result = secp256k1.ecdsaVerify(
        sigDEC,
        Buffer.from(messageHash, "hex"),
        publicKeyBuffer
      );

      if (!result) {
        flag = false;
        return false;
      } else {
        stack.push("1");
        flag = true;
        return true;
      }
    } else if (instruction.startsWith("OP_PUSHBYTES_")) {
      index++;
      const value = prevoutScriptAsm[index];
      stack.push(value);
    }
  });
  return flag;
}

export function verifyP2WPKHScript(prevout, witness, msgHash) {
  const signatureHex = witness[0];
  const publicKeyHex = witness[1];
  const publicKeyBuffer = Buffer.from(publicKeyHex, "hex");

  const prevoutScriptAsm = prevout.scriptpubkey_asm.split(" ");
  const pubKeyHash = prevoutScriptAsm[2];
  const scriptpubkey_asm = `OP_DUP OP_HASH160 OP_PUSHBYTES_20 ${pubKeyHash} OP_EQUALVERIFY OP_CHECKSIG`;
  const result = verifyP2PKHScript(
    scriptpubkey_asm,
    signatureHex,
    publicKeyHex,
    msgHash
  );

  return result;
}
