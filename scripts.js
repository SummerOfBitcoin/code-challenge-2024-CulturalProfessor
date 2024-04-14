import CryptoJS from "crypto-js";
import { Stack } from "./stack.js";
import EC from "elliptic";
const ec = new EC.ec("secp256k1");

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

      const { r, s } = derToRS(DEREncodedSignatureHex);

      const publicKeyBuffer = Buffer.from(publicKeyHex, "hex");
      const messageBuffer = Buffer.from(messageHash, "hex");

      const result = ec.verify(
        messageHash,
        {
          r: r,
          s: s,
        },
        publicKeyBuffer
      );

      if (!result) {
        throw new Error("Signature verification failed");
      } else {
        return true;
      }
    } else if (instruction.startsWith("OP_PUSHBYTES_")) {
      index++;
      const value = prevoutScriptAsm[index];
      stack.push(value);
    }
    // console.log(stack.size(), instruction, stack.printStack());
  });
}

export function derToRS(DEREncodedSignatureHex) {
  let r, s;
  if (DEREncodedSignatureHex.length === 144) {
    r = DEREncodedSignatureHex.substr(10, 64);
    s = DEREncodedSignatureHex.substr(78, 64);
  }
  // implement for 71 bytes also
  r = BigInt(`0x${r}`);
  s = BigInt(`0x${s}`);
  return { r, s };
}
