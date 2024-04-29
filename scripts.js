import CryptoJS from "crypto-js";
import { Stack } from "./stack.js";
import secp256k1 from "secp256k1";
import { derToRS } from "./utils.js";

export function verifyP2PKHScript(
  scriptpubkey_asm,
  signatureHex,
  publicKeyHex,
  messageHash
) {
  const stack = new Stack();
  const prevoutScriptAsm = scriptpubkey_asm.split(" ");
  // const scriptSigAsm = scriptsig_asm.split(" ");

  // const signatureHex = scriptSigAsm[1];
  // const publicKeyHex = scriptSigAsm[3];

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
        flag = false;
        return false;
      } else {
        stack.push("1");
        flag = true;
        // console.log("Signature is valid");
        return true;
      }
    } else if (instruction.startsWith("OP_PUSHBYTES_")) {
      index++;
      const value = prevoutScriptAsm[index];
      stack.push(value);
    }
    // console.log(stack.size(), instruction, stack.printStack());
  });
  return flag;
}

export function verifyP2WPKHScript(prevout, witness, msgHash) {
  // Extract signature and public key from witness
  const signatureHex = witness[0];
  const publicKeyHex = witness[1];
  // const publicKeyHex = prevout.scriptpubkey_asm.split(" ")[2];
  // console.log("Public Key Hex:", publicKeyHex);
  // Verify the signature
  const publicKeyBuffer = Buffer.from(publicKeyHex, "hex");

  const prevoutScriptAsm = prevout.scriptpubkey_asm.split(" ");
  const pubKeyHash = prevoutScriptAsm[2];
  // Use p2pkh here for verification

  // const signatureBuffer = Buffer.from(signatureHex,"hex");
  // const sigDEC = secp256k1.signatureImport(
  //   signatureBuffer.slice(0, signatureBuffer.byteLength - 1)
  // );

  // const result = secp256k1.ecdsaVerify(
  //   sigDEC,
  //   Buffer.from(msgHash, "hex"),
  //   publicKeyBuffer
  // );
  const scriptpubkey_asm = `OP_DUP OP_HASH160 OP_PUSHBYTES_20 ${pubKeyHash} OP_EQUALVERIFY OP_CHECKSIG`;
  const result = verifyP2PKHScript(
    scriptpubkey_asm,
    signatureHex,
    publicKeyHex,
    msgHash
  );

  return result;
}

// export function verifyP2WSHscript(
//   prevout,
//   witness,
//   msgHash,
//   inner_witnessscript_asm
// ) {
//   // Extract the witnessScript from the prevout
//   const scriptpubkey = prevout.scriptpubkey_asm.split(" ")[2];
//   const signature1 = witness[1];
//   const signature2 = witness[2];
//   const witnessScript = witness[3];

//   const stack = new Stack();

//   const witnessScriptAsm = inner_witnessscript_asm.split(" ");

//   stack.push(signature1);
//   stack.push(signature2);

//   witnessScriptAsm.forEach((instruction, index) => {
//     if (instruction === "OP_PUSHBYTES_33") {
//       index++;
//       const value = witnessScriptAsm[index];
//       stack.push(value);
//     } else if (instruction === "OP_CHECKMULTISIG") {
//       const publicKey3 = stack.pop();
//       const publicKey2 = stack.pop();
//       const publicKey1 = stack.pop();

//       const publicKeyBuffer1 = Buffer.from(publicKey1, "hex");
//       const publicKeyBuffer2 = Buffer.from(publicKey2, "hex");
//       const publicKeyBuffer3 = Buffer.from(publicKey3, "hex");

//       const signature2 = stack.pop();
//       const signature1 = stack.pop();
//       console.log("Signature 1:", signature1);
//       console.log("Signature 2:", signature2);

//       const { r: r1, s: s1 } = derToRS(signature1);
//       if (r1 === undefined || s1 === undefined) {
//         return false;
//       }
//       let signatureBuffer1 = Buffer.from(r1 + s1, "hex");
//       if (signatureBuffer1.length !== 64) {
//         signatureBuffer1 = Buffer.concat([
//           Buffer.alloc(64 - signatureBuffer1.length, 0),
//           signatureBuffer1,
//         ]);
//       }

//       const { r: r2, s: s2 } = derToRS(signature2);
//       if (r2 === undefined || s2 === undefined) {
//         return false;
//       }
//       let signatureBuffer2 = Buffer.from(r2 + s2, "hex");
//       if (signatureBuffer2.length !== 64) {
//         signatureBuffer2 = Buffer.concat([
//           Buffer.alloc(64 - signatureBuffer2.length, 0),
//           signatureBuffer2,
//         ]);
//       }

//       if (!result) {
//         console.log("Signature is invalid");
//         return false;
//       } else {
//         console.log("Signature is valid");
//         return true;
//       }
//     }
//   });
// }
