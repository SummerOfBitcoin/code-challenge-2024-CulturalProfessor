import CryptoJS from "crypto-js";
import { verifyP2PKHScript, verifyP2WPKHScript } from "./scripts.js";
import {
  serializeSegWitTransaction,
  serializeTransaction,
} from "./serialize.js";
import {
  msgHashForSegWitSigVerification,
  msgHashForSigVerification,
} from "./messageHash.js";
import { reverseBytes, doubleSHA256Hash } from "./utils.js";
import fs, { chownSync } from "fs";

const transactionJSON = {
  version: 1,
  locktime: 0,
  vin: [
    {
      txid: "e343dc4bc128e72dc6300c467a6ec37bfc4c8c59dbcc90d90a609fab2ddb082d",
      vout: 0,
      prevout: {
        scriptpubkey: "001438dce15fa7735a14075e255a942974f1e274db06",
        scriptpubkey_asm:
          "OP_0 OP_PUSHBYTES_20 38dce15fa7735a14075e255a942974f1e274db06",
        scriptpubkey_type: "v0_p2wpkh",
        scriptpubkey_address: "bc1q8rwwzha8wddpgp67y4dfg2t57838fkcxyqdwy7",
        value: 4092,
      },
      scriptsig: "",
      scriptsig_asm: "",
      witness: [
        "304402201c91da3c6363ae4ae824fac90bcc5044e17a619e09eddcfe4fe3b3b547c4da7f02206ef0112cdd3e1516fa4ec285b1343c151a3337622da1d5c5da272bedeb25660501",
        "03610ec7abcea7ca2b42974cebb42c24ed1943493e94f5b7bc6d8352e308fbf268",
      ],
      is_coinbase: false,
      sequence: 4294967295,
    },
  ],
  vout: [
    {
      scriptpubkey: "0014a171823325dbad4dbdc558b29f1778eedff066de",
      scriptpubkey_asm:
        "OP_0 OP_PUSHBYTES_20 a171823325dbad4dbdc558b29f1778eedff066de",
      scriptpubkey_type: "v0_p2wpkh",
      scriptpubkey_address: "bc1q59ccyve9mwk5m0w9tzef79mcam0lqek775sr3w",
      value: 1232,
    },
  ],
};

function verifyTransaction(transactionJSON, realFilename) {
  const { vin, vout, version, locktime } = transactionJSON;
  // const serializedTransactionData = serializeTransaction(transactionJSON);
  // const doubledSHA256Trxn = doubleSHA256Hash(serializedTransactionData);
  // const reversedDoubledSHA256Trxn = reverseBytes(doubledSHA256Trxn);
  // // Double SHA256 -> Reverse -> SHA256 for filename
  // const filename = CryptoJS.SHA256(
  //   CryptoJS.enc.Hex.parse(reversedDoubledSHA256Trxn)
  // ).toString();
  // console.log("Filename:", filename);

  // SERIALIZATION FOR SEGREGATED WITNESS NOT WORKING FOR NOW

  // const segWitSerialized = serializeSegWitTransaction(transactionJSON);
  // const segWitDoubledSHA256Trxn = doubleSHA256Hash(segWitSerialized);
  // // console.log("Double SHA256:", segWitDoubledSHA256Trxn);
  // const segWitReversedDoubledSHA256Trxn = reverseBytes(segWitDoubledSHA256Trxn);
  // const segWitFilename = CryptoJS.SHA256(
  //   CryptoJS.enc.Hex.parse(segWitReversedDoubledSHA256Trxn)
  // ).toString();
  // console.log("Seg Filename:", segWitFilename);

  let flag = false;
  vin.forEach((input, index) => {
    const { prevout, scriptsig, scriptsig_asm } = input;
    if (input.prevout.scriptpubkey_type === "p2pkh") {
      let msgHash = msgHashForSigVerification(transactionJSON, index);
      msgHash = doubleSHA256Hash(msgHash);
      const verificationResult = verifyP2PKHScript(
        prevout,
        scriptsig,
        scriptsig_asm,
        msgHash
      );
      if (!verificationResult) {
        flag = false;
        return;
      } else {
        flag = true;
      }
    } else if (input.prevout.scriptpubkey_type === "v0_p2wpkh") {
      const { witness } = input;
      const msgHash = msgHashForSegWitSigVerification(transactionJSON, index);
      const verificationResult = verifyP2WPKHScript(prevout, witness, msgHash);
      // Implement P2WPKH verification
      if (!verificationResult) {
        flag = false;
        return;
      } else {
        flag = true;
      }
    } else if (input.prevout.scriptpubkey_type === "v0_p2wsh") {
      return false;
    } else if (input.prevout.scriptpubkey_type === "p2sh") {
      return false;
    } else if (input.prevout.scriptpubkey_type === "p2ms") {
      return false;
    } else if (input.prevout.scriptpubkey_type === "v1_p2tr") {
      return true;
    }
  });
  return flag;
}

console.log("Verification result:", verifyTransaction(transactionJSON));

// async function readTransactions() {
//   const mempoolPath = "./mempool";
//   fs.readdir(mempoolPath, (err, files) => {
//     if (err) {
//       console.error("Could not list the directory.", err);
//       process.exit(1);
//     }
//     let fileVerifiedCount = 0;
//     let invalidTransactionCount = 0;
//     let startTimestamp = new Date().getTime();
//     let endTimestamp = 0;
//     files.forEach((file, index) => {
//       const filePath = `${mempoolPath}/${file}`;
//       fs.readFile(filePath, "utf8", (err, data) => {
//         if (err) {
//           console.error("Could not read the file.", err);
//           return;
//         }
//         try {
//           const transactionJSON = JSON.parse(data);
//           const result = verifyTransaction(transactionJSON, file);
//           if (result) {
//             fileVerifiedCount++;
//           } else {
//             // console.log("Transaction is invalid:", filePath);
//             invalidTransactionCount++;
//           }
//           if (index === files.length - 1) {
//             endTimestamp = new Date().getTime();
//             let elapsedTime = endTimestamp - startTimestamp;
//             console.log("Verified files count:", fileVerifiedCount);
//             console.log("Invalid transactions count:", invalidTransactionCount);
//             console.log("Elapsed time in minutes:", elapsedTime / 60000);
//           }
//         } catch (e) {
//           console.error("Error parsing JSON", e);
//         }
//       });
//     });
//   });
// }

// await readTransactions();