import CryptoJS from "crypto-js";
import { verifyP2PKHScript } from "./scripts.js";
import fs from "fs";

const transactionJSON = {
  version: 1,
  locktime: 0,
  vin: [
    {
      txid: "94df6f20970e1f5c4635780cdaa0781a13c9046c70cb35d8108dbdb2877d5a59",
      vout: 0,
      prevout: {
        scriptpubkey: "76a9147f0f6a2f76c096ce1c57abfef413b1f38ec407c588ac",
        scriptpubkey_asm:
          "OP_DUP OP_HASH160 OP_PUSHBYTES_20 7f0f6a2f76c096ce1c57abfef413b1f38ec407c5 OP_EQUALVERIFY OP_CHECKSIG",
        scriptpubkey_type: "p2pkh",
        scriptpubkey_address: "1CaqHQEhHUgo6JUUCupb7GtGFVkUgnSqR7",
        value: 1000000,
      },
      scriptsig:
        "483045022100bf3ec2ec7506a3c3e29f5ee4d39162ccdb063fb547f1749a1cc282b9b7a261c9022029cedd3aea84c612012856cd654a639a3112cfcdf3fa5b7c9815a29496f280010121027db40e505a98750020729f1b08572d2a5a0454ea54f88b70b62b7bf2ee342c89",
      scriptsig_asm:
        "OP_PUSHBYTES_72 3045022100bf3ec2ec7506a3c3e29f5ee4d39162ccdb063fb547f1749a1cc282b9b7a261c9022029cedd3aea84c612012856cd654a639a3112cfcdf3fa5b7c9815a29496f2800101 OP_PUSHBYTES_33 027db40e505a98750020729f1b08572d2a5a0454ea54f88b70b62b7bf2ee342c89",
      is_coinbase: false,
      sequence: 4294967295,
    },
    {
      txid: "6bb902771f52e7cde26113956eecdb24c9cc5fb6d99b737eebdd93ac6d0142cf",
      vout: 1,
      prevout: {
        scriptpubkey: "76a914a18f6ffb0dfe94c90e8845a5b8e8f0abcfefcaec88ac",
        scriptpubkey_asm:
          "OP_DUP OP_HASH160 OP_PUSHBYTES_20 a18f6ffb0dfe94c90e8845a5b8e8f0abcfefcaec OP_EQUALVERIFY OP_CHECKSIG",
        scriptpubkey_type: "p2pkh",
        scriptpubkey_address: "1FjFd6KPgzAHf9SKWQgPbXi4R7MhMicjCW",
        value: 399308,
      },
      scriptsig:
        "4730440220255120a922100f554308dab412d8151282314439155d8036ff4ef6a19410e7a80220676b4dcc65e95e45ffb919401f05d26d504f6298a0bc59c69a25f8128250fd10012103cc748e1bda9420ca3b2a98ef207626350156f8eec84d6cd1d8e03f8bb7129cc1",
      scriptsig_asm:
        "OP_PUSHBYTES_71 30440220255120a922100f554308dab412d8151282314439155d8036ff4ef6a19410e7a80220676b4dcc65e95e45ffb919401f05d26d504f6298a0bc59c69a25f8128250fd1001 OP_PUSHBYTES_33 03cc748e1bda9420ca3b2a98ef207626350156f8eec84d6cd1d8e03f8bb7129cc1",
      is_coinbase: false,
      sequence: 4294967295,
    },
  ],
  vout: [
    {
      scriptpubkey: "76a91403fcf11bc69667fc2b6ebebac99bfd857954a31f88ac",
      scriptpubkey_asm:
        "OP_DUP OP_HASH160 OP_PUSHBYTES_20 03fcf11bc69667fc2b6ebebac99bfd857954a31f OP_EQUALVERIFY OP_CHECKSIG",
      scriptpubkey_type: "p2pkh",
      scriptpubkey_address: "1N63HMUrEC4n4W7iUscoHxFnrYJdGmEFs",
      value: 393698,
    },
    {
      scriptpubkey: "76a914e716d089a84759b490f242804b656899bfaab93788ac",
      scriptpubkey_asm:
        "OP_DUP OP_HASH160 OP_PUSHBYTES_20 e716d089a84759b490f242804b656899bfaab937 OP_EQUALVERIFY OP_CHECKSIG",
      scriptpubkey_type: "p2pkh",
      scriptpubkey_address: "1N4tRVwqMXj2auYkHY2frEQsEzWHrDZTdM",
      value: 1000000,
    },
  ],
};
function msgHashForSigVerification(transactionJSON, inputIndex) {
  const { vin, vout, version, locktime } = transactionJSON;
  let serializedTrxnForSigHash = "";
  // Serialize version
  let paddedVersion = version.toString(16).padStart(8, "0");
  serializedTrxnForSigHash += reverseBytes(paddedVersion);

  // Serialize vin length
  serializedTrxnForSigHash += vin.length.toString(16).padStart(2, "0");

  // Serialize vin
  // you have to leave the space for script sig in the inputs other than the one you are verifying empty, in case of multiple inputs
  vin.forEach((input, index) => {
    serializedTrxnForSigHash += reverseBytes(input.txid);
    let paddedInputVout = input.vout.toString(16).padStart(8, "0");
    serializedTrxnForSigHash += reverseBytes(paddedInputVout);
    let pubketAtScriptSig = "";
    if (index !== inputIndex) {
      pubketAtScriptSig = "";
    } else {
      pubketAtScriptSig = input.prevout.scriptpubkey;
    }
    let pubketAtScriptSigSize = Buffer.from(pubketAtScriptSig, "hex")
      .length.toString(16)
      .padStart(2, "0");
    serializedTrxnForSigHash += pubketAtScriptSigSize;
    serializedTrxnForSigHash += pubketAtScriptSig;
    serializedTrxnForSigHash += input.sequence.toString(16).padStart(8, "0");
  });

  // Serialize vout length
  serializedTrxnForSigHash += vout.length.toString(16).padStart(2, "0");
  vout.forEach((output) => {
    let paddedOutput = output.value.toString(16).padStart(16, "0");
    serializedTrxnForSigHash += reverseBytes(paddedOutput);
    let pubketAtScriptPubKey = output.scriptpubkey;
    let pubketAtScriptPubKeySize = Buffer.from(pubketAtScriptPubKey, "hex")
      .length.toString(16)
      .padStart(2, "0");
    serializedTrxnForSigHash += pubketAtScriptPubKeySize;
    serializedTrxnForSigHash += pubketAtScriptPubKey;
  });

  // Serialize locktime
  serializedTrxnForSigHash += locktime.toString(16).padStart(8, "0");
  serializedTrxnForSigHash += "01000000";
  return serializedTrxnForSigHash;
}

function serializeTransaction(transaction) {
  const { version, locktime, vin, vout } = transaction;
  let serializedTransaction = "";

  // Serialize version
  let paddedVersion = version.toString(16).padStart(8, "0");
  serializedTransaction += reverseBytes(paddedVersion);

  // Serialize vin length
  serializedTransaction += vin.length.toString(16).padStart(2, "0");

  // Serialize vin
  vin.forEach((input) => {
    serializedTransaction += input.txid.match(/.{2}/g).reverse().join("");
    let paddedInputVout = input.vout.toString(16).padStart(8, "0");
    serializedTransaction += reverseBytes(paddedInputVout);
    if (input.scriptsig) {
      serializedTransaction += input.scriptsig
        .match(/.{2}/g)
        .length.toString(16)
        .padStart(2, "0");
      serializedTransaction += input.scriptsig;
    }
    serializedTransaction += input.sequence.toString(16).padStart(8, "0");
  });

  // Serialize vout length
  serializedTransaction += vout.length.toString(16).padStart(2, "0");

  // Serialize vout
  vout.forEach((output) => {
    let paddedOutput = output.value.toString(16).padStart(16, "0");
    serializedTransaction += reverseBytes(paddedOutput);
    serializedTransaction += output.scriptpubkey
      .match(/.{2}/g)
      .length.toString(16)
      .padStart(2, "0");
    serializedTransaction += output.scriptpubkey;
  });

  // Serialize locktime
  serializedTransaction += locktime.toString(16).padStart(8, "0");

  return serializedTransaction;
}

function reverseBytes(hexString) {
  // Split the hex string into pairs of characters
  const pairs = hexString.match(/.{1,2}/g);

  // Reverse the order of the pairs
  const reversedPairs = pairs.reverse();

  // Join the reversed pairs back together
  const reversedHexString = reversedPairs.join("");

  return reversedHexString;
}

function doubleSHA256Hash(serializedTransactionData) {
  const hash1 = CryptoJS.SHA256(
    CryptoJS.enc.Hex.parse(serializedTransactionData)
  ).toString();
  const hash2 = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(hash1)).toString();
  return hash2;
}

function verifyTransaction(transactionJSON) {
  const { vin, vout, version, locktime } = transactionJSON;
  const serializedTransactionData = serializeTransaction(transactionJSON);
  const doubledSHA256Trxn = doubleSHA256Hash(serializedTransactionData);
  const reversedDoubledSHA256Trxn = reverseBytes(doubledSHA256Trxn);
  // Double SHA256 -> Reverse -> SHA256 for filename
  const filename = CryptoJS.SHA256(
    CryptoJS.enc.Hex.parse(reversedDoubledSHA256Trxn)
  ).toString();

  let flag = false;
  vin.forEach((input, index) => {
    const { prevout, scriptsig, scriptsig_asm } = input;
    let msgHash = msgHashForSigVerification(transactionJSON, index);
    msgHash = doubleSHA256Hash(msgHash);

    if (input.prevout.scriptpubkey_type === "p2pkh") {
      const verificationResult = verifyP2PKHScript(
        prevout,
        scriptsig,
        scriptsig_asm,
        msgHash
      );
      if (!verificationResult) {
        flag = false;
        return false;
      } else {
        flag = true;
      }
    } else if (input.prevout.scriptpubkey_type === "p2sh") {
      // Implement P2SH verification
      return false;
    } else if (input.prevout.scriptpubkey_type === "v0_p2wpkh") {
      // Implement P2WPKH verification
      return false;
    } else if (input.prevout.scriptpubkey_type === "v0_p2wsh") {
      // Implement P2WSH verification
      return false;
    } else if (input.prevout.scriptpubkey_type === "p2tr") {
      // Implement P2TR verification
      return false;
    }
  });
  return flag;
}

console.log("Verification result:",verifyTransaction(transactionJSON));

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
//           const result = verifyTransaction(transactionJSON);
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
