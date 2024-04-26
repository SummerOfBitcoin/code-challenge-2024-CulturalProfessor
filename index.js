import CryptoJS from "crypto-js";
import { verifyP2PKHScript, verifyP2WPKHScript } from "./scripts.js";
import { serializeTransaction } from "./serialize.js";
import {
  msgHashForSegWitSigVerification,
  msgHashForSigVerification,
} from "./messageHash.js";
import { reverseBytes, doubleSHA256Hash } from "./utils.js";
import fs from "fs";

const transactionJSON = {
  version: 2,
  locktime: 834637,
  vin: [
    {
      txid: "a3336d908030c8f2af03f1101585f7b3247edba686a2f48a2c7966d5707c0454",
      vout: 1,
      prevout: {
        scriptpubkey: "0014594b9d704b835b91c2ab6927deb1b36fb63350e9",
        scriptpubkey_asm:
          "OP_0 OP_PUSHBYTES_20 594b9d704b835b91c2ab6927deb1b36fb63350e9",
        scriptpubkey_type: "v0_p2wpkh",
        scriptpubkey_address: "bc1qt99e6uztsdders4tdynaavdnd7mrx58fssf4f7",
        value: 11805728,
      },
      scriptsig: "",
      scriptsig_asm: "",
      witness: [
        "304402205f2c5ef5ebc1ae4ffcef200a6fc6e60bf996ea0f8a5b188e86fc3239bcdb54b30220089df646a08d3fb2c7940b62a0461f0d3fe0664a596d7ca7d050bb13b6f0f36d01",
        "02f5ef263466e8bc46b09c6d4164fba6f71af79fb05bd893e090d46b9d6006403f",
      ],
      is_coinbase: false,
      sequence: 4294967293,
    },
  ],
  vout: [
    {
      scriptpubkey: "00148166a639d0f26d6044f8e2b7072634606c2ac242",
      scriptpubkey_asm:
        "OP_0 OP_PUSHBYTES_20 8166a639d0f26d6044f8e2b7072634606c2ac242",
      scriptpubkey_type: "v0_p2wpkh",
      scriptpubkey_address: "bc1qs9n2vwws7fkkq38cu2mswf35vpkz4sjz72saj9",
      value: 4954790,
    },
    {
      scriptpubkey: "a914425a2834d743cde2f4472914492e24b62a310a3e87",
      scriptpubkey_asm:
        "OP_HASH160 OP_PUSHBYTES_20 425a2834d743cde2f4472914492e24b62a310a3e OP_EQUAL",
      scriptpubkey_type: "p2sh",
      scriptpubkey_address: "37jrXRhWVuxqzmWXeZ1wZQQDcrMUQ5dnvQ",
      value: 6847104,
    },
  ],
};

function verifyTransaction(transactionJSON, realFilename) {
  const { vin, vout, version, locktime } = transactionJSON;
  const serializedTransactionData = serializeTransaction(transactionJSON);
  const doubledSHA256Trxn = doubleSHA256Hash(serializedTransactionData);
  const reversedDoubledSHA256Trxn = reverseBytes(doubledSHA256Trxn);
  // Double SHA256 -> Reverse -> SHA256 for filename
  const filename = CryptoJS.SHA256(
    CryptoJS.enc.Hex.parse(reversedDoubledSHA256Trxn)
  ).toString();
  // console.log("Filename:", filename);

  // SERIALIZATION FOR SEGREGATED WITNESS NOT INCLUDEDS MARKER,FLAG AND WITNESS

  let flag = false;
  let value = 0;
  vin.forEach((input, index) => {
    const { prevout, scriptsig, scriptsig_asm, vout } = input;
    if (vout === 0) {
      value += prevout.value;
    }
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
      // flag = true;
      return true;
    }
  });
  return { flag, doubledSHA256Trxn, value, filename };
}

// console.log("Verification result:", verifyTransaction(transactionJSON));

export async function readTransactions() {
  const mempoolPath = "./mempool";
  const validTxids = [];
  const validFiles = [];
  let totalValue = 0;
  fs.writeFileSync("./nonSerial.txt", ``, { flag: "w" });

  const files = await fs.promises.readdir(mempoolPath);
  for (const file of files) {
    const filePath = `${mempoolPath}/${file}`;
    try {
      const data = await fs.promises.readFile(filePath, "utf8");
      const transactionJSON = JSON.parse(data);
      const { flag, doubledSHA256Trxn, value, filename } = verifyTransaction(
        transactionJSON,
        file
      );
      // Invalid propbably due to large input size
      // if (
      //   "c1b07e1401bcd97807fa664732adb35fc12a6d389d807b8e8176ec9a0dc495c5" ===
      //     doubledSHA256Trxn ||
      //   "0cef1aeb21c04bccf4441f3763b6d57d50c2da82ddd667008f0587fc8541d583" ===
      //     doubledSHA256Trxn ||
      //   "41f24d67f36b0a0fca6d245ff8c6950863bf831abc3d94b6d15f5e1d41b9f9e6" ===
      //     doubledSHA256Trxn ||
      //   "c5394a81f42338e75bee39aba352ca018109f35b1eb51e453ecc06ebc699137b" ===
      //     doubledSHA256Trxn
      // ) {
      //   let val = 0;
      //   transactionJSON.vin.forEach((input, index) => {
      //     const { prevout, scriptsig, scriptsig_asm, vout } = input;
      //     val = val + prevout.value;
      //   });
      //   console.log(file, val);
      //   console.log("Input", transactionJSON.vin.length);
      // }
      if (`${filename}.json` !== file) {
        fs.writeFileSync("./nonSerial.txt", `${file}\t${flag}\n`, {
          flag: "a",
        });
      }

      totalValue += value;
      if (flag) {
        if (transactionJSON.vin.length < 300) {
          // console.log("Input", file,transactionJSON.vin.length);
          validTxids.push(doubledSHA256Trxn);
          validFiles.push(file);
        }
      }
    } catch (e) {
      console.error("Error processing file:", filePath, e);
    }
  }
  return {
    totalValue: totalValue,
    validTxids: validTxids,
    validFiles: validFiles,
  };
}

await readTransactions();
