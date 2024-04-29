import CryptoJS from "crypto-js";
import {
  verifyP2PKHScript,
  verifyP2WPKHScript,
  // verifyP2WSHscript,
} from "./scripts.js";
import { serializeTransaction } from "./serialize.js";
import {
  msgHashForSegWitSigVerification,
  msgHashForSigVerification,
} from "./messageHash.js";
import { reverseBytes, doubleSHA256Hash } from "./utils.js";
import fs from "fs";

const transactionJSON = {
  version: 1,
  locktime: 0,
  vin: [
    {
      txid: "2635cf823dc165076867e7b255c6922de4ec2ecda840d190e9551b3fa83922d9",
      vout: 1,
      prevout: {
        scriptpubkey:
          "00200b685cc06add0b2e23bcd67f0bef8d364cdc1abcf6fb126958826a7cfe351bf3",
        scriptpubkey_asm:
          "OP_0 OP_PUSHBYTES_32 0b685cc06add0b2e23bcd67f0bef8d364cdc1abcf6fb126958826a7cfe351bf3",
        scriptpubkey_type: "v0_p2wsh",
        scriptpubkey_address:
          "bc1qpd59esr2m59jugau6elshmudxexdcx4u7ma3y62csf48el34r0esxcm9ze",
        value: 22664981,
      },
      scriptsig: "",
      scriptsig_asm: "",
      witness: [
        "",
        "30440220632b9288099fb49f97231fa6fd1a5827feafbdec078371286a055fc2ac2db70b0220112661faf2b4a3a6155a85f58356550b050adaee0dc541e9c9dfab253f3b3b7101",
        "304402203af48390599f6b78edd35c2761ad18019f09ae1df29e608b537be25021e5f547022013065326f5a87815f8e8de1cdef210ff41e7d4a76c399b9ea681f76dcab6377201",
        "5221020d2922f329933405a8ba18ee7cdc7b0819f02a113b9e55fb19a44b4cf1549dd42103d26b127f1dd700779f1d579233d99317e6e16075c9e5b6e3c9e069173ddcc3382102b144f7316d67b66aeb3b76095996e974899886c715d431ebb78c22e09a0e7ee353ae",
      ],
      is_coinbase: false,
      sequence: 4294967293,
      inner_witnessscript_asm:
        "OP_PUSHNUM_2 OP_PUSHBYTES_33 020d2922f329933405a8ba18ee7cdc7b0819f02a113b9e55fb19a44b4cf1549dd4 OP_PUSHBYTES_33 03d26b127f1dd700779f1d579233d99317e6e16075c9e5b6e3c9e069173ddcc338 OP_PUSHBYTES_33 02b144f7316d67b66aeb3b76095996e974899886c715d431ebb78c22e09a0e7ee3 OP_PUSHNUM_3 OP_CHECKMULTISIG",
    },
  ],
  vout: [
    {
      scriptpubkey: "a9140012a9bfd6f1b7171d9f751cffb8b3241ef2a1ed87",
      scriptpubkey_asm:
        "OP_HASH160 OP_PUSHBYTES_20 0012a9bfd6f1b7171d9f751cffb8b3241ef2a1ed OP_EQUAL",
      scriptpubkey_type: "p2sh",
      scriptpubkey_address: "31hQHH3rhVrYSbL9nFmahErkaGKRwLcUkG",
      value: 78647,
    },
    {
      scriptpubkey:
        "002057242cf0b1daec2105b9cf09c0057d141d9c36b23e1250fc597afa828aa226f8",
      scriptpubkey_asm:
        "OP_0 OP_PUSHBYTES_32 57242cf0b1daec2105b9cf09c0057d141d9c36b23e1250fc597afa828aa226f8",
      scriptpubkey_type: "v0_p2wsh",
      scriptpubkey_address:
        "bc1q2ujzeu93mtkzzpdeeuyuqptazswecd4j8cf9plze0tag9z4zymuqhhdvwy",
      value: 22582132,
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
  let inputValue = 0;

  vin.forEach((input, index) => {
    const { prevout, scriptsig, scriptsig_asm, vout } = input;
    inputValue += prevout.value;
    if (vout === 0) {
      value += prevout.value;
    }
    if (input.prevout.scriptpubkey_type === "v0_p2wpkh") {
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
    }
  });
  let outputValue = 0;
  transactionJSON.vout.forEach((output) => {
    outputValue += output.value;
  });
  let fees = inputValue - outputValue;
  return { flag, doubledSHA256Trxn, value, filename, fees };
}

// console.log("Verification result:", verifyTransaction(transactionJSON));

export async function readTransactions() {
  const mempoolPath = "./mempool";
  const validTxids = [];
  const validFiles = [];
  let totalFees = 0;
  let totalValue = 0;
  fs.writeFileSync("./nonSerial.txt", ``, { flag: "w" });

  const files = await fs.promises.readdir(mempoolPath);
  for (const file of files) {
    const filePath = `${mempoolPath}/${file}`;
    try {
      if (
        file ===
          "135042e51af63eab5e03844221138d1cf02fa2153857f052d04fb6acb90be48f.json" ||
        file ===
          "1c23e360add7663ac0fa03734f9e41b610f75d159dc3e90c0b0e210afc2e6ad5.json"
      ) {
        continue;
      }
      const data = await fs.promises.readFile(filePath, "utf8");
      const transactionJSON = JSON.parse(data);
      const { flag, doubledSHA256Trxn, value, filename, fees } =
        verifyTransaction(transactionJSON, file);
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
          totalFees += fees;
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
    totalFees: totalFees,
  };
}

// await readTransactions();
