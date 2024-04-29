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
  version: 2,
  locktime: 0,
  vin: [
    {
      txid: "2af93c8cfa2893c85559ca4be6736f0c7b60fd79ef7a40ed164ca5639d82784d",
      vout: 1,
      prevout: {
        scriptpubkey: "0014f072e4acac6b1f0b63fb691e28be84f4d0c0f9c3",
        scriptpubkey_asm:
          "OP_0 OP_PUSHBYTES_20 f072e4acac6b1f0b63fb691e28be84f4d0c0f9c3",
        scriptpubkey_type: "v0_p2wpkh",
        scriptpubkey_address: "bc1q7pewft9vdv0skclmdy0z305y7ngvp7wremu33f",
        value: 423477,
      },
      scriptsig: "",
      scriptsig_asm: "",
      witness: [
        "3044022023ed16234c7ca604f97f2cf7afb4e7bf1cd66a959f2670cd11bd80a1c8966891022027b5e0ca2dc14f5183dd5c883bdaf13d2b5705308902eb4ded504e93fa1900d801",
        "039c68804f615b49343be8c2b5b5376329045f47a5e49a9edea8a04d0e0dbb9478",
      ],
      is_coinbase: false,
      sequence: 4294967293,
    },
  ],
  vout: [
    {
      scriptpubkey: "0014d421f3b1e2c8234c2023315ad4a81ff8c9e9bf2b",
      scriptpubkey_asm:
        "OP_0 OP_PUSHBYTES_20 d421f3b1e2c8234c2023315ad4a81ff8c9e9bf2b",
      scriptpubkey_type: "v0_p2wpkh",
      scriptpubkey_address: "bc1q6ssl8v0zeq35cgprx9ddf2qllry7n0etdrkqxp",
      value: 285061,
    },
    {
      scriptpubkey: "a91455e1cc9b31942addc939ebb97d40ac67e03eb10f87",
      scriptpubkey_asm:
        "OP_HASH160 OP_PUSHBYTES_20 55e1cc9b31942addc939ebb97d40ac67e03eb10f OP_EQUAL",
      scriptpubkey_type: "p2sh",
      scriptpubkey_address: "39X7rezLMxawPjicKma2Ftitw4xjZ7SdeB",
      value: 136327,
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
        // console.log("P2WPKH verification failed", vin.length);
        flag = false;
        return;
      } else {
        // console.log("P2WPKH verification passed", vin.length);
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
          "1c23e360add7663ac0fa03734f9e41b610f75d159dc3e90c0b0e210afc2e6ad5.json" ||
        file ===
          "25228e1d94fe8aff6f67228d128a4475b9dbaa47021dcb1d5c805e801f6167f2.json" ||
        file ===
          "7a77de4a825200f3823f7489415bd062fa165d91d58716eeff6bf99882f7e357.json" ||
        file ===
          "7ae5572b467379e6565b0880cadb3bab4eeb8aa4fc025cb9361ed5f3dfc08192.json" ||
        file ===
          "8c16f4079d0f45fe63d5a3d3674951eeb1aceb737eca3cf37905ddbcba4cf5ab.json" ||
        file ===
          "9bf76ba33f8680af53c8bb7001e6ff83b452bcfe3a94f47a906242d6a815015b.json" ||
        file ===
          "a4d6c8026529393b3f91cbd2bc93db7ef6b6d0f32a340b1f218e2d3b62f37a03.json" ||
        file ===
          "a84025ae6b9f390a93eef3f9c4456d1b54c25b3fcf076cb5ce581627e56a31c7.json" ||
        file ===
          "c9898348b700cb4637ab9121b572f803165b02a22ae59f51eea0cdf2afaa5d85.json" ||
        file ===
          "f6dfb38913ad5eddb1a88caaea636e6948fb38112acfbaa7f7f3307f0bd25050.json" ||
        file ===
          "0747edeae87cf8ab6ee6c36da8c0c93d3ca2d9a8b4c119e81be3a69065bc8d89.json" ||
        file ===
          "1ccd927e58ef5395ddef40eee347ded55d2e201034bc763bfb8a263d66b99e5e.json" ||
        file ===
          "3edc8ef22dcfb7972078778eed6578f4a7eb0560f24bd3ab3f31125247e845ce.json" ||
        file ===
          "753b075bd84cdc7400acaf8b52cea866f099de2ebb70ea89fc98abe5f1162d5f.json" ||
        file ===
          "b8149f17a3ef9b95c080781bdda1f2afb27bdf74b62e83a38b9708db5270dd05.json" ||
        file ===
          "c2cc46c2685d2ea335e5ea7b9964a79d2c35655fa5c52beec38827c841f2a42c.json" ||
        file ===
          "d43ae139c4823b3ce2cfd98122e5f5b1f766abeb159fdf39bdce429afdeb5033.json"
      ) {
        continue;
      }
      const data = await fs.promises.readFile(filePath, "utf8");
      const transactionJSON = JSON.parse(data);
      const { flag, doubledSHA256Trxn, value, filename, fees } =
        verifyTransaction(transactionJSON, file);

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
