import CryptoJS from "crypto-js";
import fs from "fs";
import {
  serializeSegWitTransactionForWTXID,
  serializeTransaction,
} from "./serialize.js";

export function reverseBytes(hexString) {
  return hexString.match(/.{2}/g).reverse().join("");
}

export function doubleSHA256Hash(serializedTransactionData) {
  const hash1 = CryptoJS.SHA256(
    CryptoJS.enc.Hex.parse(serializedTransactionData)
  ).toString();
  const hash2 = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(hash1)).toString();
  return hash2;
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

export async function getTXIDS() {
  const mempoolPath = "./mempool";
  const txids = [];
  const files = await fs.promises.readdir(mempoolPath);

  for (const file of files) {
    const filePath = `${mempoolPath}/${file}`;
    try {
      const data = await fs.promises.readFile(filePath, "utf8");
      const transactionJSON = JSON.parse(data);
      const serializedTransactionData = serializeTransaction(transactionJSON);
      const doubledSHA256Trxn = doubleSHA256Hash(serializedTransactionData);
      txids.push(doubledSHA256Trxn);
    } catch (e) {
      console.error("Error processing file:", filePath, e);
    }
  }

  return txids;
}

export async function getWTXIDS(validFiles) {
  const mempoolPath = "./mempool";
  const txids = [];
  const files = await fs.promises.readdir(mempoolPath);
  for (const file of files) {
    if (!validFiles.includes(file)) {
      continue;
    }
    const filePath = `${mempoolPath}/${file}`;
    try {
      const data = await fs.promises.readFile(filePath, "utf8");
      const transactionJSON = JSON.parse(data);
      let flag = true;
      transactionJSON.vin.forEach((input) => {
        if (!input.witness) {
          flag = false;
        }
      });
      let serializedTransactionData = "";
      if (flag) {
        serializedTransactionData =
          serializeSegWitTransactionForWTXID(transactionJSON);
        const doubledSHA256Trxn = doubleSHA256Hash(serializedTransactionData);
        txids.push(doubledSHA256Trxn);
      } else {
        console.log(file);
        // serializedTransactionData = serializeTransaction(transactionJSON);
      }
    } catch (e) {
      console.error("Error processing file:", filePath, e);
    }
  }
  return txids;
}

export function createCoinbaseTransaction(blockReward, scriptpubkey) {
  return `010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100ffffffff02${blockReward}1976a914745d83affb76096abeb668376a8a62b6cb00264c88ac000000000000000026${scriptpubkey}0120000000000000000000000000000000000000000000000000000000000000000000000000`;
}

export function createMerkleRoot(txids) {
  try {
    // Calculate the Merkle root iteratively without recursion
    txids = txids.map((txid) => reverseBytes(txid));
    while (txids.length > 1) {
      const result = [];
      for (let i = 0; i < txids.length; i += 2) {
        const one = txids[i];
        const two = i + 1 < txids.length ? txids[i + 1] : one;
        const concat = one + two;
        result.push(doubleSHA256Hash(concat));
      }
      txids = result;
    }
    // Return the Merkle root
    return txids[0];
  } catch (error) {
    console.error("Error in createMerkleRoot:", error);
    throw error; 
  }
}

export function writeInFile(filePath, data) {
  try {
    fs.writeFileSync(filePath, "", { flag: "w" });

    data.forEach((element) => {
      fs.writeFileSync(filePath, element + "\n", { flag: "a" });
    });
  } catch (error) {
    console.error("Error in writeInFile:", error);
    throw error;
  }
}
