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

export async function getWTXIDS() {
  const mempoolPath = "./mempool";
  const txids = [];
  const files = await fs.promises.readdir(mempoolPath);

  for (const file of files) {
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
      if (!flag) {
        continue;
      }
      const serializedTransactionData =
        serializeSegWitTransactionForWTXID(transactionJSON);
      const doubledSHA256Trxn = doubleSHA256Hash(serializedTransactionData);
      txids.push(doubledSHA256Trxn);
    } catch (e) {
      console.error("Error processing file:", filePath, e);
    }
  }

  return txids;
}

// export function createCoinbaseTransaction(totalValue, witnessCommitment) {
//   const coinbaseTransaction = {
//     version: 2,
//     locktime: 0,
//     vin: [
//       {
//         txid: "0000000000000000000000000000000000000000000000000000000000000000",
//         vout: 4294967295,
//         scriptsig: "",
//         scriptsig_asm: "",
//         witness: [
//           "304402201c91da3c6363ae4ae824fac90bcc5044e17a619e09eddcfe4fe3b3b547c4da7f02206ef0112cdd3e1516fa4ec285b1343c151a3337622da1d5c5da272bedeb25660501",
//           "03610ec7abcea7ca2b42974cebb42c24ed1943493e94f5b7bc6d8352e308fbf268",
//         ],
//         is_coinbase: true,
//         sequence: "ffffffff",
//       },
//     ],
//     vout: [
//       {
//         scriptpubkey_type: "p2pkh",
//         scriptpubkey_address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
//         scriptpubkey: "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
//         scriptpubkey_asm:
//           "OP_DUP OP_HASH160 OP_PUSHBYTES_20 62e907b15cbf27d5425399ebf6f0fb50ebb88f18 OP_EQUALVERIFY OP_CHECKSIG",
//         value: totalValue,
//       },
//       {
//         scriptpubkey: witnessCommitment,
//         scriptpubkey_asm:
//           "OP_0 OP_PUSHBYTES_20 a171823325dbad4dbdc558b29f1778eedff066de",
//         scriptpubkey_type: "p2wpkh",
//         scriptpubkey_address: "bc1q59ccyve9mwk5m0w9tzef79mcam0lqek775sr3w",
//         value: 0,
//       },
//     ],
//   };
//   return coinbaseTransaction;
// }

export function createMerkleRoot(txids) {
  try {
    // Calculate the Merkle root iteratively without recursion
    txids = txids.map((txid) => reverseBytes(txid));
    while (txids.length > 1) {
      const result = [];
      for (let i = 0; i < txids.length; i += 2) {
        const one = txids[i];
        const two = i + 1 < txids.length ? txids[i + 1] : one; // Ensure last element is concatenated with itself if odd number of elements
        const concat = one + two;
        result.push(doubleSHA256Hash(concat));
      }
      txids = result;
    }

    // Return the Merkle root
    return txids[0];
  } catch (error) {
    console.error("Error in createMerkleRoot:", error);
    throw error; // Propagate the error to the caller
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
