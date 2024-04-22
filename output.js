import { readTransactions } from "./index.js";
import fs from "fs";
import CryptoJS from "crypto-js";
import { doubleSHA256Hash } from "./utils.js";
import { serializeSegWitTransactionForWTXID } from "./serialize.js";

async function createBlock() {
  const version = "00000020";
  // 32 bytes
  const previousBlockHash = "00".repeat(32);
  const { merkleRoot, totalValue, validTxids } = await createMerkleRoot();
  const time = Math.floor(Date.now() / 1000)
    .toString(16)
    .padStart(8, "0");

  const nonce = "00000000";
  // Maybe error here
  const target =
    "0000ffff00000000000000000000000000000000000000000000000000000000";
  const bits = "1f00ffff";

  const blockHeader =
    version + previousBlockHash + merkleRoot + time + bits + nonce;

  const coinbaseTransaction = createCoinbaseTransaction(totalValue);
  const serializedCoinbase =
    serializeSegWitTransactionForWTXID(coinbaseTransaction);
  const wtxid = doubleSHA256Hash(serializedCoinbase);
  validTxids.unshift(wtxid);

  const block = {
    blockHeader: blockHeader,
    serializedCoinbase: serializedCoinbase,
    validTxids: validTxids,
  };

  const blockValues = Object.values(block).flatMap((value) =>
    Array.isArray(value) ? value : [value]
  );

  fs.writeFileSync("./output.txt", "", { flag: "w" });

  blockValues.forEach((element) => {
    fs.writeFileSync(`./output.txt`, element + "\n", { flag: "a" });
  });
}

async function createMerkleRoot() {
  const { txids, totalValue, validTxids } = await readTransactions();

  let merkleTree = txids; // Initial list of txids
  while (merkleTree.length > 1) {
    let level = [];
    for (let i = 0; i < merkleTree.length; i += 2) {
      let left = merkleTree[i];
      let right = i + 1 === merkleTree.length ? left : merkleTree[i + 1];
      let concat = left + right;
      let hash = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(concat)).toString();
      level.push(hash);
    }
    merkleTree = level;
  }
  return {
    merkleRoot: merkleTree[0],
    totalValue: totalValue,
    validTxids: validTxids,
  };
}
createBlock();

function createCoinbaseTransaction(totalValue) {
  const coinbaseTransaction = {
    version: 2,
    locktime: 0,
    vin: [
      {
        txid: "0000000000000000000000000000000000000000000000000000000000000000",
        vout: 0,
        scriptsig: "",
        scriptsig_asm: "",
        witness: [
          "304402201c91da3c6363ae4ae824fac90bcc5044e17a619e09eddcfe4fe3b3b547c4da7f02206ef0112cdd3e1516fa4ec285b1343c151a3337622da1d5c5da272bedeb25660501",
          "03610ec7abcea7ca2b42974cebb42c24ed1943493e94f5b7bc6d8352e308fbf268",
        ],
        is_coinbase: true,
        sequence: "ffffffff",
      },
    ],
    vout: [
      {
        scriptpubkey: "0014a171823325dbad4dbdc558b29f1778eedff066de",
        scriptpubkey_asm:
          "OP_0 OP_PUSHBYTES_20 a171823325dbad4dbdc558b29f1778eedff066de",
        scriptpubkey_type: "p2wpkh",
        scriptpubkey_address: "bc1q59ccyve9mwk5m0w9tzef79mcam0lqek775sr3w",
        value: totalValue,
      },
    ],
  };
  return coinbaseTransaction;
}
