import { readTransactions } from "./index.js";
import fs from "fs";
import CryptoJS from "crypto-js";
import { doubleSHA256Hash } from "./utils.js";
import { serializeSegWitTransactionForWTXID } from "./serialize.js";

async function createBlock() {
  const version = "00000020";
  // 32 bytes
  const previousBlockHash = "00".repeat(32);
  const time = Math.floor(Date.now() / 1000)
    .toString(16)
    .padStart(8, "0");
  // console.log("Time: ", time);
  const { merkleRoot, totalValue, validTxids } = await createMerkleRoot();

  let nonce = "00000000";
  // Maybe error here our target should be lower than this

  let bits = "00000000";
  let blockHeader =
    version + previousBlockHash + merkleRoot + time + bits + nonce;
  // console.log("Block Header: ", blockHeader, blockHeader.length);
  // blockhash = doubleSHA256Hash(blockHeader);
  // 4262944507652438202757495313951717853240532272612529385745411476082174135379

  //Expected
  // 26008872543971271528331265717745458250338554625754332728821881862605241600316

  let blockhash = doubleSHA256Hash(blockHeader);
  let c = 0;
  while (
    BigInt("0x" + blockhash) >
    BigInt("0x0000ffff00000000000000000000000000000000000000000000000000000000")
  ) {
    // console.log("Block hash is greater than target", c);
    nonce = Math.floor(Math.random() * 4294967295)
      .toString(16)
      .padStart(8, "0");
    blockHeader =
      version + previousBlockHash + merkleRoot + time + bits + nonce;
    blockhash = doubleSHA256Hash(blockHeader);

    let roughPrecision=""
    for (let i = 0; i < blockhash.length; i++) {
      if (blockhash[i+1] !== "0") {
        roughPrecision = blockhash.slice(i, i + 6);
        bits= `${Math.floor((64-i)/2)}${roughPrecision}`
        break;
      }
    }    
    
    c++;
  }

  // console.log("Header: ", blockHeader);
  // console.log("Block Hash: ", blockhash);
  // console.log("bits: ", bits);
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

  // Ensure an even number of transaction IDs by duplicating the last ID if needed
  if (merkleTree.length % 2 === 1) {
    merkleTree.push(merkleTree[merkleTree.length - 1]);
  }

  while (merkleTree.length > 1) {
    let level = [];
    for (let i = 0; i < merkleTree.length; i += 2) {
      let left = merkleTree[i];
      let right = merkleTree[i + 1];
      let concat = left + right;
      let hash = doubleSHA256Hash(concat);
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

createBlock();
