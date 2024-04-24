import { readTransactions } from "./index.js";
import fs from "fs";
import CryptoJS from "crypto-js";
import { doubleSHA256Hash, reverseBytes } from "./utils.js";
import { serializeSegWitTransactionForWTXID } from "./serialize.js";

async function createBlock() {
  const startTime = Date.now(); // Record the start time

  const version = "00000001";
  const previousBlockHash = "00".repeat(32);
  const time = Math.floor(Date.now() / 1000)
    .toString(16)
    .padStart(8, "0");
  const { merkleRoot, totalValue, validTxids } = await createMerkleRoot();

  let nonce = "00000000";

  let bits = "ffff001f";
  let blockHeader =
    version + previousBlockHash + merkleRoot + time + bits + nonce;
  let c = 0;
  let flag = false;
  // console.log("Header: ", blockHeader);
  // console.log("Block Hash: ", blockhash);
  do {
    nonce = Math.floor(Math.random() * 4294967295)
      .toString(16)
      .padStart(8, "0");
    blockHeader = `${version}${previousBlockHash}${reverseBytes(
      merkleRoot
    )}${reverseBytes(time)}${bits}${reverseBytes(nonce)}`;

    c++;
    // console.log(c)
  } while (
    BigInt("0x" + doubleSHA256Hash(blockHeader)) >
    BigInt("0x0000ffff00000000000000000000000000000000000000000000000000000000")
  );

  // console.log("Block hash is greater than target", c);
  // console.log("Header: ", blockHeader,blockHeader.length);
  // console.log("Block Hash: ", doubleSHA256Hash(blockHeader));
  // console.log("bits: ", bits);
  // console.log(
  //   BigInt("0x" + doubleSHA256Hash(blockHeader)),
  //   BigInt("0x0000ffff00000000000000000000000000000000000000000000000000000000")
  // );
  // if (
  //   BigInt("0x" + doubleSHA256Hash(blockHeader)) <
  //   BigInt("0x0000ffff00000000000000000000000000000000000000000000000000000000")
  // ) {
  //   console.log("Block hash is less than target");
  // } else {
  //   console.log("Block hash is greater than target");
  // }
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

  const endTime = Date.now(); // Record the end time
  const executionTime = (endTime - startTime) / 60000; // Calculate execution time in seconds
  // console.log(`Execution time: ${executionTime} Minutes`);
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
