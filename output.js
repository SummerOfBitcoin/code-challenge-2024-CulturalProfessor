import { readTransactions } from "./index.js";
import fs from "fs";
import {
  doubleSHA256Hash,
  reverseBytes,
  getTXIDS,
  getWTXIDS,
  createMerkleRoot,
  // createCoinbaseTransaction,
  writeInFile,
} from "./utils.js";
import {
  serializeSegWitTransactionForWTXID,
  serializeTransaction,
} from "./serialize.js";

async function createBlock() {
  const startTime = Date.now(); // Record the start time
  const version = "00000001";
  const previousBlockHash = "00".repeat(32);
  let time = Math.floor(Date.now() / 1000)
    .toString(16)
    .padStart(8, "0");
  let { totalValue, validTxids } = await readTransactions();
  const wtxids = await getWTXIDS();
  wtxids.unshift(
    "0000000000000000000000000000000000000000000000000000000000000000"
  );
  let { witnessRootHash } = await createMerkleRoot(wtxids);
  let witnessReservedValue =
    "0000000000000000000000000000000000000000000000000000000000000000";

  // const txids = await getTXIDS();
  // const witnessCommitment = `6a24aa21a9ed${doubleSHA256Hash(
  //   `${witnessReservedValue}${witnessRootHash}`
  // )}`;
  // const coinbaseTransaction = createCoinbaseTransaction(
  //   totalValue,
  //   witnessCommitment
  // );
  // const serializedCoinbase = serializeTransaction(coinbaseTransaction);
  const serializedCoinbase =
    "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100ffffffff02f595814a000000001976a914745d83affb76096abeb668376a8a62b6cb00264c88ac0000000000000000266a24aa21a9ed7246abf6b5c293ff2883fdefdd5faed5680495069d8cb700761c35f18f477af40120000000000000000000000000000000000000000000000000000000000000000000000000";
  // console.log("Coinbase Transaction: ", serializedCoinbase);
  const coinbaseTxid = doubleSHA256Hash(serializedCoinbase);
  validTxids.unshift(coinbaseTxid);
  validTxids = validTxids.map((txid) => {
    return reverseBytes(txid);
  });
  // txids.unshift(coinbaseTxid);
  // console.log("Coinbase TXID: ", coinbaseTxid);
  let merkleRoot = createMerkleRoot(validTxids);

  // console.log("Merkle Root: ", merkleRoot);
  // merkleRoot = reverseBytes(merkleRoot);
  // console.log("Merkle Root: ", merkleRoot);

  let nonce = "00000000";
  let bits = "ffff001f";
  let blockHeader =
    version + previousBlockHash + merkleRoot + time + bits + nonce;
  let c = 0;

  // console.log("Serialed", coinbaseTransaction);
  time = reverseBytes(time);
  do {
    nonce = Math.floor(Math.random() * 4294967295)
      .toString(16)
      .padStart(8, "0");
    nonce = reverseBytes(nonce);
    blockHeader = `${version}${previousBlockHash}${merkleRoot}${time}${bits}${nonce}`;
  } while (
    BigInt("0x" + reverseBytes(doubleSHA256Hash(blockHeader))) >
    BigInt("0x0000ffff00000000000000000000000000000000000000000000000000000000")
  );

  const block = {
    blockHeader: blockHeader,
    serializedCoinbase: serializedCoinbase,
    validTxids: validTxids,
  };

  const blockValues = Object.values(block).flatMap((value) =>
    Array.isArray(value) ? value : [value]
  );

  writeInFile("./output.txt", blockValues);
  // writeInFile("./txid.txt", txids);
  writeInFile("./validtxid.txt", validTxids);
  writeInFile("./wtxid.txt", wtxids);

  const endTime = Date.now();
  const executionTime = (endTime - startTime) / 60000;
  // console.log(`Execution time: ${executionTime} Minutes`);
}

createBlock();
