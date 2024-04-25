import { readTransactions } from "./index.js";
import fs from "fs";
import {
  doubleSHA256Hash,
  reverseBytes,
  getTXIDS,
  getWTXIDS,
  createMerkleRoot,
  createCoinbaseTransaction,
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
  let { witnessRootHash } = await createMerkleRoot(wtxids);
  let witnessReservedValue =
    "0000000000000000000000000000000000000000000000000000000000000000";

  const txids = await getTXIDS();
  const witnessCommitment = `aa21a9ed${doubleSHA256Hash(
    `${witnessReservedValue}${witnessRootHash}`
  )}`;
  const coinbaseTransaction = createCoinbaseTransaction(
    totalValue,
    witnessCommitment
  );
  const serializedCoinbase = serializeTransaction(coinbaseTransaction);
  // console.log("Coinbase Transaction: ", serializedCoinbase);
  const coinbaseTxid = doubleSHA256Hash(serializedCoinbase);
  validTxids.unshift(coinbaseTxid);
  txids.unshift(coinbaseTxid);
  // console.log("Coinbase TXID: ", coinbaseTxid);
  let { merkleRoot } = await createMerkleRoot(txids);

  let nonce = "00000000";
  let bits = "ffff001f";
  let blockHeader =
    version + previousBlockHash + merkleRoot + time + bits + nonce;
  let c = 0;

  // console.log("Merkle Root: ", merkleRoot);
  merkleRoot = reverseBytes(merkleRoot);
  // console.log("Merkle Root: ", merkleRoot);

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
  writeInFile("./txid.txt", txids);
  writeInFile("./wtxid.txt", wtxids);

  const endTime = Date.now();
  const executionTime = (endTime - startTime) / 60000;
  // console.log(`Execution time: ${executionTime} Minutes`);
}

createBlock();
