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
  let { totalValue, validTxids, validFiles } = await readTransactions();
  let wtxids = await getWTXIDS();
  wtxids.unshift("00".repeat(32));
  wtxids = wtxids.map((txid) => {
    return reverseBytes(txid);
  });
  let witnessRootHash = await createMerkleRoot(wtxids);
  let witnessReservedValue =
    "0000000000000000000000000000000000000000000000000000000000000000";

  let witnessCommitment = doubleSHA256Hash(
    witnessRootHash + witnessReservedValue
  );
  const scriptpubkey = `6a24aa21a9ed${witnessCommitment}`;
  const serializedCoinbase = `010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100ffffffff02f6994e7c260000001976a914745d83affb76096abeb668376a8a62b6cb00264c88ac000000000000000026${scriptpubkey}0120000000000000000000000000000000000000000000000000000000000000000000000000`;
  const coinbaseTxid = doubleSHA256Hash(serializedCoinbase);

  validTxids.unshift(coinbaseTxid);
  validTxids = validTxids.map((txid) => {
    return reverseBytes(txid);
  });
  let merkleRoot = createMerkleRoot(validTxids);
  let nonce = "00000000";
  let bits = "ffff001f";
  let blockHeader =
    version + previousBlockHash + merkleRoot + time + bits + nonce;
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
