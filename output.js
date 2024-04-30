import { readTransactions } from "./index.js";
import fs from "fs";
import {
  doubleSHA256Hash,
  reverseBytes,
  getTXIDS,
  getWTXIDS,
  createMerkleRoot,
  writeInFile,
  createCoinbaseTransaction,
} from "./utils.js";

async function createBlock() {
  const version = "00000001";
  const previousBlockHash = "00".repeat(32);
  let time = Math.floor(Date.now() / 1000)
    .toString(16)
    .padStart(8, "0");
  let { validTxids, validFiles, totalFees } =
    await readTransactions();
  // console.log("Total Fees: ", totalFees);
  let blockSubsidy = 624981725;
  let blockReward = blockSubsidy + totalFees;
  blockReward = blockReward.toString(16).padStart(16, "0");
  blockReward = reverseBytes(blockReward);

  // Error Probably due to wtxids
  let wtxids = await getWTXIDS(validFiles);

  wtxids.unshift("00".repeat(32));
  wtxids = wtxids.map((wtxid) => {
    return reverseBytes(wtxid);
  });
  let witnessRootHash = await createMerkleRoot(wtxids);
  let witnessReservedValue =
    "0000000000000000000000000000000000000000000000000000000000000000";

  let witnessCommitment = doubleSHA256Hash(
    witnessRootHash + witnessReservedValue
  );
  // console.log("Witness Commitment: ", witnessCommitment);
  const scriptpubkey = `6a24aa21a9ed${witnessCommitment}`;
  const serializedCoinbase = createCoinbaseTransaction(
    blockReward,
    scriptpubkey
  );
  // console.log("Coinbase Transaction: ", serializedCoinbase);

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
}

createBlock();
