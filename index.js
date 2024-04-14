import CryptoJS from "crypto-js";
import { verifyP2PKHScript } from "./scripts.js";

const transactionJSON = {
  version: 1,
  locktime: 0,
  vin: [
    {
      txid: "4407d689765e67e7ac99b0f96834fbf845a92a3ec2a56c032df7228d02f421b1",
      vout: 3,
      prevout: {
        scriptpubkey: "76a914c1ff5f4b3a7b9fb43639f8a8ecf53f608983bb6488ac",
        scriptpubkey_asm:
          "OP_DUP OP_HASH160 OP_PUSHBYTES_20 c1ff5f4b3a7b9fb43639f8a8ecf53f608983bb64 OP_EQUALVERIFY OP_CHECKSIG",
        scriptpubkey_type: "p2pkh",
        scriptpubkey_address: "1JgmLbfckxmmKdqAyfayaP37RtaFjB4ovp",
        value: 52419,
      },
      scriptsig:
        "483045022100feeafd13943ece155a277351b5649a3b69186de24f90785a8e2cd3170eb6c0c902201b072cb2ef7eeff1eea8ba185dfca77c5bb6b38e521fd008835d46c50c73aa5c0121038b572d6693afe809ed2df3233ba99b67415a60655a71fa5f06a3cf982e7d37e7",
      scriptsig_asm:
        "OP_PUSHBYTES_72 3045022100feeafd13943ece155a277351b5649a3b69186de24f90785a8e2cd3170eb6c0c902201b072cb2ef7eeff1eea8ba185dfca77c5bb6b38e521fd008835d46c50c73aa5c01 OP_PUSHBYTES_33 038b572d6693afe809ed2df3233ba99b67415a60655a71fa5f06a3cf982e7d37e7",
      is_coinbase: false,
      sequence: 4294967295,
    },
  ],
  vout: [
    {
      scriptpubkey: "76a9145192aab0e1617a7ecd92123059ca9a8fe1a734fb88ac",
      scriptpubkey_asm:
        "OP_DUP OP_HASH160 OP_PUSHBYTES_20 5192aab0e1617a7ecd92123059ca9a8fe1a734fb OP_EQUALVERIFY OP_CHECKSIG",
      scriptpubkey_type: "p2pkh",
      scriptpubkey_address: "18SKS8AUEah84BwURDXH3rXXd8FpAhSQzm",
      value: 48852,
    },
  ],
};

function serializeTransaction(transaction) {
  const { version, locktime, vin, vout } = transaction;
  let serializedTransaction = "";

  // Serialize version
  let paddedVersion = version.toString(16).padStart(8, "0");
  serializedTransaction += reverseBytes(paddedVersion);

  // Serialize vin length
  serializedTransaction += vin.length.toString(16).padStart(2, "0");

  // Serialize vin
  vin.forEach((input) => {
    serializedTransaction += input.txid.match(/.{2}/g).reverse().join("");
    let paddedInputVout = input.vout.toString(16).padStart(8, "0");
    serializedTransaction += reverseBytes(paddedInputVout);
    serializedTransaction += input.scriptsig
      .match(/.{2}/g)
      .length.toString(16)
      .padStart(2, "0");
    serializedTransaction += input.scriptsig;
    serializedTransaction += input.sequence.toString(16).padStart(8, "0");
  });

  // Serialize vout length
  serializedTransaction += vout.length.toString(16).padStart(2, "0");

  // Serialize vout
  vout.forEach((output) => {
    let paddedOutput = output.value.toString(16).padStart(16, "0");
    serializedTransaction += reverseBytes(paddedOutput);
    serializedTransaction += output.scriptpubkey
      .match(/.{2}/g)
      .length.toString(16)
      .padStart(2, "0");
    serializedTransaction += output.scriptpubkey;
  });

  // Serialize locktime
  serializedTransaction += locktime.toString(16).padStart(8, "0");

  return serializedTransaction;
}

function reverseBytes(hexString) {
  // Split the hex string into pairs of characters
  const pairs = hexString.match(/.{1,2}/g);

  // Reverse the order of the pairs
  const reversedPairs = pairs.reverse();

  // Join the reversed pairs back together
  const reversedHexString = reversedPairs.join("");

  return reversedHexString;
}

function signatureMessageHash(serializedTransactionData) {
  const hash1 = CryptoJS.SHA256(
    CryptoJS.enc.Hex.parse(serializedTransactionData)
  ).toString();
  const hash2 = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(hash1)).toString();
  return hash2;
}

function verifyTransaction(transactionJSON) {
  const { vin, vout, version, locktime } = transactionJSON;
  const serializedTransactionData = serializeTransaction(transactionJSON);

  const messageHash = signatureMessageHash(serializedTransactionData);
  const reverseMessageHashByteOrder = reverseBytes(messageHash);
  //Double SHA256 -> Reverse -> SHA256 for filename
  const filename = CryptoJS.SHA256(
    CryptoJS.enc.Hex.parse(reverseMessageHashByteOrder)
  ).toString();
  console.log("Serialized Trxn : ", serializedTransactionData);
  console.log("MsgH : ", messageHash);
  console.log("RevMsgH : ", reverseMessageHashByteOrder);
  console.log("Filename : ", filename);

  vin.forEach((input) => {
    const { prevout, scriptsig, scriptsig_asm } = input;
    const verificationResult = verifyP2PKHScript(
      prevout,
      scriptsig,
      scriptsig_asm,
      messageHash
    );
    console.log(verificationResult);
  });
}

verifyTransaction(transactionJSON);
