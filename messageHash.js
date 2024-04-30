import { reverseBytes, doubleSHA256Hash } from "./utils.js";

export function msgHashForSegWitSigVerification(transactionJSON, inputIndex) {
  const { vin, vout, version, locktime } = transactionJSON;

  // Serialize version
  let paddedVersion = version.toString(16).padStart(8, "0");
  paddedVersion = reverseBytes(paddedVersion);

  // Serialize and hash txid+vout
  let serializedInputs = "";
  vin.forEach((input, index) => {
    serializedInputs += reverseBytes(input.txid);
    let vout = input.vout.toString(16).padStart(8, "0");
    serializedInputs += reverseBytes(vout);
  });
  let doubledSHA256Inputs = doubleSHA256Hash(serializedInputs);

  // Serialize and hash sequence
  let serializedSequence = "";
  vin.forEach((input, index) => {
    serializedSequence += reverseBytes(input.sequence.toString(16).padStart(8, "0"));
    
  });
  let doubledSHA256Sequence = doubleSHA256Hash(serializedSequence);

  // Serialize and hash txid+vout for our input index or outpoint

  let serializedInputAtIndex = "";
  let inputAtIndex = vin[inputIndex];
  serializedInputAtIndex += reverseBytes(inputAtIndex.txid);
  let voutAtIndex = inputAtIndex.vout.toString(16).padStart(8, "0");
  serializedInputAtIndex += reverseBytes(voutAtIndex);

  // scriptcode for the input at index

  let pubKeyHash = inputAtIndex.prevout.scriptpubkey_asm.split(" ")[2];
  let scriptCode = `1976a914${pubKeyHash}88ac`;

  // input amount for the input at index in little endian
  let inputAmount = inputAtIndex.prevout.value.toString(16).padStart(16, "0");
  inputAmount = reverseBytes(inputAmount);

  // sequence for the input at index
  let sequenceAtIndex = inputAtIndex.sequence.toString(16).padStart(8, "0");
  sequenceAtIndex = reverseBytes(sequenceAtIndex);
  // serialize and hash all outputs
  let serializedOutputs = "";
  vout.forEach((output) => {
    let value = output.value.toString(16).padStart(16, "0");
    serializedOutputs += reverseBytes(value);
    let scriptPubKey = output.scriptpubkey;
    let scriptPubKeySize = Buffer.from(scriptPubKey, "hex")
      .length.toString(16)
      .padStart(2, "0");
    serializedOutputs += scriptPubKeySize;
    serializedOutputs += scriptPubKey;
  });
  let doubledSHA256Outputs = doubleSHA256Hash(serializedOutputs);

  let locktimeHex = locktime.toString(16).padStart(8, "0");

  let signatureHashType = "01000000";
  let preImage = `${paddedVersion}${doubledSHA256Inputs}${doubledSHA256Sequence}${serializedInputAtIndex}${scriptCode}${inputAmount}${sequenceAtIndex}${doubledSHA256Outputs}${locktimeHex}${signatureHashType}`;
  let doubleSHA256PreImage = doubleSHA256Hash(preImage);
  return doubleSHA256PreImage;
}

export function msgHashForSigVerification(transactionJSON, inputIndex) {
  const { vin, vout, version, locktime } = transactionJSON;
  let serializedTrxnForSigHash = "";
  // Serialize version
  let paddedVersion = version.toString(16).padStart(8, "0");
  serializedTrxnForSigHash += reverseBytes(paddedVersion);

  // Serialize vin length
  serializedTrxnForSigHash += vin.length.toString(16).padStart(2, "0");

  // Serialize vin
  vin.forEach((input, index) => {
    serializedTrxnForSigHash += reverseBytes(input.txid);
    let paddedInputVout = input.vout.toString(16).padStart(8, "0");
    serializedTrxnForSigHash += reverseBytes(paddedInputVout);
    let pubketAtScriptSig = "";
    if (index !== inputIndex) {
      pubketAtScriptSig = "";
    } else {
      pubketAtScriptSig = input.prevout.scriptpubkey;
    }
    let pubketAtScriptSigSize = Buffer.from(pubketAtScriptSig, "hex")
      .length.toString(16)
      .padStart(2, "0");
    serializedTrxnForSigHash += pubketAtScriptSigSize;
    serializedTrxnForSigHash += pubketAtScriptSig;
    serializedTrxnForSigHash += input.sequence.toString(16).padStart(8, "0");
  });

  // Serialize vout length
  serializedTrxnForSigHash += vout.length.toString(16).padStart(2, "0");
  vout.forEach((output) => {
    let paddedOutput = output.value.toString(16).padStart(16, "0");
    serializedTrxnForSigHash += reverseBytes(paddedOutput);
    let pubketAtScriptPubKey = output.scriptpubkey;
    let pubketAtScriptPubKeySize = Buffer.from(pubketAtScriptPubKey, "hex")
      .length.toString(16)
      .padStart(2, "0");
    serializedTrxnForSigHash += pubketAtScriptPubKeySize;
    serializedTrxnForSigHash += pubketAtScriptPubKey;
  });

  // Serialize locktime
  serializedTrxnForSigHash += locktime.toString(16).padStart(8, "0");
  serializedTrxnForSigHash += "01000000";
  return serializedTrxnForSigHash;
}
