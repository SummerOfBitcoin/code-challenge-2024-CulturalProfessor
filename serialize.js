import { reverseBytes } from "./utils.js";

export function serializeSegWitTransactionForWTXID(transaction) {
  const { version, locktime, vin, vout } = transaction;
  let serializedTransaction = "";

  // Serialize version
  let paddedVersion = version.toString(16).padStart(8, "0");
  serializedTransaction += reverseBytes(paddedVersion);

  // Serialize marker
  serializedTransaction += "00";

  // Serialize flag
  serializedTransaction += "01";

  // Serialize vin length
  serializedTransaction += vin.length.toString(16).padStart(2, "0");

  // Serialize vin
  vin.forEach((input) => {
    serializedTransaction += reverseBytes(input.txid);
    let paddedInputVout = input.vout.toString(16).padStart(8, "0");
    serializedTransaction += reverseBytes(paddedInputVout);
    if (input.scriptsig) {
      serializedTransaction += input.scriptsig
        .match(/.{2}/g)
        .length.toString(16)
        .padStart(2, "0");
      serializedTransaction += input.scriptsig;
    } else {
      serializedTransaction += "00";
    }
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

  // Serialize witness
  // Serialize witness
  vin.forEach((input) => {
    if (input.witness && input.witness.length > 0) {
      serializedTransaction += input.witness.length
        .toString(16)
        .padStart(2, "0");
      input.witness.forEach((witnessElement) => {
        let elementSize = witnessElement.length / 2;
        serializedTransaction += elementSize.toString(16).padStart(2, "0");
        serializedTransaction += witnessElement;
      });
    } else {
      // If witness data is not present, add a zero-length witness marker
      serializedTransaction += "00";
    }
  });
  // Serialize locktime
  serializedTransaction += locktime.toString(16).padStart(8, "0");

  return serializedTransaction;
}

export function serializeTransaction(transaction) {
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
    if (input.scriptsig) {
      serializedTransaction += input.scriptsig
        .match(/.{2}/g)
        .length.toString(16)
        .padStart(2, "0");
      serializedTransaction += input.scriptsig;
    } else {
      serializedTransaction += "00";
    }
    serializedTransaction += reverseBytes(input.sequence.toString(16).padStart(8, "0"));
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
