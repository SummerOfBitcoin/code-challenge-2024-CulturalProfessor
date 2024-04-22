import { reverseBytes } from "./utils.js";

export function serializeSegWitTransaction(transaction) {
  const { version, locktime, vin, vout } = transaction;

  let serializedTransaction = "";
  // Serialize version
  let paddedVersion = version.toString(16).padStart(8, "0");
  serializedTransaction += reverseBytes(paddedVersion);

  // Serialize marker and flag
  serializedTransaction += "00";
  serializedTransaction += "01";

  // Serialize vin length
  serializedTransaction += vin.length.toString(16).padStart(2, "0");

  // Serialize vin
  vin.forEach((input) => {
    serializedTransaction += input.txid.match(/.{2}/g).reverse().join("");
    let paddedInputVout = input.vout.toString(16).padStart(8, "0");
    serializedTransaction += reverseBytes(paddedInputVout);
    serializedTransaction += "00"; // scriptSig length for SegWit inputs
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
  vin.forEach((input) => {
    serializedTransaction += input.witness.length.toString(16).padStart(2, "0");
    input.witness.forEach((witnessElement) => {
      let elementSize = witnessElement.length / 2;
      serializedTransaction += elementSize.toString(16).padStart(2, "0");
      serializedTransaction += witnessElement;
    });
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

  // Serialize locktime
  serializedTransaction += locktime.toString(16).padStart(8, "0");

  return serializedTransaction;
}
