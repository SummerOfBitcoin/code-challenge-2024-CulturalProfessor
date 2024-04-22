import CryptoJS from "crypto-js";

export function reverseBytes(hexString) {
  return hexString.match(/.{2}/g).reverse().join("");
}

export function doubleSHA256Hash(serializedTransactionData) {
  const hash1 = CryptoJS.SHA256(
    CryptoJS.enc.Hex.parse(serializedTransactionData)
  ).toString();
  const hash2 = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(hash1)).toString();
  return hash2;
}

export function derToRS(DEREncodedSignatureHex) {
  let r, s;
  if (DEREncodedSignatureHex.length === 144) {
    r = DEREncodedSignatureHex.substr(10, 64);
    s = DEREncodedSignatureHex.substr(78, 64);
  }
  if (DEREncodedSignatureHex.length === 142) {
    r = DEREncodedSignatureHex.substr(8, 64);
    s = DEREncodedSignatureHex.substr(76, 64);
  }
  // implement for 71 bytes also
  if (r !== undefined && s !== undefined) {
    r = BigInt(`0x${r}`).toString(16);
    s = BigInt(`0x${s}`).toString(16);
    return { r, s };
  } else {
    return { r: undefined, s: undefined };
  }
}