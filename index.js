import CryptoJS from "crypto-js";
import {
  verifyP2PKHScript,
  verifyP2WPKHScript,
  // verifyP2WSHscript,
} from "./scripts.js";
import { serializeTransaction } from "./serialize.js";
import {
  msgHashForSegWitSigVerification,
  msgHashForSigVerification,
} from "./messageHash.js";
import { reverseBytes, doubleSHA256Hash } from "./utils.js";
import fs from "fs";

const transactionJSON = {
  version: 2,
  locktime: 0,
  vin: [
    {
      txid: "2af93c8cfa2893c85559ca4be6736f0c7b60fd79ef7a40ed164ca5639d82784d",
      vout: 1,
      prevout: {
        scriptpubkey: "0014f072e4acac6b1f0b63fb691e28be84f4d0c0f9c3",
        scriptpubkey_asm:
          "OP_0 OP_PUSHBYTES_20 f072e4acac6b1f0b63fb691e28be84f4d0c0f9c3",
        scriptpubkey_type: "v0_p2wpkh",
        scriptpubkey_address: "bc1q7pewft9vdv0skclmdy0z305y7ngvp7wremu33f",
        value: 423477,
      },
      scriptsig: "",
      scriptsig_asm: "",
      witness: [
        "3044022023ed16234c7ca604f97f2cf7afb4e7bf1cd66a959f2670cd11bd80a1c8966891022027b5e0ca2dc14f5183dd5c883bdaf13d2b5705308902eb4ded504e93fa1900d801",
        "039c68804f615b49343be8c2b5b5376329045f47a5e49a9edea8a04d0e0dbb9478",
      ],
      is_coinbase: false,
      sequence: 4294967293,
    },
  ],
  vout: [
    {
      scriptpubkey: "0014d421f3b1e2c8234c2023315ad4a81ff8c9e9bf2b",
      scriptpubkey_asm:
        "OP_0 OP_PUSHBYTES_20 d421f3b1e2c8234c2023315ad4a81ff8c9e9bf2b",
      scriptpubkey_type: "v0_p2wpkh",
      scriptpubkey_address: "bc1q6ssl8v0zeq35cgprx9ddf2qllry7n0etdrkqxp",
      value: 285061,
    },
    {
      scriptpubkey: "a91455e1cc9b31942addc939ebb97d40ac67e03eb10f87",
      scriptpubkey_asm:
        "OP_HASH160 OP_PUSHBYTES_20 55e1cc9b31942addc939ebb97d40ac67e03eb10f OP_EQUAL",
      scriptpubkey_type: "p2sh",
      scriptpubkey_address: "39X7rezLMxawPjicKma2Ftitw4xjZ7SdeB",
      value: 136327,
    },
  ],
};
function verifyTransaction(transactionJSON, realFilename) {
  const { vin, vout, version, locktime } = transactionJSON;
  const serializedTransactionData = serializeTransaction(transactionJSON);
  const doubledSHA256Trxn = doubleSHA256Hash(serializedTransactionData);
  const reversedDoubledSHA256Trxn = reverseBytes(doubledSHA256Trxn);
  // Double SHA256 -> Reverse -> SHA256 for filename
  const filename = CryptoJS.SHA256(
    CryptoJS.enc.Hex.parse(reversedDoubledSHA256Trxn)
  ).toString();
  // console.log("Filename:", filename);

  // SERIALIZATION FOR SEGREGATED WITNESS NOT INCLUDEDS MARKER,FLAG AND WITNESS

  let flag = false;
  let value = 0;
  let inputValue = 0;

  vin.forEach((input, index) => {
    const { prevout, scriptsig, scriptsig_asm, vout } = input;
    inputValue += prevout.value;
    if (vout === 0) {
      value += prevout.value;
    }
    if (input.prevout.scriptpubkey_type === "v0_p2wpkh") {
      const { witness } = input;
      const msgHash = msgHashForSegWitSigVerification(transactionJSON, index);
      const verificationResult = verifyP2WPKHScript(prevout, witness, msgHash);
      // Implement P2WPKH verification
      if (!verificationResult) {
        // console.log("P2WPKH verification failed", vin.length);
        flag = false;
        return;
      } else {
        // console.log("P2WPKH verification passed", vin.length);
        flag = true;
      }
    } else {
      flag = false;
      // console.log('file',realFilename)
      return;
    }
  });
  let outputValue = 0;
  transactionJSON.vout.forEach((output) => {
    outputValue += output.value;
  });
  let fees = inputValue - outputValue;
  return { flag, doubledSHA256Trxn, value, filename, fees };
}

// console.log("Verification result:", verifyTransaction(transactionJSON));

export async function readTransactions() {
  const mempoolPath = "./mempool";
  const validTxids = [];
  const validFiles = [];
  let totalFees = 0;
  let totalValue = 0;
  fs.writeFileSync("./nonSerial.txt", ``, { flag: "w" });

  const files = await fs.promises.readdir(mempoolPath);
  for (const file of files) {
    const filePath = `${mempoolPath}/${file}`;
    try {
      if (
        file ===
          "135042e51af63eab5e03844221138d1cf02fa2153857f052d04fb6acb90be48f.json" ||
        file ===
          "1c23e360add7663ac0fa03734f9e41b610f75d159dc3e90c0b0e210afc2e6ad5.json" ||
        file ===
          "25228e1d94fe8aff6f67228d128a4475b9dbaa47021dcb1d5c805e801f6167f2.json" ||
        file ===
          "7a77de4a825200f3823f7489415bd062fa165d91d58716eeff6bf99882f7e357.json" ||
        file ===
          "7ae5572b467379e6565b0880cadb3bab4eeb8aa4fc025cb9361ed5f3dfc08192.json" ||
        file ===
          "8c16f4079d0f45fe63d5a3d3674951eeb1aceb737eca3cf37905ddbcba4cf5ab.json" ||
        file ===
          "9bf76ba33f8680af53c8bb7001e6ff83b452bcfe3a94f47a906242d6a815015b.json" ||
        file ===
          "a4d6c8026529393b3f91cbd2bc93db7ef6b6d0f32a340b1f218e2d3b62f37a03.json" ||
        file ===
          "a84025ae6b9f390a93eef3f9c4456d1b54c25b3fcf076cb5ce581627e56a31c7.json" ||
        file ===
          "c9898348b700cb4637ab9121b572f803165b02a22ae59f51eea0cdf2afaa5d85.json" ||
        file ===
          "f6dfb38913ad5eddb1a88caaea636e6948fb38112acfbaa7f7f3307f0bd25050.json" ||
        file ===
          "0747edeae87cf8ab6ee6c36da8c0c93d3ca2d9a8b4c119e81be3a69065bc8d89.json" ||
        file ===
          "1ccd927e58ef5395ddef40eee347ded55d2e201034bc763bfb8a263d66b99e5e.json" ||
        file ===
          "3edc8ef22dcfb7972078778eed6578f4a7eb0560f24bd3ab3f31125247e845ce.json" ||
        file ===
          "753b075bd84cdc7400acaf8b52cea866f099de2ebb70ea89fc98abe5f1162d5f.json" ||
        file ===
          "b8149f17a3ef9b95c080781bdda1f2afb27bdf74b62e83a38b9708db5270dd05.json" ||
        file ===
          "c2cc46c2685d2ea335e5ea7b9964a79d2c35655fa5c52beec38827c841f2a42c.json" ||
        file ===
          "d43ae139c4823b3ce2cfd98122e5f5b1f766abeb159fdf39bdce429afdeb5033.json" ||
        file ===
          "0e520e912a2ed0aef0e88355843e8970858ca5e746ec071d473f398b77093da9.json" ||
        file ===
          "0faf7ff9d0c79822856ee74df020de106249a1d87fc51af3a3c6201ef71515a9.json" ||
        file ===
          "211d49c9f0954a2ebcde1e22696a2d78bf47b5658d10471a8e448393d93bd133.json" ||
        file ===
          "2e1487de05eae97835ae29c265238920789ca55eecc18930b5035c6874f36d9a.json" ||
        file ===
          "3304e7eb21e0eca8ec2b08265a551778d125792f421fc04c89f68aa05ffba3c9.json" ||
        file ===
          "3dc3838f32122e54ac65a4230c3ab69db6d977c66cd3402335e2dadcbb7fd321.json" ||
        file ===
          "3eb5323419b8140ccce1e692b26ade670e3db270aa3c6a3d5681a5a8c3f5d22c.json" ||
        file ===
          "4a182e4d00d047237dc773db2bca6414d60529557dd2b072f39bb9fbd56a1262.json" ||
        file ===
          "55c90678c191475fb621dae5bf78da7aaa73faba395fdd003a9317699b5b39b1.json" ||
        file ===
          "5da40502e3620b0d83819e07f1047f8345d993f84236ed977119bebd1efc4719.json" ||
        file ===
          "5e4d8484ebcacb1a06c8bdd81af88290fd38b855eadb373db165769961beee19.json" ||
        file ===
          "619a4aa079cbb2f8c2bc230a3574d2a49b373a02577763802b07dccec7d1264b.json" ||
        file ===
          "6b70be27f2d6ab4f8236ff2390f54a823596fe5768495ff603bb59a0992b59dc.json" ||
        file ===
          "6e3c127f222945e437e7298a44ce7d179af61e00e0789732a09d16e6af97c392.json" ||
        file ===
          "83ec2002a07a4b570fc33492a82052398fc1c02c424c304e92dafff9c8d78887.json" ||
        file ===
          "85edde5b0393ab11d90dae927a553acd972e74859261f33be1eaaa1a68dc3eae.json" ||
        file ===
          "88a3f203d03cc8885ced0955a25a971365e9cd17125401f08d0dacde90cd01ea.json" ||
        file ===
          "8c3611431fad43febf5d0f7fb4fbf38cd40d54624bda0f76dd315061e777e5fe.json" ||
        file ===
          "8c7fe32f4600edcad2bf610d954d95671d8972b4ef4598759fd68c4856cd3951.json" ||
        file ===
          "94ce490fd6129a5b2ad677f74a7d4331ceea02c142bc15f9a9b807415d5f1864.json" ||
        file ===
          "95a920f1dda9ac2c10c29bbe7d44d698d7e1eae4e5ac9b0a9c7e19ad1eeb829e.json" ||
        file ===
          "c64914a017f66f369f6e0f94d81989e60d8320b92135aaa980cd78dc569bf4cd.json" ||
        file ===
          "d06199806b530f6dd2645db2de9e891e4e13ffc5e98f651cf061a3e19b94599b.json" ||
        file ===
          "db903e8f8f9a3ee5c6759e6fa035ed29f829f60ca7dd8fe7208efe34f38c51e3.json" ||
        file ===
          "dcd2a039db976c83b899db5d8b618199e51e625e9d851120b796cfd79bc9bdcc.json" ||
        file ===
          "f47c1418421ed1189b4c07cd37236e9353b5ed4f1e95192a499a932d3cce37ee.json" ||
        file ===
          "ff2273b8e9ac16c15d1cacb027111ab2a07b9d732f207ba6b28f43ab28f92d1b.json"
      ) {
        continue;
      }
      const data = await fs.promises.readFile(filePath, "utf8");
      const transactionJSON = JSON.parse(data);
      const { flag, doubledSHA256Trxn, value, filename, fees } =
        verifyTransaction(transactionJSON, file);

      if (`${filename}.json` !== file) {
        fs.writeFileSync("./nonSerial.txt", `${file}\t${flag}\n`, {
          flag: "a",
        });
      }

      totalValue += value;
      if (flag) {
        if (transactionJSON.vin.length < 300) {
          let invf = [];
          transactionJSON.vin.forEach((input) => {
            if (
              !input.witness ||
              input.prevout.scriptpubkey_type !== "v0_p2wpkh"
            ) {
              console.log(file);
            }
          });
          // console.log("Input", file, transactionJSON.vin.length);
          validTxids.push(doubledSHA256Trxn);
          validFiles.push(file);
          totalFees += fees;
        }
      }
    } catch (e) {
      console.error("Error processing file:", filePath, e);
    }
  }
  return {
    totalValue: totalValue,
    validTxids: validTxids,
    validFiles: validFiles,
    totalFees: totalFees,
  };
}

// await readTransactions();
