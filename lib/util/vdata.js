const BufferReader = require("../encoding/bufferreader");

const actions = [
  "NO_PROGRAM",
  "ERR",
  "CREATE_TOKEN",
  "MINT",
  "STOP_MINT",
  "BURN",
  "REGISTER_NAME",
  "UPDATE_NAME_FIRST",
  "UPDATE_NAME",
  "RENEW_NAME",
];

exports.parse = (vData) => {
  let bufferReader = new BufferReader(vData);

  let ret = [];

  let action = bufferReader.readInt32LE();

  ret.push(action);

  if (actions[action] === "CREATE_TOKEN") {
    let keyLength = bufferReader.readVarintNum();
    let key = bufferReader.read(keyLength);
    ret.push(key);

    let nameLength = bufferReader.readVarintNum();
    let name = bufferReader.read(nameLength);
    ret.push(name);

    let version = bufferReader.readUInt64LEBN();
    ret.push(version.toString());

    let codeLength = bufferReader.readVarintNum();
    let code = bufferReader.read(codeLength);
    ret.push(code);

    let maxSupply = bufferReader.readUInt64LEBN();
    ret.push(maxSupply.toString());
  }

  return ret;
};
