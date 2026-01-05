var $root = {};
export const encodePunchNatType = {
  Symmetric: 0,
  Cone: 1,
};

export const decodePunchNatType = {
  0: "Symmetric",
  1: "Cone",
};

export const encodePunchNatModel = {
  All: 0,
  IPv4: 1,
  IPv6: 2,
  IPv4Tcp: 3,
  IPv4Udp: 4,
  IPv6Tcp: 5,
  IPv6Udp: 6,
};

export const decodePunchNatModel = {
  0: "All",
  1: "IPv4",
  2: "IPv6",
  3: "IPv4Tcp",
  4: "IPv4Udp",
  5: "IPv6Tcp",
  6: "IPv6Udp",
};

export function encodeHandshakeRequest(message) {
  let bb = popByteBuffer();
  _encodeHandshakeRequest(message, bb);
  return toUint8Array(bb);
}

function _encodeHandshakeRequest(message, bb) {
  // optional string version = 1;
  let $version = message.version;
  if ($version !== undefined) {
    writeVarint32(bb, 10);
    writeString(bb, $version);
  }

  // optional bool secret = 2;
  let $secret = message.secret;
  if ($secret !== undefined) {
    writeVarint32(bb, 16);
    writeByte(bb, $secret ? 1 : 0);
  }

  // optional string key_finger = 3;
  let $key_finger = message.key_finger;
  if ($key_finger !== undefined) {
    writeVarint32(bb, 26);
    writeString(bb, $key_finger);
  }
}

export function decodeHandshakeRequest(binary) {
  return _decodeHandshakeRequest(wrapByteBuffer(binary));
}

function _decodeHandshakeRequest(bb) {
  let message = {};

  end_of_message: while (!isAtEnd(bb)) {
    let tag = readVarint32(bb);

    switch (tag >>> 3) {
      case 0:
        break end_of_message;

      // optional string version = 1;
      case 1: {
        message.version = readString(bb, readVarint32(bb));
        break;
      }

      // optional bool secret = 2;
      case 2: {
        message.secret = !!readByte(bb);
        break;
      }

      // optional string key_finger = 3;
      case 3: {
        message.key_finger = readString(bb, readVarint32(bb));
        break;
      }

      default:
        skipUnknownField(bb, tag & 7);
    }
  }

  return message;
}

export function encodeHandshakeResponse(message) {
  let bb = popByteBuffer();
  _encodeHandshakeResponse(message, bb);
  return toUint8Array(bb);
}

function _encodeHandshakeResponse(message, bb) {
  // optional string version = 1;
  let $version = message.version;
  if ($version !== undefined) {
    writeVarint32(bb, 10);
    writeString(bb, $version);
  }

  // optional bool secret = 2;
  let $secret = message.secret;
  if ($secret !== undefined) {
    writeVarint32(bb, 16);
    writeByte(bb, $secret ? 1 : 0);
  }

  // optional bytes public_key = 3;
  let $public_key = message.public_key;
  if ($public_key !== undefined) {
    writeVarint32(bb, 26);
    writeVarint32(bb, $public_key.length), writeBytes(bb, $public_key);
  }

  // optional string key_finger = 4;
  let $key_finger = message.key_finger;
  if ($key_finger !== undefined) {
    writeVarint32(bb, 34);
    writeString(bb, $key_finger);
  }
}

export function decodeHandshakeResponse(binary) {
  return _decodeHandshakeResponse(wrapByteBuffer(binary));
}

function _decodeHandshakeResponse(bb) {
  let message = {};

  end_of_message: while (!isAtEnd(bb)) {
    let tag = readVarint32(bb);

    switch (tag >>> 3) {
      case 0:
        break end_of_message;

      // optional string version = 1;
      case 1: {
        message.version = readString(bb, readVarint32(bb));
        break;
      }

      // optional bool secret = 2;
      case 2: {
        message.secret = !!readByte(bb);
        break;
      }

      // optional bytes public_key = 3;
      case 3: {
        message.public_key = readBytes(bb, readVarint32(bb));
        break;
      }

      // optional string key_finger = 4;
      case 4: {
        message.key_finger = readString(bb, readVarint32(bb));
        break;
      }

      default:
        skipUnknownField(bb, tag & 7);
    }
  }

  return message;
}

export function encodeSecretHandshakeRequest(message) {
  let bb = popByteBuffer();
  _encodeSecretHandshakeRequest(message, bb);
  return toUint8Array(bb);
}

function _encodeSecretHandshakeRequest(message, bb) {
  // optional string token = 1;
  let $token = message.token;
  if ($token !== undefined) {
    writeVarint32(bb, 10);
    writeString(bb, $token);
  }

  // optional bytes key = 2;
  let $key = message.key;
  if ($key !== undefined) {
    writeVarint32(bb, 18);
    writeVarint32(bb, $key.length), writeBytes(bb, $key);
  }
}

export function decodeSecretHandshakeRequest(binary) {
  return _decodeSecretHandshakeRequest(wrapByteBuffer(binary));
}

function _decodeSecretHandshakeRequest(bb) {
  let message = {};

  end_of_message: while (!isAtEnd(bb)) {
    let tag = readVarint32(bb);

    switch (tag >>> 3) {
      case 0:
        break end_of_message;

      // optional string token = 1;
      case 1: {
        message.token = readString(bb, readVarint32(bb));
        break;
      }

      // optional bytes key = 2;
      case 2: {
        message.key = readBytes(bb, readVarint32(bb));
        break;
      }

      default:
        skipUnknownField(bb, tag & 7);
    }
  }

  return message;
}

export function encodeRegistrationRequest(message) {
  let bb = popByteBuffer();
  _encodeRegistrationRequest(message, bb);
  return toUint8Array(bb);
}

function _encodeRegistrationRequest(message, bb) {
  // optional string token = 1;
  let $token = message.token;
  if ($token !== undefined) {
    writeVarint32(bb, 10);
    writeString(bb, $token);
  }

  // optional string device_id = 2;
  let $device_id = message.device_id;
  if ($device_id !== undefined) {
    writeVarint32(bb, 18);
    writeString(bb, $device_id);
  }

  // optional string name = 3;
  let $name = message.name;
  if ($name !== undefined) {
    writeVarint32(bb, 26);
    writeString(bb, $name);
  }

  // optional bool is_fast = 4;
  let $is_fast = message.is_fast;
  if ($is_fast !== undefined) {
    writeVarint32(bb, 32);
    writeByte(bb, $is_fast ? 1 : 0);
  }

  // optional string version = 5;
  let $version = message.version;
  if ($version !== undefined) {
    writeVarint32(bb, 42);
    writeString(bb, $version);
  }

  // optional fixed32 virtual_ip = 6;
  let $virtual_ip = message.virtual_ip;
  if ($virtual_ip !== undefined) {
    writeVarint32(bb, 53);
    writeInt32(bb, $virtual_ip);
  }

  // optional bool allow_ip_change = 7;
  let $allow_ip_change = message.allow_ip_change;
  if ($allow_ip_change !== undefined) {
    writeVarint32(bb, 56);
    writeByte(bb, $allow_ip_change ? 1 : 0);
  }

  // optional bool client_secret = 8;
  let $client_secret = message.client_secret;
  if ($client_secret !== undefined) {
    writeVarint32(bb, 64);
    writeByte(bb, $client_secret ? 1 : 0);
  }

  // optional bytes client_secret_hash = 9;
  let $client_secret_hash = message.client_secret_hash;
  if ($client_secret_hash !== undefined) {
    writeVarint32(bb, 74);
    writeVarint32(bb, $client_secret_hash.length),
      writeBytes(bb, $client_secret_hash);
  }
}

export function decodeRegistrationRequest(binary) {
  return _decodeRegistrationRequest(wrapByteBuffer(binary));
}

function _decodeRegistrationRequest(bb) {
  let message = {};

  end_of_message: while (!isAtEnd(bb)) {
    let tag = readVarint32(bb);

    switch (tag >>> 3) {
      case 0:
        break end_of_message;

      // optional string token = 1;
      case 1: {
        message.token = readString(bb, readVarint32(bb));
        break;
      }

      // optional string device_id = 2;
      case 2: {
        message.device_id = readString(bb, readVarint32(bb));
        break;
      }

      // optional string name = 3;
      case 3: {
        message.name = readString(bb, readVarint32(bb));
        break;
      }

      // optional bool is_fast = 4;
      case 4: {
        message.is_fast = !!readByte(bb);
        break;
      }

      // optional string version = 5;
      case 5: {
        message.version = readString(bb, readVarint32(bb));
        break;
      }

      // optional fixed32 virtual_ip = 6;
      case 6: {
        message.virtual_ip = readInt32(bb) >>> 0;
        break;
      }

      // optional bool allow_ip_change = 7;
      case 7: {
        message.allow_ip_change = !!readByte(bb);
        break;
      }

      // optional bool client_secret = 8;
      case 8: {
        message.client_secret = !!readByte(bb);
        break;
      }

      // optional bytes client_secret_hash = 9;
      case 9: {
        message.client_secret_hash = readBytes(bb, readVarint32(bb));
        break;
      }

      default:
        skipUnknownField(bb, tag & 7);
    }
  }

  return message;
}

export function encodeRegistrationResponse(message) {
  let bb = popByteBuffer();
  _encodeRegistrationResponse(message, bb);
  return toUint8Array(bb);
}

function _encodeRegistrationResponse(message, bb) {
  // optional fixed32 virtual_ip = 1;
  let $virtual_ip = message.virtual_ip;
  if ($virtual_ip !== undefined) {
    writeVarint32(bb, 13);
    writeInt32(bb, $virtual_ip);
  }

  // optional fixed32 virtual_gateway = 2;
  let $virtual_gateway = message.virtual_gateway;
  if ($virtual_gateway !== undefined) {
    writeVarint32(bb, 21);
    writeInt32(bb, $virtual_gateway);
  }

  // optional fixed32 virtual_netmask = 3;
  let $virtual_netmask = message.virtual_netmask;
  if ($virtual_netmask !== undefined) {
    writeVarint32(bb, 29);
    writeInt32(bb, $virtual_netmask);
  }

  // optional uint32 epoch = 4;
  let $epoch = message.epoch;
  if ($epoch !== undefined) {
    writeVarint32(bb, 32);
    writeVarint32(bb, $epoch);
  }

  // repeated DeviceInfo device_info_list = 5;
  let array$device_info_list = message.device_info_list;
  if (array$device_info_list !== undefined) {
    for (let value of array$device_info_list) {
      writeVarint32(bb, 42);
      let nested = popByteBuffer();
      _encodeDeviceInfo(value, nested);
      writeVarint32(bb, nested.limit);
      writeByteBuffer(bb, nested);
      pushByteBuffer(nested);
    }
  }

  // optional fixed32 public_ip = 6;
  let $public_ip = message.public_ip;
  if ($public_ip !== undefined) {
    writeVarint32(bb, 53);
    writeInt32(bb, $public_ip);
  }

  // optional uint32 public_port = 7;
  let $public_port = message.public_port;
  if ($public_port !== undefined) {
    writeVarint32(bb, 56);
    writeVarint32(bb, $public_port);
  }

  // optional bytes public_ipv6 = 8;
  let $public_ipv6 = message.public_ipv6;
  if ($public_ipv6 !== undefined) {
    writeVarint32(bb, 66);
    writeVarint32(bb, $public_ipv6.length), writeBytes(bb, $public_ipv6);
  }
}

export function decodeRegistrationResponse(binary) {
  return _decodeRegistrationResponse(wrapByteBuffer(binary));
}

function _decodeRegistrationResponse(bb) {
  let message = {};

  end_of_message: while (!isAtEnd(bb)) {
    let tag = readVarint32(bb);

    switch (tag >>> 3) {
      case 0:
        break end_of_message;

      // optional fixed32 virtual_ip = 1;
      case 1: {
        message.virtual_ip = readInt32(bb) >>> 0;
        break;
      }

      // optional fixed32 virtual_gateway = 2;
      case 2: {
        message.virtual_gateway = readInt32(bb) >>> 0;
        break;
      }

      // optional fixed32 virtual_netmask = 3;
      case 3: {
        message.virtual_netmask = readInt32(bb) >>> 0;
        break;
      }

      // optional uint32 epoch = 4;
      case 4: {
        message.epoch = readVarint32(bb) >>> 0;
        break;
      }

      // repeated DeviceInfo device_info_list = 5;
      case 5: {
        let limit = pushTemporaryLength(bb);
        let values =
          message.device_info_list || (message.device_info_list = []);
        values.push(_decodeDeviceInfo(bb));
        bb.limit = limit;
        break;
      }

      // optional fixed32 public_ip = 6;
      case 6: {
        message.public_ip = readInt32(bb) >>> 0;
        break;
      }

      // optional uint32 public_port = 7;
      case 7: {
        message.public_port = readVarint32(bb) >>> 0;
        break;
      }

      // optional bytes public_ipv6 = 8;
      case 8: {
        message.public_ipv6 = readBytes(bb, readVarint32(bb));
        break;
      }

      default:
        skipUnknownField(bb, tag & 7);
    }
  }

  return message;
}

export function encodeDeviceInfo(message) {
  let bb = popByteBuffer();
  _encodeDeviceInfo(message, bb);
  return toUint8Array(bb);
}

function _encodeDeviceInfo(message, bb) {
  // optional string name = 1;
  let $name = message.name;
  if ($name !== undefined) {
    writeVarint32(bb, 10);
    writeString(bb, $name);
  }

  // optional fixed32 virtual_ip = 2;
  let $virtual_ip = message.virtual_ip;
  if ($virtual_ip !== undefined) {
    writeVarint32(bb, 21);
    writeInt32(bb, $virtual_ip);
  }

  // optional uint32 device_status = 3;
  let $device_status = message.device_status;
  if ($device_status !== undefined) {
    writeVarint32(bb, 24);
    writeVarint32(bb, $device_status);
  }

  // optional bool client_secret = 4;
  let $client_secret = message.client_secret;
  if ($client_secret !== undefined) {
    writeVarint32(bb, 32);
    writeByte(bb, $client_secret ? 1 : 0);
  }

  // optional bytes client_secret_hash = 5;
  let $client_secret_hash = message.client_secret_hash;
  if ($client_secret_hash !== undefined) {
    writeVarint32(bb, 42);
    writeVarint32(bb, $client_secret_hash.length),
      writeBytes(bb, $client_secret_hash);
  }

  // optional bool wireguard = 6;
  let $wireguard = message.wireguard;
  if ($wireguard !== undefined) {
    writeVarint32(bb, 48);
    writeByte(bb, $wireguard ? 1 : 0);
  }
}

export function decodeDeviceInfo(binary) {
  return _decodeDeviceInfo(wrapByteBuffer(binary));
}

function _decodeDeviceInfo(bb) {
  let message = {};

  end_of_message: while (!isAtEnd(bb)) {
    let tag = readVarint32(bb);

    switch (tag >>> 3) {
      case 0:
        break end_of_message;

      // optional string name = 1;
      case 1: {
        message.name = readString(bb, readVarint32(bb));
        break;
      }

      // optional fixed32 virtual_ip = 2;
      case 2: {
        message.virtual_ip = readInt32(bb) >>> 0;
        break;
      }

      // optional uint32 device_status = 3;
      case 3: {
        message.device_status = readVarint32(bb) >>> 0;
        break;
      }

      // optional bool client_secret = 4;
      case 4: {
        message.client_secret = !!readByte(bb);
        break;
      }

      // optional bytes client_secret_hash = 5;
      case 5: {
        message.client_secret_hash = readBytes(bb, readVarint32(bb));
        break;
      }

      // optional bool wireguard = 6;
      case 6: {
        message.wireguard = !!readByte(bb);
        break;
      }

      default:
        skipUnknownField(bb, tag & 7);
    }
  }

  return message;
}

export function encodeDeviceList(message) {
  let bb = popByteBuffer();
  _encodeDeviceList(message, bb);
  return toUint8Array(bb);
}

function _encodeDeviceList(message, bb) {
  // optional uint32 epoch = 1;
  let $epoch = message.epoch;
  if ($epoch !== undefined) {
    writeVarint32(bb, 8);
    writeVarint32(bb, $epoch);
  }

  // repeated DeviceInfo device_info_list = 2;
  let array$device_info_list = message.device_info_list;
  if (array$device_info_list !== undefined) {
    for (let value of array$device_info_list) {
      writeVarint32(bb, 18);
      let nested = popByteBuffer();
      _encodeDeviceInfo(value, nested);
      writeVarint32(bb, nested.limit);
      writeByteBuffer(bb, nested);
      pushByteBuffer(nested);
    }
  }
}

export function decodeDeviceList(binary) {
  return _decodeDeviceList(wrapByteBuffer(binary));
}

function _decodeDeviceList(bb) {
  let message = {};

  end_of_message: while (!isAtEnd(bb)) {
    let tag = readVarint32(bb);

    switch (tag >>> 3) {
      case 0:
        break end_of_message;

      // optional uint32 epoch = 1;
      case 1: {
        message.epoch = readVarint32(bb) >>> 0;
        break;
      }

      // repeated DeviceInfo device_info_list = 2;
      case 2: {
        let limit = pushTemporaryLength(bb);
        let values =
          message.device_info_list || (message.device_info_list = []);
        values.push(_decodeDeviceInfo(bb));
        bb.limit = limit;
        break;
      }

      default:
        skipUnknownField(bb, tag & 7);
    }
  }

  return message;
}

export function encodePunchInfo(message) {
  let bb = popByteBuffer();
  _encodePunchInfo(message, bb);
  return toUint8Array(bb);
}

function _encodePunchInfo(message, bb) {
  // repeated fixed32 public_ip_list = 2;
  let array$public_ip_list = message.public_ip_list;
  if (array$public_ip_list !== undefined) {
    let packed = popByteBuffer();
    for (let value of array$public_ip_list) {
      writeInt32(packed, value);
    }
    writeVarint32(bb, 18);
    writeVarint32(bb, packed.offset);
    writeByteBuffer(bb, packed);
    pushByteBuffer(packed);
  }

  // optional uint32 public_port = 3;
  let $public_port = message.public_port;
  if ($public_port !== undefined) {
    writeVarint32(bb, 24);
    writeVarint32(bb, $public_port);
  }

  // optional uint32 public_port_range = 4;
  let $public_port_range = message.public_port_range;
  if ($public_port_range !== undefined) {
    writeVarint32(bb, 32);
    writeVarint32(bb, $public_port_range);
  }

  // optional PunchNatType nat_type = 5;
  let $nat_type = message.nat_type;
  if ($nat_type !== undefined) {
    writeVarint32(bb, 40);
    writeVarint32(bb, encodePunchNatType[$nat_type]);
  }

  // optional bool reply = 6;
  let $reply = message.reply;
  if ($reply !== undefined) {
    writeVarint32(bb, 48);
    writeByte(bb, $reply ? 1 : 0);
  }

  // optional fixed32 local_ip = 7;
  let $local_ip = message.local_ip;
  if ($local_ip !== undefined) {
    writeVarint32(bb, 61);
    writeInt32(bb, $local_ip);
  }

  // optional uint32 local_port = 8;
  let $local_port = message.local_port;
  if ($local_port !== undefined) {
    writeVarint32(bb, 64);
    writeVarint32(bb, $local_port);
  }

  // optional bytes ipv6 = 9;
  let $ipv6 = message.ipv6;
  if ($ipv6 !== undefined) {
    writeVarint32(bb, 74);
    writeVarint32(bb, $ipv6.length), writeBytes(bb, $ipv6);
  }

  // optional uint32 ipv6_port = 10;
  let $ipv6_port = message.ipv6_port;
  if ($ipv6_port !== undefined) {
    writeVarint32(bb, 80);
    writeVarint32(bb, $ipv6_port);
  }

  // optional uint32 tcp_port = 11;
  let $tcp_port = message.tcp_port;
  if ($tcp_port !== undefined) {
    writeVarint32(bb, 88);
    writeVarint32(bb, $tcp_port);
  }

  // repeated uint32 udp_ports = 12;
  let array$udp_ports = message.udp_ports;
  if (array$udp_ports !== undefined) {
    let packed = popByteBuffer();
    for (let value of array$udp_ports) {
      writeVarint32(packed, value);
    }
    writeVarint32(bb, 98);
    writeVarint32(bb, packed.offset);
    writeByteBuffer(bb, packed);
    pushByteBuffer(packed);
  }

  // repeated uint32 public_ports = 13;
  let array$public_ports = message.public_ports;
  if (array$public_ports !== undefined) {
    let packed = popByteBuffer();
    for (let value of array$public_ports) {
      writeVarint32(packed, value);
    }
    writeVarint32(bb, 106);
    writeVarint32(bb, packed.offset);
    writeByteBuffer(bb, packed);
    pushByteBuffer(packed);
  }

  // optional uint32 public_tcp_port = 14;
  let $public_tcp_port = message.public_tcp_port;
  if ($public_tcp_port !== undefined) {
    writeVarint32(bb, 112);
    writeVarint32(bb, $public_tcp_port);
  }

  // optional PunchNatModel punch_model = 15;
  let $punch_model = message.punch_model;
  if ($punch_model !== undefined) {
    writeVarint32(bb, 120);
    writeVarint32(bb, encodePunchNatModel[$punch_model]);
  }
}

export function decodePunchInfo(binary) {
  return _decodePunchInfo(wrapByteBuffer(binary));
}

function _decodePunchInfo(bb) {
  let message = {};

  end_of_message: while (!isAtEnd(bb)) {
    let tag = readVarint32(bb);

    switch (tag >>> 3) {
      case 0:
        break end_of_message;

      // repeated fixed32 public_ip_list = 2;
      case 2: {
        let values = message.public_ip_list || (message.public_ip_list = []);
        if ((tag & 7) === 2) {
          let outerLimit = pushTemporaryLength(bb);
          while (!isAtEnd(bb)) {
            values.push(readInt32(bb) >>> 0);
          }
          bb.limit = outerLimit;
        } else {
          values.push(readInt32(bb) >>> 0);
        }
        break;
      }

      // optional uint32 public_port = 3;
      case 3: {
        message.public_port = readVarint32(bb) >>> 0;
        break;
      }

      // optional uint32 public_port_range = 4;
      case 4: {
        message.public_port_range = readVarint32(bb) >>> 0;
        break;
      }

      // optional PunchNatType nat_type = 5;
      case 5: {
        message.nat_type = decodePunchNatType[readVarint32(bb)];
        break;
      }

      // optional bool reply = 6;
      case 6: {
        message.reply = !!readByte(bb);
        break;
      }

      // optional fixed32 local_ip = 7;
      case 7: {
        message.local_ip = readInt32(bb) >>> 0;
        break;
      }

      // optional uint32 local_port = 8;
      case 8: {
        message.local_port = readVarint32(bb) >>> 0;
        break;
      }

      // optional bytes ipv6 = 9;
      case 9: {
        message.ipv6 = readBytes(bb, readVarint32(bb));
        break;
      }

      // optional uint32 ipv6_port = 10;
      case 10: {
        message.ipv6_port = readVarint32(bb) >>> 0;
        break;
      }

      // optional uint32 tcp_port = 11;
      case 11: {
        message.tcp_port = readVarint32(bb) >>> 0;
        break;
      }

      // repeated uint32 udp_ports = 12;
      case 12: {
        let values = message.udp_ports || (message.udp_ports = []);
        if ((tag & 7) === 2) {
          let outerLimit = pushTemporaryLength(bb);
          while (!isAtEnd(bb)) {
            values.push(readVarint32(bb) >>> 0);
          }
          bb.limit = outerLimit;
        } else {
          values.push(readVarint32(bb) >>> 0);
        }
        break;
      }

      // repeated uint32 public_ports = 13;
      case 13: {
        let values = message.public_ports || (message.public_ports = []);
        if ((tag & 7) === 2) {
          let outerLimit = pushTemporaryLength(bb);
          while (!isAtEnd(bb)) {
            values.push(readVarint32(bb) >>> 0);
          }
          bb.limit = outerLimit;
        } else {
          values.push(readVarint32(bb) >>> 0);
        }
        break;
      }

      // optional uint32 public_tcp_port = 14;
      case 14: {
        message.public_tcp_port = readVarint32(bb) >>> 0;
        break;
      }

      // optional PunchNatModel punch_model = 15;
      case 15: {
        message.punch_model = decodePunchNatModel[readVarint32(bb)];
        break;
      }

      default:
        skipUnknownField(bb, tag & 7);
    }
  }

  return message;
}

export function encodeClientStatusInfo(message) {
  let bb = popByteBuffer();
  _encodeClientStatusInfo(message, bb);
  return toUint8Array(bb);
}

function _encodeClientStatusInfo(message, bb) {
  // optional fixed32 source = 1;
  let $source = message.source;
  if ($source !== undefined) {
    writeVarint32(bb, 13);
    writeInt32(bb, $source);
  }

  // repeated RouteItem p2p_list = 2;
  let array$p2p_list = message.p2p_list;
  if (array$p2p_list !== undefined) {
    for (let value of array$p2p_list) {
      writeVarint32(bb, 18);
      let nested = popByteBuffer();
      _encodeRouteItem(value, nested);
      writeVarint32(bb, nested.limit);
      writeByteBuffer(bb, nested);
      pushByteBuffer(nested);
    }
  }

  // optional uint64 up_stream = 3;
  let $up_stream = message.up_stream;
  if ($up_stream !== undefined) {
    writeVarint32(bb, 24);
    writeVarint64(bb, $up_stream);
  }

  // optional uint64 down_stream = 4;
  let $down_stream = message.down_stream;
  if ($down_stream !== undefined) {
    writeVarint32(bb, 32);
    writeVarint64(bb, $down_stream);
  }

  // optional PunchNatType nat_type = 5;
  let $nat_type = message.nat_type;
  if ($nat_type !== undefined) {
    writeVarint32(bb, 40);
    writeVarint32(bb, encodePunchNatType[$nat_type]);
  }
}

export function decodeClientStatusInfo(binary) {
  return _decodeClientStatusInfo(wrapByteBuffer(binary));
}

function _decodeClientStatusInfo(bb) {
  let message = {};

  end_of_message: while (!isAtEnd(bb)) {
    let tag = readVarint32(bb);

    switch (tag >>> 3) {
      case 0:
        break end_of_message;

      // optional fixed32 source = 1;
      case 1: {
        message.source = readInt32(bb) >>> 0;
        break;
      }

      // repeated RouteItem p2p_list = 2;
      case 2: {
        let limit = pushTemporaryLength(bb);
        let values = message.p2p_list || (message.p2p_list = []);
        values.push(_decodeRouteItem(bb));
        bb.limit = limit;
        break;
      }

      // optional uint64 up_stream = 3;
      case 3: {
        message.up_stream = readVarint64(bb, /* unsigned */ true);
        break;
      }

      // optional uint64 down_stream = 4;
      case 4: {
        message.down_stream = readVarint64(bb, /* unsigned */ true);
        break;
      }

      // optional PunchNatType nat_type = 5;
      case 5: {
        message.nat_type = decodePunchNatType[readVarint32(bb)];
        break;
      }

      default:
        skipUnknownField(bb, tag & 7);
    }
  }

  return message;
}

export function encodeRouteItem(message) {
  let bb = popByteBuffer();
  _encodeRouteItem(message, bb);
  return toUint8Array(bb);
}

function _encodeRouteItem(message, bb) {
  // optional fixed32 next_ip = 1;
  let $next_ip = message.next_ip;
  if ($next_ip !== undefined) {
    writeVarint32(bb, 13);
    writeInt32(bb, $next_ip);
  }
}

export function decodeRouteItem(binary) {
  return _decodeRouteItem(wrapByteBuffer(binary));
}

function _decodeRouteItem(bb) {
  let message = {};

  end_of_message: while (!isAtEnd(bb)) {
    let tag = readVarint32(bb);

    switch (tag >>> 3) {
      case 0:
        break end_of_message;

      // optional fixed32 next_ip = 1;
      case 1: {
        message.next_ip = readInt32(bb) >>> 0;
        break;
      }

      default:
        skipUnknownField(bb, tag & 7);
    }
  }

  return message;
}

function pushTemporaryLength(bb) {
  let length = readVarint32(bb);
  let limit = bb.limit;
  bb.limit = bb.offset + length;
  return limit;
}

function skipUnknownField(bb, type) {
  switch (type) {
    case 0:
      while (readByte(bb) & 0x80) {}
      break;
    case 2:
      skip(bb, readVarint32(bb));
      break;
    case 5:
      skip(bb, 4);
      break;
    case 1:
      skip(bb, 8);
      break;
    default:
      throw new Error("Unimplemented type: " + type);
  }
}

function stringToLong(value) {
  return {
    low: value.charCodeAt(0) | (value.charCodeAt(1) << 16),
    high: value.charCodeAt(2) | (value.charCodeAt(3) << 16),
    unsigned: false,
  };
}

function longToString(value) {
  let low = value.low;
  let high = value.high;
  return String.fromCharCode(
    low & 0xffff,
    low >>> 16,
    high & 0xffff,
    high >>> 16
  );
}

// The code below was modified from https://github.com/protobufjs/bytebuffer.js
// which is under the Apache License 2.0.

let f32 = new Float32Array(1);
let f32_u8 = new Uint8Array(f32.buffer);

let f64 = new Float64Array(1);
let f64_u8 = new Uint8Array(f64.buffer);

function intToLong(value) {
  value |= 0;
  return {
    low: value,
    high: value >> 31,
    unsigned: value >= 0,
  };
}

let bbStack = [];

function popByteBuffer() {
  const bb = bbStack.pop();
  if (!bb) return { bytes: new Uint8Array(64), offset: 0, limit: 0 };
  bb.offset = bb.limit = 0;
  return bb;
}

function pushByteBuffer(bb) {
  bbStack.push(bb);
}

function wrapByteBuffer(bytes) {
  return { bytes, offset: 0, limit: bytes.length };
}

function toUint8Array(bb) {
  let bytes = bb.bytes;
  let limit = bb.limit;
  return bytes.length === limit ? bytes : bytes.subarray(0, limit);
}

function skip(bb, offset) {
  if (bb.offset + offset > bb.limit) {
    throw new Error("Skip past limit");
  }
  bb.offset += offset;
}

function isAtEnd(bb) {
  return bb.offset >= bb.limit;
}

function grow(bb, count) {
  let bytes = bb.bytes;
  let offset = bb.offset;
  let limit = bb.limit;
  let finalOffset = offset + count;
  if (finalOffset > bytes.length) {
    let newBytes = new Uint8Array(finalOffset * 2);
    newBytes.set(bytes);
    bb.bytes = newBytes;
  }
  bb.offset = finalOffset;
  if (finalOffset > limit) {
    bb.limit = finalOffset;
  }
  return offset;
}

function advance(bb, count) {
  let offset = bb.offset;
  if (offset + count > bb.limit) {
    throw new Error("Read past limit");
  }
  bb.offset += count;
  return offset;
}

function readBytes(bb, count) {
  let offset = advance(bb, count);
  return bb.bytes.subarray(offset, offset + count);
}

function writeBytes(bb, buffer) {
  let offset = grow(bb, buffer.length);
  bb.bytes.set(buffer, offset);
}

function readString(bb, count) {
  // Sadly a hand-coded UTF8 decoder is much faster than subarray+TextDecoder in V8
  let offset = advance(bb, count);
  let fromCharCode = String.fromCharCode;
  let bytes = bb.bytes;
  let invalid = "\uFFFD";
  let text = "";

  for (let i = 0; i < count; i++) {
    let c1 = bytes[i + offset],
      c2,
      c3,
      c4,
      c;

    // 1 byte
    if ((c1 & 0x80) === 0) {
      text += fromCharCode(c1);
    }

    // 2 bytes
    else if ((c1 & 0xe0) === 0xc0) {
      if (i + 1 >= count) text += invalid;
      else {
        c2 = bytes[i + offset + 1];
        if ((c2 & 0xc0) !== 0x80) text += invalid;
        else {
          c = ((c1 & 0x1f) << 6) | (c2 & 0x3f);
          if (c < 0x80) text += invalid;
          else {
            text += fromCharCode(c);
            i++;
          }
        }
      }
    }

    // 3 bytes
    else if ((c1 & 0xf0) == 0xe0) {
      if (i + 2 >= count) text += invalid;
      else {
        c2 = bytes[i + offset + 1];
        c3 = bytes[i + offset + 2];
        if (((c2 | (c3 << 8)) & 0xc0c0) !== 0x8080) text += invalid;
        else {
          c = ((c1 & 0x0f) << 12) | ((c2 & 0x3f) << 6) | (c3 & 0x3f);
          if (c < 0x0800 || (c >= 0xd800 && c <= 0xdfff)) text += invalid;
          else {
            text += fromCharCode(c);
            i += 2;
          }
        }
      }
    }

    // 4 bytes
    else if ((c1 & 0xf8) == 0xf0) {
      if (i + 3 >= count) text += invalid;
      else {
        c2 = bytes[i + offset + 1];
        c3 = bytes[i + offset + 2];
        c4 = bytes[i + offset + 3];
        if (((c2 | (c3 << 8) | (c4 << 16)) & 0xc0c0c0) !== 0x808080)
          text += invalid;
        else {
          c =
            ((c1 & 0x07) << 0x12) |
            ((c2 & 0x3f) << 0x0c) |
            ((c3 & 0x3f) << 0x06) |
            (c4 & 0x3f);
          if (c < 0x10000 || c > 0x10ffff) text += invalid;
          else {
            c -= 0x10000;
            text += fromCharCode((c >> 10) + 0xd800, (c & 0x3ff) + 0xdc00);
            i += 3;
          }
        }
      }
    } else text += invalid;
  }

  return text;
}

function writeString(bb, text) {
  // Sadly a hand-coded UTF8 encoder is much faster than TextEncoder+set in V8
  let n = text.length;
  let byteCount = 0;

  // Write the byte count first
  for (let i = 0; i < n; i++) {
    let c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < n) {
      c = (c << 10) + text.charCodeAt(++i) - 0x35fdc00;
    }
    byteCount += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
  }
  writeVarint32(bb, byteCount);

  let offset = grow(bb, byteCount);
  let bytes = bb.bytes;

  // Then write the bytes
  for (let i = 0; i < n; i++) {
    let c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < n) {
      c = (c << 10) + text.charCodeAt(++i) - 0x35fdc00;
    }
    if (c < 0x80) {
      bytes[offset++] = c;
    } else {
      if (c < 0x800) {
        bytes[offset++] = ((c >> 6) & 0x1f) | 0xc0;
      } else {
        if (c < 0x10000) {
          bytes[offset++] = ((c >> 12) & 0x0f) | 0xe0;
        } else {
          bytes[offset++] = ((c >> 18) & 0x07) | 0xf0;
          bytes[offset++] = ((c >> 12) & 0x3f) | 0x80;
        }
        bytes[offset++] = ((c >> 6) & 0x3f) | 0x80;
      }
      bytes[offset++] = (c & 0x3f) | 0x80;
    }
  }
}

function writeByteBuffer(bb, buffer) {
  let offset = grow(bb, buffer.limit);
  let from = bb.bytes;
  let to = buffer.bytes;

  // This for loop is much faster than subarray+set on V8
  for (let i = 0, n = buffer.limit; i < n; i++) {
    from[i + offset] = to[i];
  }
}

function readByte(bb) {
  return bb.bytes[advance(bb, 1)];
}

function writeByte(bb, value) {
  let offset = grow(bb, 1);
  bb.bytes[offset] = value;
}

function readFloat(bb) {
  let offset = advance(bb, 4);
  let bytes = bb.bytes;

  // Manual copying is much faster than subarray+set in V8
  f32_u8[0] = bytes[offset++];
  f32_u8[1] = bytes[offset++];
  f32_u8[2] = bytes[offset++];
  f32_u8[3] = bytes[offset++];
  return f32[0];
}

function writeFloat(bb, value) {
  let offset = grow(bb, 4);
  let bytes = bb.bytes;
  f32[0] = value;

  // Manual copying is much faster than subarray+set in V8
  bytes[offset++] = f32_u8[0];
  bytes[offset++] = f32_u8[1];
  bytes[offset++] = f32_u8[2];
  bytes[offset++] = f32_u8[3];
}

function readDouble(bb) {
  let offset = advance(bb, 8);
  let bytes = bb.bytes;

  // Manual copying is much faster than subarray+set in V8
  f64_u8[0] = bytes[offset++];
  f64_u8[1] = bytes[offset++];
  f64_u8[2] = bytes[offset++];
  f64_u8[3] = bytes[offset++];
  f64_u8[4] = bytes[offset++];
  f64_u8[5] = bytes[offset++];
  f64_u8[6] = bytes[offset++];
  f64_u8[7] = bytes[offset++];
  return f64[0];
}

function writeDouble(bb, value) {
  let offset = grow(bb, 8);
  let bytes = bb.bytes;
  f64[0] = value;

  // Manual copying is much faster than subarray+set in V8
  bytes[offset++] = f64_u8[0];
  bytes[offset++] = f64_u8[1];
  bytes[offset++] = f64_u8[2];
  bytes[offset++] = f64_u8[3];
  bytes[offset++] = f64_u8[4];
  bytes[offset++] = f64_u8[5];
  bytes[offset++] = f64_u8[6];
  bytes[offset++] = f64_u8[7];
}

function readInt32(bb) {
  let offset = advance(bb, 4);
  let bytes = bb.bytes;
  return (
    bytes[offset] |
    (bytes[offset + 1] << 8) |
    (bytes[offset + 2] << 16) |
    (bytes[offset + 3] << 24)
  );
}

function writeInt32(bb, value) {
  let offset = grow(bb, 4);
  let bytes = bb.bytes;
  bytes[offset] = value;
  bytes[offset + 1] = value >> 8;
  bytes[offset + 2] = value >> 16;
  bytes[offset + 3] = value >> 24;
}

function readInt64(bb, unsigned) {
  return {
    low: readInt32(bb),
    high: readInt32(bb),
    unsigned,
  };
}

function writeInt64(bb, value) {
  writeInt32(bb, value.low);
  writeInt32(bb, value.high);
}

function readVarint32(bb) {
  let c = 0;
  let value = 0;
  let b;
  do {
    b = readByte(bb);
    if (c < 32) value |= (b & 0x7f) << c;
    c += 7;
  } while (b & 0x80);
  return value;
}

function writeVarint32(bb, value) {
  value >>>= 0;
  while (value >= 0x80) {
    writeByte(bb, (value & 0x7f) | 0x80);
    value >>>= 7;
  }
  writeByte(bb, value);
}

function readVarint64(bb, unsigned) {
  let part0 = 0;
  let part1 = 0;
  let part2 = 0;
  let b;

  b = readByte(bb);
  part0 = b & 0x7f;
  if (b & 0x80) {
    b = readByte(bb);
    part0 |= (b & 0x7f) << 7;
    if (b & 0x80) {
      b = readByte(bb);
      part0 |= (b & 0x7f) << 14;
      if (b & 0x80) {
        b = readByte(bb);
        part0 |= (b & 0x7f) << 21;
        if (b & 0x80) {
          b = readByte(bb);
          part1 = b & 0x7f;
          if (b & 0x80) {
            b = readByte(bb);
            part1 |= (b & 0x7f) << 7;
            if (b & 0x80) {
              b = readByte(bb);
              part1 |= (b & 0x7f) << 14;
              if (b & 0x80) {
                b = readByte(bb);
                part1 |= (b & 0x7f) << 21;
                if (b & 0x80) {
                  b = readByte(bb);
                  part2 = b & 0x7f;
                  if (b & 0x80) {
                    b = readByte(bb);
                    part2 |= (b & 0x7f) << 7;
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  return {
    low: part0 | (part1 << 28),
    high: (part1 >>> 4) | (part2 << 24),
    unsigned,
  };
}

function writeVarint64(bb, value) {
  let part0 = value.low >>> 0;
  let part1 = ((value.low >>> 28) | (value.high << 4)) >>> 0;
  let part2 = value.high >>> 24;

  // ref: src/google/protobuf/io/coded_stream.cc
  let size =
    part2 === 0
      ? part1 === 0
        ? part0 < 1 << 14
          ? part0 < 1 << 7
            ? 1
            : 2
          : part0 < 1 << 21
          ? 3
          : 4
        : part1 < 1 << 14
        ? part1 < 1 << 7
          ? 5
          : 6
        : part1 < 1 << 21
        ? 7
        : 8
      : part2 < 1 << 7
      ? 9
      : 10;

  let offset = grow(bb, size);
  let bytes = bb.bytes;

  switch (size) {
    case 10:
      bytes[offset + 9] = (part2 >>> 7) & 0x01;
    case 9:
      bytes[offset + 8] = size !== 9 ? part2 | 0x80 : part2 & 0x7f;
    case 8:
      bytes[offset + 7] =
        size !== 8 ? (part1 >>> 21) | 0x80 : (part1 >>> 21) & 0x7f;
    case 7:
      bytes[offset + 6] =
        size !== 7 ? (part1 >>> 14) | 0x80 : (part1 >>> 14) & 0x7f;
    case 6:
      bytes[offset + 5] =
        size !== 6 ? (part1 >>> 7) | 0x80 : (part1 >>> 7) & 0x7f;
    case 5:
      bytes[offset + 4] = size !== 5 ? part1 | 0x80 : part1 & 0x7f;
    case 4:
      bytes[offset + 3] =
        size !== 4 ? (part0 >>> 21) | 0x80 : (part0 >>> 21) & 0x7f;
    case 3:
      bytes[offset + 2] =
        size !== 3 ? (part0 >>> 14) | 0x80 : (part0 >>> 14) & 0x7f;
    case 2:
      bytes[offset + 1] =
        size !== 2 ? (part0 >>> 7) | 0x80 : (part0 >>> 7) & 0x7f;
    case 1:
      bytes[offset] = size !== 1 ? part0 | 0x80 : part0 & 0x7f;
  }
}

function readVarint32ZigZag(bb) {
  let value = readVarint32(bb);

  // ref: src/google/protobuf/wire_format_lite.h
  return (value >>> 1) ^ -(value & 1);
}

function writeVarint32ZigZag(bb, value) {
  // ref: src/google/protobuf/wire_format_lite.h
  writeVarint32(bb, (value << 1) ^ (value >> 31));
}

function readVarint64ZigZag(bb) {
  let value = readVarint64(bb, /* unsigned */ false);
  let low = value.low;
  let high = value.high;
  let flip = -(low & 1);

  // ref: src/google/protobuf/wire_format_lite.h
  return {
    low: ((low >>> 1) | (high << 31)) ^ flip,
    high: (high >>> 1) ^ flip,
    unsigned: false,
  };
}

function writeVarint64ZigZag(bb, value) {
  let low = value.low;
  let high = value.high;
  let flip = high >> 31;

  // ref: src/google/protobuf/wire_format_lite.h
  writeVarint64(bb, {
    low: (low << 1) ^ flip,
    high: ((high << 1) | (low >>> 31)) ^ flip,
    unsigned: false,
  });
}

export default $root;
