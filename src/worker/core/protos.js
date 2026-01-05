import {
  encodeHandshakeRequest,
  decodeHandshakeRequest,
  encodeHandshakeResponse,
  decodeHandshakeResponse,
  encodeSecretHandshakeRequest,
  decodeSecretHandshakeRequest,
  encodeRegistrationRequest,
  decodeRegistrationRequest,
  encodeRegistrationResponse,
  decodeRegistrationResponse,
  encodeDeviceInfo,
  decodeDeviceInfo,
  encodeDeviceList,
  decodeDeviceList,
  encodePunchInfo,
  decodePunchInfo,
  encodeClientStatusInfo,
  decodeClientStatusInfo,
  encodeRouteItem,
  decodeRouteItem,
  encodePunchNatType,
  decodePunchNatType,
  encodePunchNatModel,
  decodePunchNatModel,
} from "./protos_generated.js";

let cachedTypes;

export function loadProtos() {
  if (cachedTypes) return cachedTypes;

  // 创建兼容的消息对象结构
  return (cachedTypes = {
    // 消息类型 - 提供创建、编码、解码方法
    HandshakeRequest: {
      create: (data) => data || {},
      encode: encodeHandshakeRequest,
      decode: decodeHandshakeRequest,
    },
    HandshakeResponse: {
      create: (data) => data || {},
      encode: encodeHandshakeResponse,
      decode: decodeHandshakeResponse,
    },
    SecretHandshakeRequest: {
      create: (data) => data || {},
      encode: encodeSecretHandshakeRequest,
      decode: decodeSecretHandshakeRequest,
    },
    RegistrationRequest: {
      create: (data) => data || {},
      encode: encodeRegistrationRequest,
      decode: decodeRegistrationRequest,
    },
    RegistrationResponse: {
      create: (data) => data || {},
      encode: encodeRegistrationResponse,
      decode: decodeRegistrationResponse,
    },
    DeviceInfo: {
      create: (data) => data || {},
      encode: encodeDeviceInfo,
      decode: decodeDeviceInfo,
    },
    DeviceList: {
      create: (data) => data || {},
      encode: encodeDeviceList,
      decode: decodeDeviceList,
    },
    PunchInfo: {
      create: (data) => data || {},
      encode: encodePunchInfo,
      decode: decodePunchInfo,
    },
    ClientStatusInfo: {
      create: (data) => data || {},
      encode: encodeClientStatusInfo,
      decode: decodeClientStatusInfo,
    },
    RouteItem: {
      create: (data) => data || {},
      encode: encodeRouteItem,
      decode: decodeRouteItem,
    },
    // 枚举类型
    PunchNatType: encodePunchNatType,
    PunchNatModel: encodePunchNatModel,
  });
}

// 创建函数 - 直接使用编码函数
export function createHandshakeRequest(version, secret, keyFinger) {
  const message = {
    version: version || "1.0.0",
    secret: secret || false,
    key_finger: keyFinger || "",
  };
  return encodeHandshakeRequest(message);
}

export function createHandshakeResponse(version, secret, publicKey, keyFinger) {
  const message = {
    version: version || "1.0.0",
    secret: secret || false,
    public_key: publicKey || new Uint8Array(0),
    key_finger: keyFinger || "",
  };
  return encodeHandshakeResponse(message);
}

export function createSecretHandshakeRequest(token, key) {
  const message = {
    token: token || "",
    key: key || new Uint8Array(0),
  };
  return encodeSecretHandshakeRequest(message);
}

export function createRegistrationRequest(
  token,
  deviceId,
  name,
  version,
  virtualIp,
  clientSecretHash
) {
  if (!token) {
    throw new Error("Token is required for registration");
  }
  const message = {
    token: token,
    device_id: deviceId || "",
    name: name || "客户端",
    is_fast: false,
    version: version || "Unknown",
    virtual_ip: virtualIp || 0,
    allow_ip_change: false,
    client_secret: false,
    client_secret_hash: clientSecretHash || new Uint8Array(0),
  };
  return encodeRegistrationRequest(message);
}

export function createRegistrationResponse(
  virtualIp,
  gateway,
  netmask,
  epoch,
  deviceInfoList,
  publicIp,
  publicPort
) {
  const message = {
    virtual_ip: virtualIp || 0,
    virtual_gateway: gateway || 0,
    virtual_netmask: netmask || 0,
    epoch: epoch || 0,
    device_info_list: deviceInfoList || [],
    public_ip: publicIp || 0,
    public_port: publicPort || 0,
    public_ipv6: new Uint8Array(0),
  };
  return encodeRegistrationResponse(message);
}

export function createDeviceInfo(
  name,
  virtualIp,
  deviceStatus,
  clientSecret,
  clientSecretHash,
  wireguard
) {
  const message = {
    name: name || "",
    virtual_ip: virtualIp || 0,
    device_status: deviceStatus || 0,
    client_secret: clientSecret || false,
    client_secret_hash: clientSecretHash || new Uint8Array(0),
    wireguard: wireguard || false,
  };
  return encodeDeviceInfo(message);
}

export function createDeviceList(epoch, deviceInfoList) {
  const message = {
    epoch: epoch || 0,
    device_info_list: deviceInfoList || [],
  };
  return encodeDeviceList(message);
}

export function createPunchInfo(
  publicIpList,
  publicPort,
  publicPortRange,
  natType,
  reply,
  localIp
) {
  const message = {
    public_ip_list: publicIpList || [],
    public_port: publicPort || 0,
    public_port_range: publicPortRange || 0,
    nat_type: natType || 0,
    reply: reply || false,
    local_ip: localIp || 0,
  };
  return encodePunchInfo(message);
}

export function createClientStatusInfo(
  source,
  p2pList,
  upStream,
  downStream,
  natType
) {
  const message = {
    source: source || 0,
    p2p_list: p2pList || [],
    up_stream: upStream || 0,
    down_stream: downStream || 0,
    nat_type: natType || 0,
  };
  return encodeClientStatusInfo(message);
}

export function createRouteItem(nextIp) {
  const message = {
    next_ip: nextIp || 0,
  };
  return encodeRouteItem(message);
}

// 解析函数 - 直接使用解码函数
export function parseHandshakeRequest(data) {
  return decodeHandshakeRequest(data);
}

export function parseHandshakeResponse(data) {
  return decodeHandshakeResponse(data);
}

export function parseSecretHandshakeRequest(data) {
  return decodeSecretHandshakeRequest(data);
}

export function parseRegistrationRequest(data) {
  return decodeRegistrationRequest(data);
}

export function parseRegistrationResponse(data) {
  return decodeRegistrationResponse(data);
}

export function parseDeviceInfo(data) {
  return decodeDeviceInfo(data);
}

export function parseDeviceList(data) {
  return decodeDeviceList(data);
}

export function parsePunchInfo(data) {
  return decodePunchInfo(data);
}

export function parseClientStatusInfo(data) {
  return decodeClientStatusInfo(data);
}

export function parseRouteItem(data) {
  return decodeRouteItem(data);
}
