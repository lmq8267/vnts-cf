// VNT 协议常量定义
export const PROTOCOL = {
  SERVICE: 1, // 修正
  ERROR: 2,
  CONTROL: 3, // 修正
  IPTURN: 4,
  OTHERTURN: 5,
};

export const TRANSPORT_PROTOCOL = {
  // Service 协议（服务端交互）
  RegistrationRequest: 1,
  RegistrationResponse: 2,
  PullDeviceList: 3,
  PushDeviceList: 4,
  HandshakeRequest: 5,
  HandshakeResponse: 6,
  SecretHandshakeRequest: 7,
  SecretHandshakeResponse: 8,
  ClientStatusInfo: 9,

  // Control 协议（客户端控制）
  Ping: 1,
  Pong: 2,
  PunchRequest: 3,
  PunchResponse: 4,
  AddrRequest: 5,
  AddrResponse: 6,

  ErrorResponse: 10,
};

export const IP_TURN_TRANSPORT_PROTOCOL = {
  Ipv4: 1,
  WGIpv4: 2,
  Ipv4Broadcast: 3,
};

export const PACKET_HEADER_SIZE = 12;
export const ENCRYPTION_RESERVED = 16;
export const MAGIC = 0x76774e54; // "vwtN" - VNT magic number

// 新增：快速转发协议类型
export const FAST_FORWARD_PROTOCOLS = {
  IPTURN_IPV4: { protocol: 4, transport: 1 },
};
