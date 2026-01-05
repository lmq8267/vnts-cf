// 轻量级VNT头部解析工具
export function parseVNTHeaderFast(buffer) {
  if (!buffer || buffer.length < 12) return null;

  return {
    protocol: buffer[1],
    transportProtocol: buffer[2],
    source:
      (buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | buffer[7],
    destination:
      (buffer[8] << 24) | (buffer[9] << 16) | (buffer[10] << 8) | buffer[11],
    isDataPacket:
      buffer[1] === 4 &&
      (buffer[2] === 1 || buffer[2] === 2 || buffer[2] === 3),
    isControlPacket: buffer[1] === 3,
    isServicePacket: buffer[1] === 1,
  };
}

// 快速路由判断
export function shouldRouteFast(header) {
  // 数据包直接转发
  if (header.isDataPacket) return "direct";

  // 控制包需要处理
  if (header.isControlPacket) return "control";

  // 服务包需要处理
  if (header.isServicePacket) return "service";

  // 其他情况默认转发
  return "direct";
}

// 创建快速响应包
export function createFastResponse(
  protocol,
  transport,
  source,
  dest,
  payload = new Uint8Array(0)
) {
  const buffer = new Uint8Array(12 + payload.length);
  buffer[0] = 2; // Version
  buffer[1] = protocol;
  buffer[2] = transport;
  buffer[3] = 0xf0; // MAX_TTL

  // 设置源和目标地址
  buffer[4] = (source >> 24) & 0xff;
  buffer[5] = (source >> 16) & 0xff;
  buffer[6] = (source >> 8) & 0xff;
  buffer[7] = source & 0xff;

  buffer[8] = (dest >> 24) & 0xff;
  buffer[9] = (dest >> 16) & 0xff;
  buffer[10] = (dest >> 8) & 0xff;
  buffer[11] = dest & 0xff;

  // 设置载荷
  if (payload.length > 0) {
    buffer.set(payload, 12);
  }

  return buffer;
}
