import { PACKET_HEADER_SIZE, ENCRYPTION_RESERVED } from "./constants.js";
import { logger } from "./logger.js";

export class NetPacket {
  constructor(data) {
    this.data = data;
    this.offset = 0;
  }

  // 轻量级头部解析方法
  static parseHeader(buffer) {
    // logger.debug(`[数据包解析-头部] 开始解析VNT头部，缓冲区长度: ${buffer?.length || 0}`);

    if (!buffer || buffer.length < 12) {
      // logger.warn(`[数据包解析-头部] 数据包长度不足，需要至少12字节，实际: ${buffer?.length || 0}`);
      throw new Error("Packet too short for header parsing");
    }

    const view = new DataView(buffer.buffer || buffer);
    // logger.debug(`[数据包解析-头部] 创建DataView完成，开始提取字段`);

    const header = {
      version: view.getUint8(0) & 0x0f,
      flags: (view.getUint8(0) & 0xf0) >> 4,
      protocol: view.getUint8(1),
      transportProtocol: view.getUint8(2),
      ttl: view.getUint8(3),
      source: view.getUint32(4, false), // 大端序
      destination: view.getUint32(8, false), // 大端序
      offset: 12,
    };

    // logger.debug(`[数据包解析-头部] 解析完成 - 版本: ${header.version}, 协议: ${header.protocol}, 传输: ${header.transportProtocol}`);
    return header;
  }

  // 保留完整解析方法用于复杂协议处理
  static parse(buffer) {
    // 安全检查：确保输入有效
    if (!buffer) {
      // logger.error(`[数据包解析-完整] 缓冲区为空或未定义`);
      throw new Error("Buffer is null or undefined");
    }

    if (!(buffer instanceof Uint8Array) && !(buffer instanceof ArrayBuffer)) {
      // logger.error(`[数据包解析-完整] 无效的缓冲区类型: ${typeof buffer}`);
      throw new Error(
        "Invalid buffer type: expected Uint8Array or ArrayBuffer"
      );
    }

    // 获取缓冲区长度
    const length =
      buffer instanceof Uint8Array ? buffer.length : buffer.byteLength;

    if (length < 12) {
      // logger.error(`[数据包解析-完整] 数据包过短: ${length}字节，最少需要12字节`);
      throw new Error(
        `Packet too short: ${length} bytes, minimum 12 bytes required`
      );
    }

    try {
      const packet = new NetPacket(buffer);
      packet.parseHeader();
      return packet;
    } catch (error) {
      // logger.error(`[数据包解析-完整] 解析失败: ${error.message}`, error);
      throw new Error(`Failed to parse VNT packet: ${error.message}`);
    }
  }

  parseHeader() {
    // 安全检查：确保数据存在且类型正确
    if (!this.data) {
      // logger.error(`[协议头解析-错误] 数据包数据为空`);
      throw new Error("Packet data is null or undefined");
    }

    // 确保有有效的 ArrayBuffer
    let buffer;
    if (this.data.buffer) {
      buffer = this.data.buffer;
    } else if (this.data instanceof Uint8Array) {
      // 创建新的 ArrayBuffer 并复制数据
      buffer = new ArrayBuffer(this.data.length);
      new Uint8Array(buffer).set(this.data);
    } else if (this.data instanceof ArrayBuffer) {
      buffer = this.data;
    } else {
      // logger.error(`[协议头解析-错误] 无效的数据类型`);
      throw new Error(
        "Invalid data type for packet parsing: expected Uint8Array or ArrayBuffer"
      );
    }

    // 安全检查：确保缓冲区足够大以包含协议头
    if (buffer.byteLength < 12) {
      // logger.warn(`[协议头解析-警告] 数据包长度不足，需要至少12字节，实际: ${buffer.byteLength}`);
      throw new Error(
        "Packet too short: minimum 12 bytes required for VNT header"
      );
    }

    const view = new DataView(buffer);

    try {
      // 正确的 VNT 协议头解析
      const byte0 = view.getUint8(0);
      this.version = byte0 & 0x0f; // 低4位是版本
      this.flags = (byte0 & 0xf0) >> 4; // 高4位是标志
      this.protocol = view.getUint8(1); // 协议类型
      this.transportProtocol = view.getUint8(2); // 传输协议
      this.ttl = view.getUint8(3); // TTL

      // IP地址使用大端序
      const sourceIpBytes = [
        view.getUint8(4),
        view.getUint8(5),
        view.getUint8(6),
        view.getUint8(7),
      ];
      this.source = new DataView(
        new Uint8Array(sourceIpBytes).buffer
      ).getUint32(0, false); // 大端序

      const destIpBytes = [
        view.getUint8(8),
        view.getUint8(9),
        view.getUint8(10),
        view.getUint8(11),
      ];
      this.destination = new DataView(
        new Uint8Array(destIpBytes).buffer
      ).getUint32(0, false); // 大端序

      this.offset = 12; // VNT header size
    } catch (error) {
      // logger.error(`[协议头解析-失败] 解析VNT协议头失败: ${error.message}`,error);
      throw new Error(`Failed to parse VNT packet header: ${error.message}`);
    }
  }

  // 移除冲突的方法定义，只保留属性访问
  payload() {
    return this.data.slice(this.offset);
  }

  payload_mut() {
    return new Uint8Array(
      this.data.buffer,
      this.offset,
      this.data.length - this.offset
    );
  }

  is_encrypt() {
    return (this.flags & 0x01) !== 0;
  }

  is_gateway() {
    return (this.flags & 0x04) !== 0;
  }

  incr_ttl() {
    // 安全检查：确保数据存在
    if (!this.data) {
      // logger.error(`[TTL递增-错误] 数据包数据为空`);
      throw new Error("Cannot increment TTL: packet data is null");
    }

    // 确保 TTL 值有效
    if (typeof this.ttl !== "number" || this.ttl < 0) {
      // logger.error(`[TTL递增-错误] TTL值无效: ${this.ttl}`);
      throw new Error("Invalid TTL value");
    }

    // 增加 TTL
    this.ttl++;

    // 确保有有效的 ArrayBuffer
    let buffer;
    if (this.data.buffer) {
      buffer = this.data.buffer;
    } else if (this.data instanceof Uint8Array) {
      buffer = new ArrayBuffer(this.data.length);
      new Uint8Array(buffer).set(this.data);
    } else if (this.data instanceof ArrayBuffer) {
      buffer = this.data;
    } else {
      // logger.error(`[TTL递增-错误] 无效的数据类型`);
      throw new Error("Invalid data type for packet modification");
    }

    // 安全检查：确保缓冲区足够大
    if (buffer.byteLength < 4) {
      // logger.error(`[TTL递增-错误] 缓冲区太短，无法修改TTL`);
      throw new Error("Packet too short to modify TTL");
    }

    try {
      const view = new DataView(buffer);
      view.setUint8(3, this.ttl); // TTL 在字节3
      return this.ttl;
    } catch (error) {
      // logger.error(`[TTL递增-失败] 写入TTL失败: ${error.message}`, error);
      throw new Error(`Failed to increment TTL: ${error.message}`);
    }
  }

  buffer() {
    return this.data;
  }

  static new(size) {
    const totalSize = 12 + size; // VNT header is 12 bytes
    const buffer = new Uint8Array(totalSize);
    // 确保第一个字节不包含加密标志
    buffer[0] = 0x00; // 清除所有标志
    return new NetPacket(buffer);
  }

  static new_encrypt(size) {
    const totalSize = 12 + size + ENCRYPTION_RESERVED; // VNT header is 12 bytes
    const buffer = new Uint8Array(totalSize);
    return new NetPacket(buffer);
  }

  // 新增：快速创建方法
  static createFast(
    protocol,
    transportProtocol,
    source,
    destination,
    payload = new Uint8Array(0)
  ) {
    const headerSize = 12;
    const buffer = new Uint8Array(headerSize + payload.length);

    const view = new DataView(buffer.buffer);
    view.setUint8(0, 2);
    view.setUint8(1, protocol);
    view.setUint8(2, transportProtocol);
    view.setUint8(3, 0x60);

    // 直接调用静态方法
    const sourceBytes = NetPacket.intToIpv4Bytes(source);
    const destBytes = NetPacket.intToIpv4Bytes(destination);

    buffer.set(sourceBytes, 4);
    buffer.set(destBytes, 8);
    buffer.set(payload, headerSize);

    return buffer;
  }

  // 安全获取 ArrayBuffer 的辅助方法
  _getArrayBuffer() {
    if (!this.data) {
      // logger.error(`[缓冲区-错误] 数据包数据为空`);
      throw new Error("Packet data is null");
    }

    if (this.data.buffer) {
      return this.data.buffer;
    } else if (this.data instanceof Uint8Array) {
      const buffer = new ArrayBuffer(this.data.length);
      new Uint8Array(buffer).set(this.data);
      return buffer;
    } else if (this.data instanceof ArrayBuffer) {
      return this.data;
    } else {
      // logger.error(`[缓冲区-错误] 无效的数据类型`);
      throw new Error("Invalid data type");
    }
  }

  // 验证数据包完整性
  validate() {
    if (!this.data) {
      // logger.error(`[数据包-错误] 数据包数据为空`);
      throw new Error("Packet data is null");
    }

    if (typeof this.protocol !== "number") {
      // logger.error(`[数据包-错误] 协议字段无效: ${this.protocol}`);
      throw new Error("Invalid protocol field");
    }

    if (typeof this.transportProtocol !== "number") {
      // logger.error(`[数据包-错误] 传输协议字段无效: ${this.transportProtocol}`);
      throw new Error("Invalid transport protocol field");
    }

    if (typeof this.source !== "number" || this.source < 0) {
      // logger.error(`[数据包-错误] 源地址无效: ${this.source}`);
      throw new Error("Invalid source address");
    }

    if (typeof this.destination !== "number" || this.destination < 0) {
      // logger.error(`[数据包-错误] 目标地址无效: ${this.destination}`);
      throw new Error("Invalid destination address");
    }

    return true;
  }

  // 设置方法
  set_protocol(protocol) {
    const buffer = this._getArrayBuffer();
    const view = new DataView(buffer);
    view.setUint8(1, protocol);
    this.protocol = protocol;
  }

  set_transport_protocol(transportProtocol) {
    const buffer = this._getArrayBuffer();
    const view = new DataView(buffer);
    view.setUint8(2, transportProtocol);
    this.transportProtocol = transportProtocol;
  }

  set_source(source) {
    const buffer = this._getArrayBuffer();
    const view = new DataView(buffer);
    // 大端序存储IP
    view.setUint8(4, (source >> 24) & 0xff);
    view.setUint8(5, (source >> 16) & 0xff);
    view.setUint8(6, (source >> 8) & 0xff);
    view.setUint8(7, source & 0xff);
    this.source = source;
  }

  set_destination(destination) {
    const buffer = this._getArrayBuffer();
    const view = new DataView(buffer);

    // 使用正确的字节顺序和偏移
    const destBytes = this.intToIpv4Bytes(destination);

    // logger.debug(`[目标地址-字节] 目标地址字节: [${destBytes.join(", ")}]`);

    // 按字节设置，确保与 Rust 一致
    view.setUint8(8, destBytes[0]);
    view.setUint8(9, destBytes[1]);
    view.setUint8(10, destBytes[2]);
    view.setUint8(11, destBytes[3]);

    this.destination = destination;
  }

  set_payload(payload) {
    const dataStart = 12; // VNT header size
    if (this.data.length < dataStart + payload.length) {
      // logger.error(`[载荷-错误] 缓冲区空间不足，需要: ${dataStart + payload.length}，可用: ${this.data.length}`);
      throw new Error("Insufficient space for payload");
    }

    // 复制 payload 数据
    const dataArray =
      this.data instanceof Uint8Array ? this.data : new Uint8Array(this.data);
    dataArray.set(payload, dataStart);
    this.data = dataArray;
  }

  set_gateway_flag(isGateway) {
    const buffer = this._getArrayBuffer();
    const view = new DataView(buffer);
    const byte0 = view.getUint8(0);

    if (isGateway) {
      view.setUint8(0, byte0 | 0x40); // 设置第6位
    } else {
      view.setUint8(0, byte0 & ~0x40); // 清除第6位
    }

    // 更新内部flags状态
    this.flags = (view.getUint8(0) & 0xf0) >> 4;
  }

  // 静态方法：IP地址转换
  static intToIpv4Bytes(ipInt) {
    return [
      (ipInt >> 24) & 0xff,
      (ipInt >> 16) & 0xff,
      (ipInt >> 8) & 0xff,
      ipInt & 0xff,
    ];
  }

  intToIpv4Bytes(ipInt) {
    return NetPacket.intToIpv4Bytes(ipInt);
  }

  set_default_version() {
    const buffer = this._getArrayBuffer();
    const view = new DataView(buffer);
    const byte0 = view.getUint8(0);
    // V2 = 2, 保留高4位标志，设置低4位为版本号
    view.setUint8(0, (byte0 & 0xf0) | 0x02);
    this.version = 2;
  }

  first_set_ttl(ttl) {
    // logger.debug(`[TTL-设置] 首次设置TTL: ${ttl}`);

    const buffer = this._getArrayBuffer();
    const view = new DataView(buffer);

    // 记录修改前的值
    const oldValue = view.getUint8(3);
    // logger.debug(`[TTL-修改前] TTL字节修改前: 0x${oldValue.toString(16).padStart(2, "0")}`);

    // 设置 TTL
    const newValue = (ttl << 4) | ttl;
    view.setUint8(3, newValue);

    // 记录修改后的值
    // logger.debug(`[TTL-修改后] TTL字节修改后: 0x${newValue.toString(16).padStart(2, "0")}`);

    this.ttl = ttl;
  }
}
