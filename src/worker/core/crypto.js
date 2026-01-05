import { ENCRYPTION_RESERVED } from "./constants.js";
import { logger } from "./logger.js";

/**
 * RSA 加密器
 * 基于 vnt_s/vnts/src/cipher/rsa_cipher.rs 实现
 */
export class RsaCipher {
  constructor(privateKeyDer, publicKeyDer) {
    logger.debug(`[RSA加密器-初始化] 创建RSA加密器实例`);
    this.privateKeyDer = privateKeyDer;
    this.publicKeyDer = publicKeyDer;
    this.finger = null; // 初始化为 null
  }

  // 异步初始化方法
  async init() {
    this.finger = await this.calculateFinger(this.publicKeyDer);
    logger.debug(
      `[RSA加密器-指纹] 公钥指纹计算完成: ${this.finger.substring(0, 16)}...`
    );
  }

  /**
   * 计算公钥指纹
   */
  async calculateFinger(publicKeyDer) {
    // 使用 SHA256 计算指纹并返回 base64
    const hashBuffer = await crypto.subtle.digest("SHA-256", publicKeyDer);
    return btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
  }

  /**
   * 获取指纹
   */
  finger() {
    return this.finger;
  }

  /**
   * 获取公钥
   */
  publicKey() {
    return this.publicKeyDer;
  }

  /**
   * RSA 解密
   * 基于 vnt_s/vnts/src/cipher/rsa_cipher.rs:116-148 实现
   */
  async decrypt(netPacket) {
    logger.debug(`[RSA解密-开始] 开始RSA解密操作`);
    try {
      // 导入私钥
      logger.debug(`[RSA解密-密钥] 导入RSA私钥`);
      const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        this.privateKeyDer,
        { name: "RSAES-PKCS1-v1_5" },
        false,
        ["decrypt"]
      );

      // 解密数据
      logger.debug(`[RSA解密-处理] 执行RSA解密`);
      const decryptedData = await crypto.subtle.decrypt(
        { name: "RSAES-PKCS1-v1_5" },
        privateKey,
        netPacket.payload()
      );

      // 创建 RSA 密钥体
      logger.debug(`[RSA解密-密钥体] 构建RSA密钥体`);
      const secretBody = new RsaSecretBody(new Uint8Array(decryptedData));

      // 构建 nonce
      const nonceRaw = this.buildNonceRaw(netPacket);
      logger.debug(`[RSA解密-验证] 构建nonce，长度: ${nonceRaw.length}字节`);

      // 验证指纹
      logger.debug(`[RSA解密-指纹] 开始验证数据指纹`);
      const hasher = await crypto.subtle.digest(
        "SHA-256",
        new Uint8Array([...secretBody.body(), ...nonceRaw])
      );
      const hashArray = new Uint8Array(hasher);
      const expectedFinger = hashArray.slice(16);

      if (!this.arraysEqual(expectedFinger, secretBody.finger())) {
        logger.error(`[RSA解密-错误] 指纹验证失败，数据可能被篡改`);
        throw new Error("finger err");
      }
      logger.debug(`[RSA解密-成功] RSA解密完成，数据完整性验证通过`);

      return secretBody;
    } catch (error) {
      logger.error(`[RSA解密-失败] 解密过程异常: ${error.message}`);
      throw new Error(`decrypt failed ${error.message}`);
    }
  }

  /**
   * RSA 加密
   * 基于 vnt_s/vnt/vnt/src/cipher/rsa_cipher.rs:69-111 实现
   */
  async encrypt(netPacket) {
    logger.debug(`[RSA加密-开始] 开始RSA加密操作`);
    if (netPacket.reserve() < 256) {
      logger.error(`[RSA加密-错误] 数据包预留空间不足，需要256字节`);
      // RSA_ENCRYPTION_RESERVED
      throw new Error("too short");
    }

    const dataLen = netPacket.data_len() + 256;
    netPacket.set_data_len(dataLen);
    logger.debug(`[RSA加密-准备] 数据包长度调整为: ${dataLen}字节`);

    const nonceRaw = this.buildNonceRaw(netPacket);
    const secretBody = new RsaSecretBody(netPacket.payload_mut());

    // 设置随机数
    logger.debug(`[RSA加密-随机数] 生成64字节随机数`);
    const random = new Uint8Array(64);
    crypto.getRandomValues(random);
    secretBody.set_random(random);

    // 计算指纹
    logger.debug(`[RSA加密-指纹] 计算数据指纹`);
    const hasher = await crypto.subtle.digest(
      "SHA-256",
      new Uint8Array([...secretBody.body(), ...nonceRaw])
    );
    const hashArray = new Uint8Array(hasher);
    secretBody.set_finger(hashArray.slice(16));

    // 导入公钥并加密
    logger.debug(`[RSA加密-密钥] 导入RSA公钥`);
    const publicKey = await crypto.subtle.importKey(
      "spki",
      this.publicKeyDer,
      { name: "RSAES-PKCS1-v1_5" },
      false,
      ["encrypt"]
    );

    logger.debug(`[RSA加密-处理] 执行RSA加密`);
    const encryptedData = await crypto.subtle.encrypt(
      { name: "RSAES-PKCS1-v1_5" },
      publicKey,
      secretBody.buffer()
    );

    // 创建新的数据包
    const newPacket = NetPacket.new(
      new Uint8Array(12 + encryptedData.byteLength)
    );
    newPacket.buffer_mut().set(netPacket.buffer().slice(0, 12), 0);
    newPacket.set_payload(new Uint8Array(encryptedData));
    logger.debug(
      `[RSA加密-成功] RSA加密完成，密文长度: ${encryptedData.byteLength}字节`
    );

    return newPacket;
  }

  buildNonceRaw(netPacket) {
    const nonceRaw = new Uint8Array(12);
    const sourceOctets = this.ipv4ToOctets(netPacket.source());
    const destOctets = this.ipv4ToOctets(netPacket.destination());

    nonceRaw.set(sourceOctets, 0);
    nonceRaw.set(destOctets, 4);
    nonceRaw[8] = netPacket.protocol();
    nonceRaw[9] = netPacket.transport_protocol();
    nonceRaw[10] = netPacket.is_gateway() ? 1 : 0;
    nonceRaw[11] = netPacket.source_ttl();

    return nonceRaw;
  }

  ipv4ToOctets(ip) {
    return [
      (ip >>> 24) & 0xff,
      (ip >>> 16) & 0xff,
      (ip >>> 8) & 0xff,
      ip & 0xff,
    ];
  }

  arraysEqual(a, b) {
    return a.length === b.length && a.every((val, i) => val === b[i]);
  }
}

/**
 * AES-GCM 加密器
 * 基于 vnt_s/vnt/vnt/src/cipher/aes_gcm/aes_gcm_cipher.rs 实现
 */
export class AesGcmCipher {
  constructor(key, finger) {
    const keySize = key.length === 16 ? "128位" : "256位";
    logger.debug(`[AES-GCM-初始化] 创建${keySize}AES-GCM加密器`);
    this.key = key;
    this.finger = finger;
  }

  /**
   * 创建 128 位 AES-GCM 加密器
   */
  static new_128(key, finger) {
    if (key.length !== 16) {
      throw new Error("Key must be 16 bytes for AES-128");
    }
    return new AesGcmCipher(key, finger);
  }

  /**
   * 创建 256 位 AES-GCM 加密器
   */
  static new_256(key, finger) {
    if (key.length !== 32) {
      throw new Error("Key must be 32 bytes for AES-256");
    }
    return new AesGcmCipher(key, finger);
  }

  /**
   * IPv4 数据包解密
   * 基于 vnt_s/vnt/vnt/src/cipher/aes_gcm/aes_gcm_cipher.rs:38-76 实现
   */
  async decrypt_ipv4(netPacket) {
    logger.debug(`[AES解密-开始] 开始AES-GCM解密`);
    if (!netPacket.is_encrypt()) {
      logger.warn(`[AES解密-警告] 数据包未标记为加密状态`);
      throw new Error("not encrypt");
    }

    if (netPacket.payload().len < 16) {
      logger.error(`[AES解密-错误] 载荷长度不足，至少需要16字节`);
      // AES_GCM_ENCRYPTION_RESERVED
      throw new Error("data err");
    }

    const nonceRaw = netPacket.head_tag();
    logger.debug(`[AES解密-参数] 获取nonce，长度: ${nonceRaw.length}字节`);
    const secretBody = new SecretBody(
      netPacket.payload_mut(),
      this.finger !== null
    );

    // 验证指纹
    if (this.finger) {
      logger.debug(`[AES解密-指纹] 开始验证AES-GCM指纹`);
      const finger = this.finger.calculate_finger(
        nonceRaw,
        secretBody.en_body()
      );
      if (!this.arraysEqual(finger, secretBody.finger())) {
        logger.error(`[AES解密-错误] AES-GCM指纹验证失败`);
        throw new Error("finger err");
      }
    }

    try {
      // 导入 AES 密钥
      logger.debug(`[AES解密-密钥] 导入AES密钥`);
      const aesKey = await crypto.subtle.importKey(
        "raw",
        this.key,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      // 解密数据
      logger.debug(`[AES解密-处理] 执行AES-GCM解密`);
      const decryptedData = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: nonceRaw,
        },
        aesKey,
        secretBody.en_body()
      );

      // 更新数据包
      netPacket.set_encrypt_flag(false);
      netPacket.set_data_len(netPacket.data_len() - 16);
      netPacket.payload_mut().set(new Uint8Array(decryptedData), 0);
      logger.debug(
        `[AES解密-成功] AES-GCM解密完成，明文长度: ${decryptedData.byteLength}字节`
      );
    } catch (error) {
      logger.error(`[AES解密-失败] 解密过程异常: ${error.message}`);
      throw new Error(`解密失败: ${error.message}`);
    }
  }

  /**
   * IPv4 数据包加密
   * 基于 vnt_s/vnt/vnt/src/cipher/aes_gcm/aes_gcm_cipher.rs:79-112 实现
   */
  async encrypt_ipv4(netPacket) {
    if (netPacket.reserve() < 16) {
      // AES_GCM_ENCRYPTION_RESERVED
      throw new Error("too short");
    }

    const nonceRaw = netPacket.head_tag();
    const dataLen = netPacket.data_len() + 16;
    netPacket.set_data_len(dataLen);

    const secretBody = new SecretBody(
      netPacket.payload_mut(),
      this.finger !== null
    );
    secretBody.set_random(Math.floor(Math.random() * 0xffffffff));

    try {
      // 导入 AES 密钥
      const aesKey = await crypto.subtle.importKey(
        "raw",
        this.key,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
      );

      // 加密数据
      const encryptedData = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonceRaw,
        },
        aesKey,
        secretBody.body()
      );

      const encryptedArray = new Uint8Array(encryptedData);
      const tag = encryptedArray.slice(-16); // GCM tag 是最后 16 字节
      const ciphertext = encryptedArray.slice(0, -16);

      // 设置加密结果
      secretBody.set_body(ciphertext);
      secretBody.set_tag(tag);

      if (this.finger) {
        const finger = this.finger.calculate_finger(
          nonceRaw,
          secretBody.en_body()
        );
        secretBody.set_finger(finger);
      }

      netPacket.set_encrypt_flag(true);
    } catch (error) {
      throw new Error(`加密失败: ${error.message}`);
    }
  }

  arraysEqual(a, b) {
    return a.length === b.length && a.every((val, i) => val === b[i]);
  }
}

/**
 * 指纹计算器
 * 基于 vnt_s/vnts/src/cipher/finger.rs 实现
 */
export class Finger {
  constructor(token) {
    logger.debug(
      `[指纹计算器-初始化] 创建指纹计算器，token长度: ${token.length}`
    );
    this.token = token;
  }

  /**
   * 计算指纹
   */
  async calculate_finger(nonceRaw, data) {
    logger.debug(`[指纹计算-开始] 开始计算SHA-256指纹`);
    logger.debug(
      `[指纹计算-参数] nonce长度: ${nonceRaw.length}字节, data长度: ${data.length}字节`
    );

    const combined = new Uint8Array([
      ...nonceRaw,
      ...data,
      ...new TextEncoder().encode(this.token),
    ]);

    logger.debug(`[指纹计算-处理] 合并数据长度: ${combined.length}字节`);

    const hash = await crypto.subtle.digest("SHA-256", combined);
    const finger = new Uint8Array(hash).slice(0, 16);

    logger.debug(`[指纹计算-完成] 指纹计算完成，取前16字节`);
    return finger;
  }
}

/**
 * RSA 密钥体
 * 基于 vnt_s/vnts/src/protocol/body.rs:529-563 实现
 */
export class RsaSecretBody {
  constructor(buffer) {
    this.buffer = buffer;
    this.len = buffer.length;
  }

  data() {
    return this.buffer.slice(0, this.len - 64); // 减去 random(32) + finger(32)
  }

  random() {
    return this.buffer.slice(this.len - 64, this.len - 32);
  }

  body() {
    return this.buffer.slice(0, this.len - 32);
  }

  finger() {
    return this.buffer.slice(this.len - 32);
  }

  buffer() {
    return this.buffer;
  }

  set_random(random) {
    this.buffer.set(random, this.len - 64);
  }

  set_finger(finger) {
    this.buffer.set(finger, this.len - 32);
  }
}

/**
 * AES 密钥体
 * 基于 VNT 协议的 SecretBody 实现
 */
export class SecretBody {
  constructor(buffer, hasFinger) {
    this.buffer = buffer;
    this.hasFinger = hasFinger;
  }

  en_body() {
    if (this.hasFinger) {
      return this.buffer.slice(0, this.buffer.length - 16); // 减去 finger
    }
    return this.buffer;
  }

  body() {
    if (this.hasFinger) {
      return this.buffer.slice(0, this.buffer.length - 32); // 减去 random + finger
    }
    return this.buffer.slice(0, this.buffer.length - 16); // 减去 random
  }

  body_mut() {
    return this.buffer;
  }

  finger() {
    if (this.hasFinger) {
      return this.buffer.slice(-16);
    }
    return new Uint8Array(0);
  }

  set_random(random) {
    const view = new DataView(this.buffer.buffer, this.buffer.byteOffset);
    view.setUint32(0, random, true);
  }

  set_tag(tag) {
    this.buffer.set(tag, this.buffer.length - 16 - (this.hasFinger ? 16 : 0));
  }

  set_finger(finger) {
    if (this.hasFinger) {
      this.buffer.set(finger, this.buffer.length - 16);
    }
  }
}

/**
 * 生成随机 U64 字符串
 */
export function randomU64String() {
  const array = new Uint8Array(8);
  crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join(
    ""
  );
}

/**
 * 生成 RSA 密钥对
 */
export async function generateRsaKeyPair() {
  logger.info(`[密钥生成-开始] 开始生成2048位RSA密钥对`);

  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSAES-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
      },
      true,
      ["encrypt", "decrypt"]
    );

    logger.debug(`[密钥生成-导出] 导出私钥和公钥`);
    const privateKeyDer = await crypto.subtle.exportKey(
      "pkcs8",
      keyPair.privateKey
    );
    const publicKeyDer = await crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey
    );

    const result = {
      privateKey: new Uint8Array(privateKeyDer),
      publicKey: new Uint8Array(publicKeyDer),
    };

    logger.info(
      `[密钥生成-成功] RSA密钥对生成完成，私钥长度: ${result.privateKey.length}字节，公钥长度: ${result.publicKey.length}字节`
    );
    return result;
  } catch (error) {
    logger.error(`[密钥生成-失败] 密钥生成异常: ${error.message}`);
    throw error;
  }
}
