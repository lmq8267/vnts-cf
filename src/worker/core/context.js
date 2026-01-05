import { logger } from "./logger.js";

class ExpireMap {
  constructor(ttlMs = 24 * 3600 * 1000, onExpire = null) {
    // logger.debug(`[过期映射-初始化] 创建ExpireMap，TTL: ${ttlMs}ms`);
    this.map = new Map();
    this.ttlMs = ttlMs;
    this.onExpire = onExpire;
    this.cleanupTimer = null;
    this.startCleanupTimer();
    // logger.debug(`[过期映射-配置] 定时器间隔: 30秒，回调函数: ${onExpire ? "已设置" : "未设置"}`);
  }

  set(key, value, customTtlMs = null) {
    const ttl = customTtlMs || this.ttlMs;
    const expireTime = Date.now() + ttl;
    // logger.debug(`[过期映射-设置] 键: ${key}, TTL: ${ttl}ms, 过期时间: ${new Date(expireTime).toISOString()}`);
    this.map.set(key, { value, expireTime });
  }

  get(key) {
    const item = this.map.get(key);
    if (!item) {
      // logger.debug(`[过期映射-获取] 键不存在: ${key}`);
      return undefined;
    }

    if (Date.now() > item.expireTime) {
      // logger.debug(`[过期映射-过期] 键已过期并删除: ${key}`);
      this.map.delete(key);
      if (this.onExpire) {
        // logger.debug(`[过期映射-回调] 执行过期回调: ${key}`);
        this.onExpire(key, item.value);
      }
      return undefined;
    }

    // 延长过期时间
    const newExpireTime = Date.now() + this.ttlMs;
    item.expireTime = newExpireTime;
    // logger.debug(`[过期映射-续期] 键: ${key}, 新过期时间: ${new Date(newExpireTime).toISOString()}`);
    return item.value;
  }

  delete(key) {
    const existed = this.map.has(key);
    this.map.delete(key);

    if (existed) {
      // logger.debug(`[过期映射-删除] 手动删除键: ${key}`);
    } else {
      // logger.debug(`[过期映射-删除] 键不存在，无需删除: ${key}`);
    }

    return existed;
  }

  cleanup() {
    // logger.debug(`[过期映射-清理] 开始清理过期项，当前项数: ${this.map.size}`);

    const now = Date.now();
    let cleanedCount = 0;

    for (const [key, item] of this.map.entries()) {
      if (now > item.expireTime) {
        // logger.debug(`[过期映射-清理] 删除过期项: ${key} (过期于: ${new Date(item.expireTime).toISOString()})`);
        this.map.delete(key);
        if (this.onExpire) {
          this.onExpire(key, item.value);
        }
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      // logger.debug(`[过期映射-清理] 清理完成，删除了 ${cleanedCount} 个过期项，剩余 ${this.map.size} 项`);
    } else {
      // logger.debug(`[过期映射-清理] 无过期项需要清理`);
    }
  }

  startCleanupTimer() {
    // logger.debug(`[过期映射-定时器] 启动30秒间隔的清理定时器`);
    this.cleanupTimer = setInterval(() => this.cleanup(), 30000);
  }

  destroy() {
    if (this.cleanupTimer) {
      // logger.debug(`[过期映射-销毁] 停止清理定时器，销毁ExpireMap实例`);
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;

      const itemCount = this.map.size;
      this.map.clear();
      // logger.debug(`[过期映射-销毁] 已清理 ${itemCount} 个剩余项，ExpireMap已完全销毁`);
    }
  }
}
/**
 * VNT 连接上下文
 * 对应 Rust 中的 VntContext 结构体
 */
export class VntContext {
  constructor(options = {}) {
    this.link_context = options.linkContext || null;
    this.server_cipher = options.serverCipher || null;
    this.link_address = options.linkAddress || null;
  }

  /**
   * 离开连接，清理资源
   * 对应 Rust 中的 leave 方法
   */
  async leave(cache) {
    // logger.debug(`[连接清理-开始] 开始清理客户端连接资源`);
    // 清理服务端加密会话
    if (this.server_cipher) {
      // logger.debug(`[连接清理-加密] 清理服务端加密会话: ${this.link_address}`);
      cache.cipher_session.delete(this.link_address);
    }

    // 清理链接上下文
    if (this.link_context) {
      // logger.debug(`[连接清理-上下文] 开始清理链接上下文`);
      // 优先使用直接引用，避免缓存过期问题
      let networkInfo = this.link_context.network_info;

      // 如果直接引用不存在，再尝试从缓存获取
      // if (!networkInfo) {
      //    networkInfo = cache.virtual_network.get(this.link_context.group);
      // }
      if (networkInfo) {
        // logger.debug(`[连接清理-网络] 匹配到token: ${this.link_context.group}`);
        const clients = networkInfo.clients;

        // 获取客户端信息
        const clientInfo = clients.get(this.link_context.virtual_ip);
        if (clientInfo) {
          // logger.debug(`[连接清理-客户端] 匹配到客户端: ${formatIp(this.link_context.virtual_ip)}`);

          // 更新客户端状态
          // logger.debug(`[连接清理-状态] 更新客户端状态为离线: ${this.link_context.virtual_ip}`);
          clientInfo.online = false;
          clientInfo.tcp_sender = null;
          clientInfo.offline_timestamp = Date.now(); // 记录离线时间
          networkInfo.epoch += 1;
          logger.info(
            `[客户端离线] 主机名:${clientInfo.name} ID:${
              clientInfo.device_id
            } IP:${formatIp(this.link_context.virtual_ip)} 已离线`
          );
        }

        // 插入 IP 会话记录，设置1天过期
        cache.insert_ip_session(
          [this.link_context.group, this.link_context.virtual_ip],
          this.link_address
        );
      }
    }
    // logger.debug(`[连接清理-完成] 客户端连接资源清理完成`);
  }
}

// 格式化IP
function formatIp(ipUint32) {
  return `${(ipUint32 >>> 24) & 0xff}.${(ipUint32 >>> 16) & 0xff}.${
    (ipUint32 >>> 8) & 0xff
  }.${ipUint32 & 0xff}`;
}

/**
 * VNT 链接上下文
 * 对应 Rust 中的 LinkVntContext 结构体
 */
export class LinkVntContext {
  constructor(options = {}) {
    this.network_info = options.networkInfo || null;
    this.group = options.group || "";
    this.virtual_ip = options.virtualIp || 0;
    this.broadcast = options.broadcast || new Ipv4Addr([255, 255, 255, 255]);
    this.timestamp = options.timestamp || Date.now();
  }
}

/**
 * 网络信息结构
 * 对应 Rust 中的 NetworkInfo
 */
export class NetworkInfo {
  constructor(network, netmask, gateway) {
    this.network = network;
    this.netmask = netmask;
    this.gateway = gateway;
    this.clients = new Map();
    this.epoch = 0;
  }

  static new(network, netmask, gateway) {
    return new NetworkInfo(network, netmask, gateway);
  }
}

/**
 * 客户端信息结构
 * 对应 Rust 中的 ClientInfo
 */
export class ClientInfo {
  constructor(options = {}) {
    this.virtual_ip = options.virtualIp || 0;
    this.device_id = options.device_id || "";
    this.name = options.name || "";
    this.version = options.version || "";
    this.wireguard = options.wireguard || null;
    this.online = options.online || false;
    this.address = options.address || { ip: "0.0.0.0", port: 0 };
    this.client_secret = options.clientSecret || false;
    this.client_secret_hash = options.clientSecretHash || [];
    this.server_secret = options.serverSecret || false;
    this.tcp_sender = options.tcpSender || null;
    this.wg_sender = options.wgSender || null;
    this.client_status = options.clientStatus || null;
    this.last_join_time = options.lastJoinTime || new Date();
    this.timestamp = options.timestamp || Date.now();
    this.status_update_time = options.status_update_time || null;
  }
}

/**
 * 应用缓存结构
 * 对应 Rust 中的 AppCache
 */
export class AppCache {
  constructor() {
    // logger.debug(`[应用缓存-初始化] 开始初始化AppCache`);
    // 虚拟网络映射：group -> NetworkInfo (7天过期)
    // logger.debug(`[应用缓存-网络] 创建虚拟网络映射，TTL: 7天`);
    this.virtual_network = new ExpireMap(
      7 * 24 * 3600 * 1000,
      (key, networkInfo) => {
        // 网络过期时检查是否有客户端
        if (networkInfo.clients.size === 0) {
          // logger.debug(`[应用缓存-网络] 网络过期并清理: ${key}`);
        }
      }
    );

    // IP 会话映射：(group, ip) -> address (1天过期)
    // logger.debug(`[应用缓存-会话] 创建IP会话映射，TTL: 1天`);
    this.ip_session = new ExpireMap(24 * 3600 * 1000, (key, address) => {
      // IP过期时清理离线客户端
      const [group, ip] = JSON.parse(key);
      const networkInfo = this.virtual_network.get(group);
      if (networkInfo) {
        const clientInfo = networkInfo.clients.get(ip);
        if (
          clientInfo &&
          !clientInfo.online &&
          clientInfo.address === address &&
          clientInfo.offline_timestamp &&
          Date.now() - clientInfo.offline_timestamp >= 24 * 3600 * 1000
        ) {
          networkInfo.clients.delete(ip);
          networkInfo.epoch += 1;
          logger.info(
            `[客户端清理] 设备 ${clientInfo.name} (${
              clientInfo.device_id
            }) IP ${this.formatIp(ip)} 离线超过1天，已清理`
          );
        }
      }
    });

    // 加密会话映射：address -> cipher (1小时过期)
    // logger.debug(`[应用缓存-加密] 创建加密会话映射，TTL: 1小时`);
    this.cipher_session = new ExpireMap(3600 * 1000);

    // 认证映射：token -> () (24小时过期)
    // logger.debug(`[应用缓存-认证] 创建认证映射，TTL: 24小时`);
    this.auth_map = new ExpireMap(24 * 3600 * 1000);

    // WireGuard 组映射：public_key -> config (永不过期)
    this.wg_group_map = new Map();
    // logger.debug(`[应用缓存-完成] AppCache初始化完成`);
  }

  async insert_ip_session(key, value) {
    this.ip_session.set(JSON.stringify(key), value);
  }

  get_ip_session(key) {
    return this.ip_session.get(JSON.stringify(key));
  }

  delete_ip_session(key) {
    return this.ip_session.delete(JSON.stringify(key));
  }

  destroy() {
    this.virtual_network.destroy();
    this.ip_session.destroy();
    this.cipher_session.destroy();
    this.auth_map.destroy();
  }
}

/**
 * IPv4 地址工具类
 */
export class Ipv4Addr {
  constructor(octets) {
    this.octets = octets;
  }

  static from(u32) {
    return new Ipv4Addr([
      (u32 >>> 24) & 0xff,
      (u32 >>> 16) & 0xff,
      (u32 >>> 8) & 0xff,
      u32 & 0xff,
    ]);
  }

  toString() {
    return this.octets.join(".");
  }

  valueOf() {
    return (
      (this.octets[0] << 24) |
      (this.octets[1] << 16) |
      (this.octets[2] << 8) |
      this.octets[3]
    );
  }
}

/**
 * 客户端状态信息
 * 对应 Rust 中的 ClientStatusInfo
 */
export class ClientStatusInfo {
  constructor() {
    this.p2p_list = [];
    this.up_stream = 0;
    this.down_stream = 0;
    this.is_cone = false;
    this.update_time = new Date();
  }
}
