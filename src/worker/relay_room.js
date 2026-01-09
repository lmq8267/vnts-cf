import { NetPacket } from "./core/packet.js";
import { VntContext } from "./core/context.js";
import { PacketHandler } from "./core/handler.js";
import { PROTOCOL, TRANSPORT_PROTOCOL } from "./core/constants.js";
import { parseVNTHeaderFast } from "./utils/fast_parser.js";
import { logger, setPendingStorage } from "./core/logger.js";

export class RelayRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    if (typeof globalThis !== "undefined") {
      globalThis.RelayRoomInstance = this;
    }
    this.connections = new Map();
    this.contexts = new Map();
    this.p2p_connections = new Map();
    this.connection_last_update = new Map();
    // 连接信息存储
    this.connectionInfos = new Map();
    this.packetHandler = new PacketHandler(env, this);

    this.isInitialized = false;
    this.initPromise = null;

    // 添加启动时间
    this.startTime = null;

    // 心跳管理
    this.heartbeatTimers = new Map();
    this.heartbeatInterval = parseInt(env.HEARTBEAT_INTERVAL || "60") * 1000;

    // 添加限流机制
    this.rateLimitMap = new Map(); // IP -> {count, lastReset}
    this.rateLimitConfig = {
      maxRequestsPerMinute: parseInt(env.RATE_LIMIT_PER_MINUTE || "60"),
      windowMs: 60000, // 1分钟
    };

    // 添加监控统计
    this.requestMetrics = {
      room: { count: 0, lastReset: Date.now() },
      test: { count: 0, lastReset: Date.now() },
    };
    // 添加缓存保存控制
    this.isSavingCache = false; // 防止并发保存
    this.pendingSave = false; // 是否有待保存的更改
    this.lastCacheSaveTime = 0; // 上次保存时间
    this.saveAlarmScheduled = false; // 是否已调度定时保存

    // 登录失败计数器
    this.loginAttempts = new Map();
  }

  // 检查IP限流
  checkRateLimit(clientIp, endpoint = "default") {
    const now = Date.now();
    const record = this.rateLimitMap.get(clientIp) || {
      count: 0,
      lastReset: now,
      endpointCount: new Map(), // endpoint -> count
    };

    // 重置过期窗口
    if (now - record.lastReset > this.rateLimitConfig.windowMs) {
      record.count = 0;
      record.lastReset = now;
      record.endpointCount.clear();
    }

    // 检查总限制
    if (record.count >= this.rateLimitConfig.maxRequestsPerMinute) {
      logger.warn(
        `[限流] IP ${clientIp} 超出每分钟请求限制: ${record.count}/${this.rateLimitConfig.maxRequestsPerMinute}`
      );
      return false;
    }

    // 更新计数
    record.count++;
    const endpointCount = record.endpointCount.get(endpoint) || 0;
    record.endpointCount.set(endpoint, endpointCount + 1);
    this.rateLimitMap.set(clientIp, record);

    // 更新监控统计
    if (this.requestMetrics[endpoint]) {
      if (
        now - this.requestMetrics[endpoint].lastReset >
        this.rateLimitConfig.windowMs
      ) {
        this.requestMetrics[endpoint].count = 0;
        this.requestMetrics[endpoint].lastReset = now;
      }
      this.requestMetrics[endpoint].count++;
    }

    return true;
  }

  // 获取客户端IP
  getClientIp(request) {
    // 优先从CF-Connecting-IP获取真实IP（不区分大小写）
    const headers = {};

    // 将所有header转换为小写key，实现不区分大小写查找
    for (const [key, value] of request.headers.entries()) {
      headers[key.toLowerCase()] = value;
    }

    return (
      headers["cf-connecting-ip"] ||
      headers["x-real-ip"] ||
      headers["x-forwarded-for"] ||
      "unknown"
    );
  }

  async init() {
    if (!this.isInitialized) {
      if (!this.initPromise) {
        this.initPromise = this.doInit();
      }
      await this.initPromise;
      this.isInitialized = true;
    }
  }

  // 从存储恢复 AppCache
  async restoreAppCache() {
    try {
      // 检查是否为本地部署
      const isLocalDeploy = this.env.LOCAL_DEPLOY === "true";
      if (isLocalDeploy) {
        logger.info(`[AppCache-恢复] 本地部署模式，跳过从存储恢复`);
        return;
      }

      const cacheData = await this.state.storage.get("appCacheData");

      if (!cacheData) {
        logger.info(`[AppCache-恢复] 存储中无缓存数据，使用新实例`);
        return;
      }

      // 检查缓存版本
      if (cacheData.version !== "1.0") {
        logger.warn(`[AppCache-恢复] 缓存版本不匹配，使用新实例`);
        return;
      }

      // 反序列化 AppCache
      const { AppCache } = await import("./core/context.js");
      const restoredCache = AppCache.deserialize(cacheData, this);
      // logger.debug("restore", "反序列化结果检查", {hasVirtualNetwork: !!restoredCache.virtual_network,virtualNetworkMapSize: restoredCache.virtual_network?.map?.size || 0,virtualNetworkEntries:restoredCache.virtual_network?.map?.entries().length || 0,});

      // 检查原始数据结构
      if (cacheData.virtual_network) {
        // logger.debug("restore", "原始数据检查", {hasVirtualNetwork: true,entriesCount: cacheData.virtual_network.entries?.length || 0,firstEntry: cacheData.virtual_network.entries?.[0],});
      }

      // 替换 PacketHandler 中的缓存
      this.packetHandler.cache = restoredCache;
      restoredCache.relayRoom = this;
      // 恢复 networks 引用（这是在 handler.js 中使用的快捷引用）
      if (!this.packetHandler.cache.networks) {
        this.packetHandler.cache.networks = new Map();
      }

      // 将 virtual_network 中的数据同步到 networks，并清理过期客户端
      let restoredNetworks = 0;
      let cleanedClients = 0;
      let cleanedNetworks = 0;
      const now = Date.now();
      const offlineThreshold = 24 * 3600 * 1000; // 24小时
      let hasChanges = false; // 标记是否有清理操作

      const mapKeys = Array.from(restoredCache.virtual_network.map.keys());
      for (const token of mapKeys) {
        const item = restoredCache.virtual_network.map.get(token);
        if (item && Date.now() <= item.expireTime) {
          const networkInfo = item.value;

          // 检查并清理过期客户端
          const clientsToDelete = [];
          if (networkInfo && networkInfo.clients) {
            for (const [
              virtualIp,
              clientInfo,
            ] of networkInfo.clients.entries()) {
              // 如果客户端离线且有离线时间戳，检查是否超过24小时
              if (
                !clientInfo.online &&
                clientInfo.offline_timestamp &&
                now - clientInfo.offline_timestamp >= offlineThreshold
              ) {
                clientsToDelete.push(virtualIp);
              }
            }

            // 删除过期客户端
            for (const virtualIp of clientsToDelete) {
              const deletedClient = networkInfo.clients.get(virtualIp);
              networkInfo.clients.delete(virtualIp);
              cleanedClients++;
              hasChanges = true;
              logger.info(
                `[AppCache-恢复] 清理离线超过24小时的客户端: ${
                  deletedClient.name
                } ID:${
                  deletedClient.device_id
                } IP:${this.packetHandler.formatIp(virtualIp)}`
              );
            }

            // 检查是否只有网关（没有实际客户端）
            const hasOnlyGateway =
              networkInfo.clients.size === 1 && networkInfo.clients.has(0);

            // 只有在清理后还有实际客户端时才恢复
            if (networkInfo.clients.size > 0 && !hasOnlyGateway) {
              this.packetHandler.cache.networks.set(token, item.value);
              restoredNetworks++;
            } else if (hasOnlyGateway) {
              // 如果只有网关，清理整个网络
              cleanedNetworks++;
              hasChanges = true;
              logger.info(`[AppCache-恢复] 清理只有网关的网络: Token ${token}`);
            }
          }
        }
      }

      // 如果有清理操作，立即保存到存储
      if (hasChanges) {
        // 清理 ip_session 中的过期记录
        const ipSessionKeys = Array.from(restoredCache.ip_session.map.keys());
        for (const key of ipSessionKeys) {
          const item = restoredCache.ip_session.map.get(key);
          if (item && Date.now() > item.expireTime) {
            restoredCache.ip_session.map.delete(key);
          }
        }
        await this.saveAppCache(true); // 跳过初始化检查
        logger.debug(`[AppCache-恢复] 清理完成，保存到存储`);
      }

      // logger.debug("restore", "成功恢复 AppCache", {totalNetworks: restoredCache.virtual_network.map.size,restoredNetworks: restoredNetworks,});

      logger.info(
        `[AppCache-恢复] 成功恢复 AppCache，Token数量: ${this.packetHandler.cache.networks.size}`
      );
    } catch (error) {
      logger.error(`[AppCache-恢复] 恢复失败: ${error.message}`, error);
      // 恢复失败时继续使用新的 AppCache
    }
  }

  // 保存 AppCache 到存储
  async saveAppCache(skipInitCheck = false) {
    // 检查是否为本地部署
    const isLocalDeploy = this.env.LOCAL_DEPLOY === "true";
    if (isLocalDeploy) {
      // 本地部署模式，不保存到存储
      return;
    }

    // 检查是否已经完成初始化恢复
    if (!skipInitCheck && !this.isInitialized) {
      return;
    }

    // 防止并发保存
    if (this.isSavingCache) {
      this.pendingSave = true;
      return;
    }

    try {
      this.isSavingCache = true;
      this.pendingSave = false;

      // 序列化 AppCache
      const cacheData = this.packetHandler.cache.serialize();
      // logger.debug("save", "AppCache 序列化完成", {networksCount: this.packetHandler.cache.networks?.size || 0,dataSize: JSON.stringify(cacheData).length,});

      // 保存到 Durable Object Storage
      await this.state.storage.put("appCacheData", cacheData);

      this.lastCacheSaveTime = Date.now();
      // logger.debug(`[AppCache-保存] 成功保存缓存到存储`);
    } catch (error) {
      logger.error(`[AppCache-保存] 保存失败: ${error.message}`, error);
    } finally {
      this.isSavingCache = false;

      // 如果有待保存的更改，再次触发保存
      if (this.pendingSave) {
        // 使用 Promise 而不是 setTimeout
        Promise.resolve().then(() => this.saveAppCache());
      }
    }
  }

  // 同步保存（立即保存，不使用定时器）
  async syncSaveAppCache() {
    await this.saveAppCache();
  }

  // 设置定时保存 Alarm
  async setupSaveAlarm() {
    // 检查是否为本地部署
    const isLocalDeploy = this.env.LOCAL_DEPLOY === "true";
    if (isLocalDeploy) {
      // logger.debug(`[Alarm-设置] 本地部署模式，跳过设置定时保存`);
      return;
    }

    // 设置定时保存，每 5 分钟保存一次
    const saveIntervalMs =
      parseInt(this.env.CACHE_SAVE_INTERVAL || "300") * 1000;

    // 调度 Alarm
    await this.state.storage.setAlarm(Date.now() + saveIntervalMs);
    this.saveAlarmScheduled = true;

    logger.debug(
      `[Alarm-设置] 已设置定时保存，间隔: ${saveIntervalMs / 1000} 秒`
    );
  }

  // Alarm 处理函数
  async alarm() {
    // logger.debug(`[Alarm-触发] 定时保存触发`);
    try {
      // 执行保存
      await this.saveAppCache();

      // 重新调度下一次 Alarm
      await this.setupSaveAlarm();
      // logger.debug(`[Alarm-完成] 定时保存完成，已调度下一次保存`);
    } catch (error) {
      logger.error(`[Alarm-错误] 定时保存失败: ${error.message}`, error);

      // 即使失败也要重新调度
      try {
        await this.setupSaveAlarm();
      } catch (scheduleError) {
        logger.error(
          `[Alarm-错误] 重新调度失败: ${scheduleError.message}`,
          scheduleError
        );
      }
    }
  }

  async doInit() {
    try {
      // 初始化PacketHandler（包括RSA）
      await this.packetHandler.init();

      // 设置启动时间
      this.startTime = Date.now();

      // 设置 logger 的 storage 引用
      setPendingStorage(this.state.storage);

      // 从存储恢复 AppCache
      await this.restoreAppCache();
      // 清除可能存在的旧 Alarm 防止覆盖原始数据
      await this.state.storage.deleteAlarm();

      // 设置定时保存 Alarm
      await this.setupSaveAlarm();

      // logger.info(`[RelayRoom-初始化] RelayRoom初始化完成`);
    } catch (error) {
      logger.error(`[RelayRoom-初始化] 初始化失败: ${error.message}`, error);
      throw error;
    }
  }
  // 计算并格式化运行时长
  getRunningDuration() {
    const now = Date.now();
    const duration = now - this.startTime;

    const seconds = Math.floor(duration / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    const months = Math.floor(days / 30);
    const years = Math.floor(days / 365);

    const parts = [];

    if (years > 0) parts.push(`${years}年`);
    if (months > 0) parts.push(`${months % 12}月`);
    if (days > 0) parts.push(`${days % 30}天`);
    if (hours > 0) parts.push(`${hours % 24}时`);
    if (minutes > 0) parts.push(`${minutes % 60}分`);
    parts.push(`${seconds % 60}秒`);

    return parts.join("");
  }

  // 获取启动时间的北京时间
  getStartTimeBeijing() {
    const startTime = new Date(this.startTime);

    // 转换为北京时间（UTC+8）
    const beijingTime = new Date(startTime.getTime() + 8 * 60 * 60 * 1000);

    const year = beijingTime.getFullYear();
    const month = String(beijingTime.getMonth() + 1).padStart(2, "0");
    const day = String(beijingTime.getDate()).padStart(2, "0");
    const hours = String(beijingTime.getHours()).padStart(2, "0");
    const minutes = String(beijingTime.getMinutes()).padStart(2, "0");
    const seconds = String(beijingTime.getSeconds()).padStart(2, "0");

    // return `${year}年${month}月${day}日 ${hours}:${minutes}:${seconds}`;
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
  }

  // 获取网关IP地址
  getGatewayIp(clientId) {
    const context = this.contexts.get(clientId);
    if (context && context.link_context && context.link_context.network_info) {
      return context.link_context.network_info.gateway;
    }
    return null;
  }
  async handleGatewayPing(clientId, uint8Data) {
    try {
      // logger.info(`开始处理客户端发来的ping包`);

      // 直接修改原始数据包
      const modifiedData = new Uint8Array(uint8Data);

      // 正确解析VNT头部的源和目标地址
      const source =
        (modifiedData[4] << 24) |
        (modifiedData[5] << 16) |
        (modifiedData[6] << 8) |
        modifiedData[7];
      const destination =
        (modifiedData[8] << 24) |
        (modifiedData[9] << 16) |
        (modifiedData[10] << 8) |
        modifiedData[11];

      // logger.debug(`源地址: ${this.packetHandler.formatIp(source)}`);
      // logger.debug(`目标地址: ${this.packetHandler.formatIp(destination)}`);

      // 交换VNT头部的源和目标地址
      modifiedData[4] = (destination >> 24) & 0xff; // 新源地址（原目标）
      modifiedData[5] = (destination >> 16) & 0xff;
      modifiedData[6] = (destination >> 8) & 0xff;
      modifiedData[7] = destination & 0xff;
      modifiedData[8] = (source >> 24) & 0xff; // 新目标地址（原源）
      modifiedData[9] = (source >> 16) & 0xff;
      modifiedData[10] = (source >> 8) & 0xff;
      modifiedData[11] = source & 0xff;

      // logger.debug(`已将ping包的VNT头部地址已交换`);

      // 修改IPv4头部的源和目标地址
      const ipv4HeaderStart = 12;
      modifiedData[ipv4HeaderStart + 12] = (destination >> 24) & 0xff;
      modifiedData[ipv4HeaderStart + 13] = (destination >> 16) & 0xff;
      modifiedData[ipv4HeaderStart + 14] = (destination >> 8) & 0xff;
      modifiedData[ipv4HeaderStart + 15] = destination & 0xff;
      modifiedData[ipv4HeaderStart + 16] = (source >> 24) & 0xff;
      modifiedData[ipv4HeaderStart + 17] = (source >> 16) & 0xff;
      modifiedData[ipv4HeaderStart + 18] = (source >> 8) & 0xff;
      modifiedData[ipv4HeaderStart + 19] = source & 0xff;

      // 修改ICMP类型为Echo Reply (0)
      const icmpStart = ipv4HeaderStart + 20;
      // logger.debug(`原始ICMP类型: ${modifiedData[icmpStart]}`);
      modifiedData[icmpStart] = 0;
      // logger.debug(`修改后ICMP类型: ${modifiedData[icmpStart]}`);

      // 重新计算校验和
      modifiedData[icmpStart + 2] = 0;
      modifiedData[icmpStart + 3] = 0;
      const icmpData = modifiedData.slice(icmpStart);
      const icmpChecksum = this.calculateIcmpChecksum(icmpData);
      modifiedData[icmpStart + 2] = (icmpChecksum >> 8) & 0xff;
      modifiedData[icmpStart + 3] = icmpChecksum & 0xff;
      // logger.debug(`ICMP校验和: 0x${icmpChecksum.toString(16)}`);

      modifiedData[ipv4HeaderStart + 10] = 0;
      modifiedData[ipv4HeaderStart + 11] = 0;
      const ipv4Header = modifiedData.slice(ipv4HeaderStart, icmpStart);
      const ipv4Checksum = this.calculateIpv4Checksum(ipv4Header);
      modifiedData[ipv4HeaderStart + 10] = (ipv4Checksum >> 8) & 0xff;
      modifiedData[ipv4HeaderStart + 11] = ipv4Checksum & 0xff;
      // logger.debug(`IPv4校验和: 0x${ipv4Checksum.toString(16)}`);

      // logger.debug(`响应包长度: ${modifiedData.length}`);
      // logger.debug(`响应包内容: ${Array.from(modifiedData).map((b) => b.toString(16).padStart(2, "0")).join(" ")}`);

      return { buffer: () => modifiedData };
    } catch (error) {
      // logger.error("处理客户端ping网关的包失败:", error);
      return null;
    }
  }

  // 添加原始buffer的校验和计算方法
  calculateIcmpChecksum(data) {
    let sum = 0;
    for (let i = 0; i < data.length - 1; i += 2) {
      sum += (data[i] << 8) | data[i + 1];
    }
    if (data.length % 2 === 1) {
      sum += data[data.length - 1] << 8;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    return ~sum & 0xffff;
  }

  calculateIpv4Checksum(header) {
    let sum = 0;
    for (let i = 0; i < 20; i += 2) {
      sum += (header[i] << 8) | header[i + 1];
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    return ~sum & 0xffff;
  }
  // 更新P2P连接状态
  updateP2PStatus(clientId, p2pTargets) {
    this.p2p_connections.set(clientId, new Set(p2pTargets));
    this.connection_last_update.set(clientId, Date.now());
    // logger.debug(`更新客户端 ${clientId} 的P2P连接状态，目标数量: ${p2pTargets.length}`);
  }

  // 处理客户端 P2P 状态报告
  handleP2PStatusReport(clientId, p2pList) {
    // logger.debug(`开始处理客户端 ${clientId} 的P2P状态报告，目标数量: ${p2pList.length}`);
    const p2pTargets = [];
    for (const targetInfo of p2pList) {
      const targetClientId = this.findClientByIp(targetInfo.target_ip);
      if (targetClientId) {
        p2pTargets.push(targetClientId);
        // logger.debug(`找到P2P目标: ${targetInfo.target_ip} -> 客户端ID: ${targetClientId}`);
      } else {
        // logger.debug(`未找到P2P目标 ${targetInfo.target_ip} 对应的客户端`);
      }
    }
    this.updateP2PStatus(clientId, p2pTargets);
    // logger.debug(`客户端 ${clientId} P2P状态处理完成，有效目标数量: ${p2pTargets.length}`);
  }

  async handleDeviceListQuery(request) {
    const url = new URL(request.url);
    const token = url.searchParams.get("token");
    const queryIp = url.searchParams.get("ip");
    // logger.info(`[房间状态-开始] 查询Token: ${token}, 查询网关: ${queryIp}`);

    try {
      // 检查cookies中的认证信息
      const cookieHeader = request.headers.get("Cookie") || "";
      const cookies = this.parseCookies(cookieHeader);

      // 如果URL参数中有token和ip，或者cookies中有有效信息，则继续
      const authToken = token || cookies.auth_token;
      const authIp = queryIp || cookies.gateway_ip;

      if (!authToken || !authIp) {
        // 返回登录页面HTML
        return new Response(this.getLoginModalHTML(), {
          status: 200,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }
      // 解析查询IP为数字格式
      const queryIpNum = this.packetHandler.parseIpv4(authIp);
      if (queryIpNum === 0) {
        return new Response(this.getLoginModalHTML("无效的网关IP地址！"), {
          status: 400,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }
      // 检查缓存是否存在
      if (!this.packetHandler.cache || !this.packetHandler.cache.networks) {
        logger.error(`[房间状态-错误] 缓存未初始化`);
        return new Response(
          this.getLoginModalHTML("服务内部错误或缓存未初始化！"),
          {
            status: 500,
            headers: { "Content-Type": "text/html; charset=utf-8" },
          }
        );
      }

      // 修复：在正确的缓存位置查找 token
      const networkInfo = this.packetHandler.cache.networks.get(authToken);
      // logger.info(`[房间状态-查找] 查找token ${token}: ${networkInfo ? "已找到" : "未找到"}`);

      if (!networkInfo) {
        return new Response(this.getLoginModalHTML("您查询的Token不存在！"), {
          status: 404,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }

      // 对比网关IP和查询IP的前三位
      const gatewayIp = networkInfo.gateway;
      const gatewayPrefix = (gatewayIp >> 8) & 0xffffff; // 去掉最后8位
      const queryPrefix = (queryIpNum >> 8) & 0xffffff;

      if (gatewayPrefix !== queryPrefix) {
        return new Response(
          this.getLoginModalHTML("参数错误，请验证后再试！"),
          {
            status: 403,
            headers: { "Content-Type": "text/html; charset=utf-8" },
          }
        );
      }

      // 构建设备列表（类似vnt客户端list格式）
      const deviceList = [];

      // 添加网关信息
      deviceList.push({
        名称: this.env.GATEWAY_NAME || "服务器",
        虚拟IP: this.packetHandler.formatIp(gatewayIp),
        状态: "在线",
        类型: "网关",
        版本: "网关",
        NAT类型: "-",
        设备ID: "-",
        加密: "-",
        上传: "-",
        下载: "-",
        上线时间: this.getStartTimeBeijing(),
        isGateway: true,
      });

      // 添加客户端信息
      let onlineCount = 0;
      let offlineCount = 0;

      for (const [virtualIp, client] of networkInfo.clients) {
        if (virtualIp !== 0) {
          if (client.online) {
            onlineCount++;
          } else {
            offlineCount++;
          }

          // 获取客户端状态信息
          const statusInfo = client.client_status;
          let upStream = "-";
          let downStream = "-";
          let natType = "-";

          if (statusInfo) {
            upStream = this.formatBytes(statusInfo.up_stream);
            downStream = this.formatBytes(statusInfo.down_stream);
            // NAT 类型转换
            if (
              statusInfo.nat_type === "Symmetric" ||
              statusInfo.nat_type === 0
            ) {
              natType = "对称型";
            } else if (
              statusInfo.nat_type === "Cone" ||
              statusInfo.nat_type === 1
            ) {
              natType = "锥型";
            } else {
              natType = "未知";
            }
          }

          deviceList.push({
            名称: client.name,
            虚拟IP: this.packetHandler.formatIp(virtualIp),
            状态: client.online ? "在线" : "离线",
            NAT类型: natType,
            设备ID: client.device_id,
            版本: client.version,
            加密: client.client_secret ? "是" : "否",
            上传: upStream,
            下载: downStream,
            上线时间: this.formatDateTime(client.last_join_time),
          });
        }
      }

      // 返回带有设备数据的HTML页面
      return new Response(
        this.getDeviceListHTML(deviceList, onlineCount, offlineCount),
        {
          status: 200,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        }
      );
    } catch (error) {
      return new Response(
        this.getLoginModalHTML("查询失败: " + error.message),
        {
          status: 500,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        }
      );
    }
  }

  // 格式化字节数为人类可读格式
  formatBytes(bytes) {
    if (!bytes || bytes === 0) {
      return "无";
    }

    const gigabytes = Math.floor(bytes / (1024 * 1024 * 1024));
    let remainingBytes = bytes % (1024 * 1024 * 1024);
    const megabytes = Math.floor(remainingBytes / (1024 * 1024));
    remainingBytes = remainingBytes % (1024 * 1024);
    const kilobytes = Math.floor(remainingBytes / 1024);
    remainingBytes = remainingBytes % 1024;

    let result = "";
    if (gigabytes > 0) result += gigabytes + " GB ";
    if (megabytes > 0) result += megabytes + " MB ";
    if (kilobytes > 0) result += kilobytes + " KB ";
    if (remainingBytes > 0) result += remainingBytes + " bytes";

    return result.trim();
  }

  formatDateTime(timestamp) {
    if (!timestamp) return "-";

    // 如果是 Date 对象，转换为时间戳
    const time = timestamp instanceof Date ? timestamp.getTime() : timestamp;

    // 转换为北京时间（UTC+8）
    const beijingTime = new Date(time + 8 * 60 * 60 * 1000);

    const year = beijingTime.getFullYear();
    const month = String(beijingTime.getMonth() + 1).padStart(2, "0");
    const day = String(beijingTime.getDate()).padStart(2, "0");
    const hours = String(beijingTime.getHours()).padStart(2, "0");
    const minutes = String(beijingTime.getMinutes()).padStart(2, "0");
    const seconds = String(beijingTime.getSeconds()).padStart(2, "0");

    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
  }

  // 解析cookies
  parseCookies(cookieHeader) {
    const cookies = {};
    if (cookieHeader) {
      cookieHeader.split(";").forEach((cookie) => {
        const [name, value] = cookie.trim().split("=");
        if (name && value) {
          cookies[name] = decodeURIComponent(value);
        }
      });
    }
    return cookies;
  }

  // 获取登录模态框HTML
  getLoginModalHTML(errorMessage = null) {
    return `<!DOCTYPE html>    
<html lang="zh-CN">    
<head>    
    <meta charset="UTF-8">    
    <meta name="viewport" content="width=device-width, initial-scale=1.0">    
    <title>客户端列表 - VNT</title>    
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>    
    <style>    
        * {    
            margin: 0;    
            padding: 0;    
            box-sizing: border-box;    
        }    
            
        body {    
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;    
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);    
            min-height: 100vh;    
            animation: gradientShift 10s ease infinite;    
            display: flex;    
            align-items: center;    
            justify-content: center;    
        }    
            
        @keyframes gradientShift {    
            0%, 100% { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }    
            50% { background: linear-gradient(135deg, #764ba2 0%, #667eea 100%); }    
        }    
            
        .modal {    
    		display: block;    
    		position: relative;    
    		background: rgba(255, 255, 255, 0.96);    
    		width: calc(100vw - 48px);   
    		max-width: 600px;     
    		min-width: 320px;   
    		padding: 36px 32px;    
    		border-radius: 16px;    
    		box-shadow: 0 20px 60px rgba(0, 0, 0, 0.28);    
    		backdrop-filter: blur(10px);    
    		animation: modalSlideIn 0.3s ease;    
	}   
            
        @keyframes modalSlideIn {    
            from {    
                opacity: 0;    
                transform: translateY(-50px);    
            }    
            to {    
                opacity: 1;    
                transform: translateY(0);    
            }    
        }    
            
        .modal h2 {    
            margin-bottom: 30px;    
            text-align: center;    
            background: linear-gradient(45deg, #667eea, #764ba2);    
            -webkit-background-clip: text;    
            -webkit-text-fill-color: transparent;    
            font-size: 24px;    
        }    
            
        .form-group {    
            margin-bottom: 20px;    
        }    
            
        .form-group label {    
            display: block;    
            margin-bottom: 8px;    
            font-weight: 500;    
            color: #333;    
        }    
            
        .form-group input {    
            width: 100%;    
            padding: 12px;    
            border: 2px solid #e0e0e0;    
            border-radius: 8px;    
            font-size: 14px;    
            transition: border-color 0.3s ease;    
        }    
            
        .form-group input:focus {    
            outline: none;    
            border-color: #667eea;    
        }    
            
        .submit-btn {    
    		display: block;    
    		margin: 0 auto;    
    		padding: 12px 40px;   
    		background: linear-gradient(45deg, #667eea, #764ba2);    
    		color: white;    
    		border: none;    
    		border-radius: 8px;    
    		font-size: 16px;    
    		font-weight: 500;    
    		cursor: pointer;    
    		transition: all 0.3s ease;    
	}    
            
        .submit-btn:hover {    
            transform: translateY(-2px);    
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);    
        }    
            
        /* 错误提示样式 */  
        .error-message {    
            background: #ffebee;    
            color: #c62828;    
            padding: 12px;    
            border-radius: 8px;    
            margin-bottom: 20px;    
            border: 1px solid #ef5350;    
            font-size: 14px;    
            animation: errorShake 0.5s ease;    
        }    
            
        @keyframes errorShake {    
            0%, 100% { transform: translateX(0); }    
            25% { transform: translateX(-5px); }    
            75% { transform: translateX(5px); }    
        }    
    </style>    
</head>    
<body>    
    <div id="app">    
        <div class="modal">    
            <h2>查询验证</h2>    
            <!-- 错误提示区域 -->  
            <div v-if="showError" class="error-message">{{ errorMessage }}</div>    
            <div class="form-group">    
                <label>组网Token：</label>    
                <input v-model="loginForm.token" placeholder="请输入组网token" @keyup.enter="login" />    
            </div>    
            <div class="form-group">    
                <label>网关IP：</label>    
                <input v-model="loginForm.gatewayIp" placeholder="请输入对应的网关IP" @keyup.enter="login" />    
            </div>    
            <button class="submit-btn" @click="login">确认查询</button>    
        </div>    
    </div>    
    <script>    
        const { createApp } = Vue;    
        createApp({    
            data() {    
                return {    
                    loginForm: {    
                        token: '',    
                        gatewayIp: ''    
                    },    
                    showError: ${errorMessage ? "true" : "false"},    
                    errorMessage: ${
                      errorMessage ? `'${errorMessage}'` : "''"
                    }    
                };    
            },    
            methods: {    
                login() {    
                    if (!this.loginForm.token || !this.loginForm.gatewayIp) {    
                        this.showError = true;    
                        this.errorMessage = '请填写完整的查询信息！';    
                        return;    
                    }    
                        
                    // 设置1小时有效期的cookies    
                    const expires = new Date();    
                    expires.setTime(expires.getTime() + (1 * 60 * 60 * 1000));    
                        
                    document.cookie = \`auth_token=\${this.loginForm.token}; expires=\${expires.toUTCString()}; path=/\`;    
                    document.cookie = \`gateway_ip=\${this.loginForm.gatewayIp}; expires=\${expires.toUTCString()}; path=/\`;    
                        
                    // 清除URL参数并重新加载页面    
                    window.location.href = window.location.origin + '/room';    
                }    
            }    
        }).mount('#app');    
    </script>    
</body>    
</html>`;
  }

  // 获取设备列表HTML
  getDeviceListHTML(deviceList, onlineCount, offlineCount) {
    return `<!DOCTYPE html>  
<html lang="zh-CN">  
<head>  
    <meta charset="UTF-8">  
    <meta name="viewport" content="width=device-width, initial-scale=1.0">  
    <title>客户端列表 - VNT</title>  
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>  
    <style>  
        * {  
            margin: 0;  
            padding: 0;  
            box-sizing: border-box;  
        }  
          
        body {  
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;  
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);  
            min-height: 100vh;  
            animation: gradientShift 10s ease infinite;  
        }  
          
        @keyframes gradientShift {  
            0%, 100% { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }  
            50% { background: linear-gradient(135deg, #764ba2 0%, #667eea 100%); }  
        }  
          
        .container {  
            max-width: 1200px;  
            margin: 0 auto;  
            padding: 20px;  
        }  
          
        .header {  
            background: rgba(255, 255, 255, 0.95);  
            border-radius: 15px;  
            padding: 20px;  
            margin-bottom: 20px;  
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);  
            backdrop-filter: blur(10px);  
            display: flex;  
            justify-content: space-between;  
            align-items: center;  
        }  
          
        .title {  
            font-size: 24px;  
            font-weight: bold;  
            background: linear-gradient(45deg, #667eea, #764ba2);  
            -webkit-background-clip: text;  
            -webkit-text-fill-color: transparent;  
        }  
          
        .logout-btn {  
            background: linear-gradient(45deg, #f44336, #e91e63);  
            color: white;  
            border: none;  
            padding: 10px 20px;  
            border-radius: 25px;  
            cursor: pointer;  
            transition: all 0.3s ease;  
            font-weight: 500;  
        }  
          
        .logout-btn:hover {  
            transform: translateY(-2px);  
            box-shadow: 0 5px 15px rgba(244, 67, 54, 0.3);  
        }  
          
        .main-content {  
            background: rgba(255, 255, 255, 0.95);  
            border-radius: 15px;  
            padding: 20px;  
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);  
            backdrop-filter: blur(10px);  
        }  
          
        .filters {  
            display: flex;  
            gap: 10px;  
            margin-bottom: 20px;  
            flex-wrap: wrap;  
        }  
          
        .filter-btn {  
            padding: 8px 16px;  
            border: 2px solid #667eea;  
            background: white;  
            color: #667eea;  
            border-radius: 20px;  
            cursor: pointer;  
            transition: all 0.3s ease;  
            font-weight: 500;  
        }  
          
        .filter-btn.active {  
            background: linear-gradient(45deg, #667eea, #764ba2);  
            color: white;  
        }  
          
        .filter-btn:hover {  
            transform: translateY(-1px);  
        }  
          
        .table-container {  
            overflow-x: auto;  
            border-radius: 10px;  
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);  
        }  
          
        table {  
            width: 100%;  
            border-collapse: collapse; 
            border-spacing: 0; 
            background: white;  
        }  
          
        th, td {  
            padding: 12px;  
            text-align: center;  
            border-bottom: 1px solid #f0f0f0; 
            border-right: 1px solid #e8e8e8; 
        }  
          
        th {  
            background: linear-gradient(45deg, #1761ea, #066ce9);  
            color: white;  
            font-weight: 600;  
            position: sticky;  
            top: 0;  
            z-index: 10;
            border-right: 1px solid rgba(255, 255, 255, 0.3);  
        }  
  
        /* 每行不同背景色 */  
	tr:nth-child(even) td { background: #c3c9ed; } /* 偶数行 - 浅蓝色 */  
	tr:nth-child(odd) td { background: #b6aaf1; } /* 奇数行 - 浅紫色 */  
  
	/* 服务器行特殊颜色 */  
	tr[data-type="gateway"] td {   
    		background: #eacfdd;   
    		font-weight: 600;  
	}  
  
	/* 悬停效果 */  
	tr:hover td {  
    		background: #ee6fdf !important;  
    		transition: background 0.2s ease;  
	} 
          
        .status-badge {  
            padding: 4px 12px;  
            border-radius: 15px;  
            font-size: 12px;  
            font-weight: 500;  
            display: inline-block;  
        }  
          
        .status-online {  
            background: linear-gradient(45deg, #4caf50, #45a049);  
            color: white;  
        }  
          
        .status-offline {  
            background: linear-gradient(45deg, #f44336, #e91e63);  
            color: white;  
        }  
          
        .pagination {  
            display: flex;  
            justify-content: space-between;  
            align-items: center;  
            margin-top: 20px;  
            flex-wrap: wrap;  
            gap: 15px;  
        }  
          
        .page-controls {  
            display: flex;  
            gap: 10px;  
            align-items: center;  
        }  
          
        .page-btn {  
            padding: 8px 16px;  
            border: 1px solid #667eea;  
            background: white;  
            color: #667eea;  
            border-radius: 5px;  
            cursor: pointer;  
            transition: all 0.3s ease;  
        }
        .page-btn:hover:not(:disabled) {  
            background: #667eea;  
            color: white;  
        }  
          
        .page-btn:disabled {  
            opacity: 0.5;  
            cursor: not-allowed;  
        }  
          
        .page-size-selector {  
            display: flex;  
            align-items: center;  
            gap: 10px;  
        }  
          
        .page-size-selector select {  
            padding: 8px;  
            border: 1px solid #667eea;  
            border-radius: 5px;  
            background: white;  
        }  
        
        /* 添加统计信息样式 */  
        .stats-container {  
            display: flex;  
            gap: 20px;  
            margin-bottom: 20px;  
            flex-wrap: wrap;  
            justify-content: center;  
        }  
          
        .stat-card {  
    		background: linear-gradient(135deg, rgba(255, 255, 255, 0.9), rgba(255, 255, 255, 0.7));  
    		padding: 15px 25px;  
    		border-radius: 12px;  
    		box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);  
    		backdrop-filter: blur(10px);  
    		text-align: center;  
    		min-width: 120px;  
    		transition: all 0.3s ease;  
    		cursor: pointer;  
    		border: 2px solid transparent;  
	}
          
        .stat-card:hover {  
            transform: translateY(-2px);  
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);  
        }  
        .stat-card.active {  
    		background: linear-gradient(135deg, #667eea, #764ba2);  
    		box-shadow: 0 8px 25px rgba(235, 242, 40, 0.815); 
		}  
  
	.stat-card.active .stat-value {  
    		background: linear-gradient(135deg, #a5f12b, #cae91a); 
    		-webkit-background-clip: text;  
    		-webkit-text-fill-color: transparent;  
	}  
  
	.stat-card.active .stat-label {  
    		color: #ffffff;  
	}
          
        .stat-value {  
            font-size: 24px;  
            font-weight: bold;  
            background: linear-gradient(45deg, #667eea, #764ba2);  
            -webkit-background-clip: text;  
            -webkit-text-fill-color: transparent;  
            margin-bottom: 5px;  
        }  
          
        .stat-label {  
            font-size: 14px;  
            color: #666;  
            font-weight: 500;  
        }  
          
        .stat-online {  
            border-left: 4px solid #4caf50;  
        }  
          
        .stat-offline {  
            border-left: 4px solid #f44336;  
        }  
          
        .stat-total {  
            border-left: 4px solid #667eea;  
        }
        
        .sortable {    
            cursor: pointer;    
            user-select: none;   
        }    
            
        .sortable:hover {    
            background-color: rgba(102, 126, 234, 0.1);    
        }    
            
        .sort-indicator {    
            display: inline-block;
            margin-left: 2px; 
            vertical-align: middle;   
            font-size: inherit;
            font-weight: bold;  
            transition: all 0.2s ease;
            position: relative;
            top: -4px;  
        }
        
        .sort-indicator.active {    
    		color: #fff;    
    		text-shadow: 0 0 3px rgba(255, 255, 255, 0.5);    
	}    
  
	.sort-indicator .hint {    
    		color: rgba(255, 255, 255, 0.4);    
    		font-size: inherit;    
	}    
  
	.sortable:hover .sort-indicator .hint {    
    		color: rgba(255, 255, 255, 0.7);    
	}    
  
	.sortable:hover .sort-indicator.active {    
    		transform: scale(1.2); 
    		top: -4px;   
	}
          
        @media (max-width: 768px) {  
            .container {  
                padding: 10px;  
            }  
              
            .header {  
                flex-direction: column;  
                gap: 15px;  
                text-align: center;  
            }  
              
            .filters {  
                justify-content: center;  
            }  
              
            .pagination {  
                flex-direction: column;  
                text-align: center;  
            }  
              
            .table-container {  
                font-size: 14px;  
            }  
            
            .stats-container {  
                gap: 10px;  
            }  
              
            .stat-card {  
                padding: 12px 20px;  
                min-width: 100px;  
            }  
              
            .stat-value {  
                font-size: 20px;  
            }  
              
            .stat-label {  
                font-size: 12px;  
            } 
              
            th, td {  
                padding: 8px 4px;  
            }  
        }  
    </style>  
</head>  
<body>  
    <div id="app">  
        <div class="container">  
            <div class="header">  
                <h1 class="title">客户端列表</h1>  
                <button class="logout-btn" @click="logout">退出</button>  
            </div>   
                
                <!-- 统计信息区域 -->  
                <div class="stats-container">  
        		<div class="stat-card stat-total"   
             			:class="{ active: currentFilter === 'all' }"  
             			@click="setFilter('all')">  
            		<div class="stat-value">{{ totalClients }}</div>  
            		<div class="stat-label">客户端总数</div>  
        	</div>  
        	<div class="stat-card stat-online"   
             		:class="{ active: currentFilter === 'online' }"  
             		@click="setFilter('online')">  
            		<div class="stat-value">{{ onlineClients }}</div>  
            		<div class="stat-label">在线客户端</div>  
        	</div>  
        	<div class="stat-card stat-offline"   
             		:class="{ active: currentFilter === 'offline' }"  
             		@click="setFilter('offline')">  
            		<div class="stat-value">{{ offlineClients }}</div>  
            		<div class="stat-label">离线客户端</div>  
        	</div>  
    	   </div>  
                  
                <div class="table-container">  
                    <table>  
                        <thead>  
                            <tr>  
                                <th @click="sortBy('虚拟IP')" class="sortable">    
            				虚拟IP  
            				<span class="sort-indicator" :class="{ active: sortKey === '虚拟IP' }">    
                				<span v-if="sortKey === '虚拟IP' && sortOrder === 'asc'">↑</span>    
                				<span v-else-if="sortKey === '虚拟IP' && sortOrder === 'desc'">↓</span>    
                				<span v-else class="hint">↕</span>    
            				</span>    
        			 </th>
                                <th>主机名</th>  
                                <th>版本</th>  
                                <th>状态</th>  
                                <th>NAT类型</th>  
                                <th>设备ID</th>  
                                <th>加密</th>  
                                <th>上传流量</th>  
                                <th>下载流量</th>
                                <th @click="sortBy('上线时间')" class="sortable">    
            				上线时间  
            				<span class="sort-indicator" :class="{ active: sortKey === '上线时间' }">    
                				<span v-if="sortKey === '上线时间' && sortOrder === 'asc'">↑</span>    
                				<span v-else-if="sortKey === '上线时间' && sortOrder === 'desc'">↓</span>    
                				<span v-else class="hint">↕</span>    
            				</span>    
        			 </th>
                            </tr>  
                        </thead>  
                        <tbody>  
                            <tr v-for="device in paginatedDevices" :key="device.虚拟IP" :data-type="device.类型 === '网关' ? 'gateway' : 'client'"> 
                                <td>{{ device.虚拟IP }}</td>  
                                <td>{{ device.名称 }}</td>  
                                <td>{{ device.版本 }}</td>  
                                <td>  
                                    <span :class="['status-badge', device.状态 === '在线' ? 'status-online' : 'status-offline']">  
                                        {{ device.状态 }}  
                                    </span>  
                                </td>  
                                <td>{{ device.NAT类型 || '-' }}</td>  
                                <td>{{ device.设备ID }}</td>  
                                <td>{{ device.加密 }}</td>  
                                <td>{{ device.上传 }}</td>  
                                <td>{{ device.下载 }}</td> 
                                <td>{{ device.上线时间 }}</td> 
                            </tr>  
                        </tbody>  
                    </table>  
                </div>  
                  
                <div class="pagination">  
                    <div class="page-controls">  
                        <button class="page-btn" @click="prevPage" :disabled="currentPage === 1">上一页</button>  
                        <span>第 {{ currentPage }} 页，共 {{ totalPages }} 页</span>  
                        <button class="page-btn" @click="nextPage" :disabled="currentPage === totalPages">下一页</button>  
                    </div>  
                      
                    <div class="page-size-selector">  
                        <label>每页显示：</label>  
                        <select v-model="pageSize" @change="currentPage = 1">  
                            <option value="5">5</option>  
                            <option value="10">10</option>  
                            <option value="15">15</option>  
                            <option value="20">20</option>  
                            <option value="50">50</option>  
                            <option value="100">100</option>  
                            <option value="all">全部</option>  
                        </select>  
                    </div>  
                </div>  
            </div>  
        </div>  
    </div>  
  
    <script>  
        const { createApp } = Vue;  
          
        createApp({  
            data() {  
                return {  
                    devices: ${JSON.stringify(deviceList)},  
                    currentFilter: 'all',  
                    filters: [  
                        { label: '全部', value: 'all' },  
                        { label: '在线', value: 'online' },  
                        { label: '离线', value: 'offline' }  
                    ],  
                    currentPage: 1,  
                    pageSize: 10,
                    sortKey: '',
                    sortOrder: 'asc',
                    // 统计数据  
                    totalClients: ${deviceList.length - 1}, // 减去服务器  
                    onlineClients: ${onlineCount},
                    offlineClients: ${offlineCount}
                };  
            },  
            computed: {
            	// 排序后的设备列表  
                sortedDevices() {
                    // 先分离网关和客户端  
                    const gateway = this.devices.find(d => d.类型 === '网关');
                    const clients = this.devices.filter(d => d.类型 !== '网关');
                      
                    // 如果没有设置排序键，返回原始顺序
                    if (!this.sortKey) {
                        return gateway ? [gateway, ...clients] : clients;
                    }
                     
                    // 对客户端进行排序  
                    const sortedClients = [...clients].sort((a, b) => {
                        let aVal = a[this.sortKey];
                        let bVal = b[this.sortKey];
                          
                        // 特殊处理IP地址排序  
                        if (this.sortKey === '虚拟IP') {
                            aVal = this.ipToNumber(aVal);
                            bVal = this.ipToNumber(bVal);
                        }
                          
                        // 特殊处理时间排序  
                        if (this.sortKey === '上线时间') {
                            aVal = new Date(aVal).getTime();
                            bVal = new Date(bVal).getTime();
                        }
                          
                        if (aVal < bVal) return this.sortOrder === 'asc' ? -1 : 1;
                        if (aVal > bVal) return this.sortOrder === 'asc' ? 1 : -1;
                        return 0;    
                    });
                      
                    // 网关始终排在第一  
                    return gateway ? [gateway, ...sortedClients] : sortedClients;
                },
                filteredDevices() {
                    let devices = this.sortedDevices;
                    if (this.currentFilter === 'all') return devices;
                    if (this.currentFilter === 'online') return devices.filter(d => d.状态 === '在线');
                    if (this.currentFilter === 'offline') return devices.filter(d => d.状态 === '离线');
                    return devices;
                },  
                totalPages() {  
                    if (this.pageSize === 'all') return 1;  
                    return Math.ceil(this.filteredDevices.length / this.pageSize);  
                },  
                paginatedDevices() {  
                    if (this.pageSize === 'all') return this.filteredDevices;  
                    const start = (this.currentPage - 1) * this.pageSize;  
                    const end = start + parseInt(this.pageSize);  
                    return this.filteredDevices.slice(start, end);  
                }  
            },  
            methods: {
            	// 排序方法
                sortBy(key) {
                    if (this.sortKey === key) {
                        // 如果点击的是当前排序列，切换排序顺序
                        this.sortOrder = this.sortOrder === 'asc' ? 'desc' : 'asc';
                    } else {
                        // 如果点击的是新列，设置为升序
                        this.sortKey = key;
                        this.sortOrder = 'asc';
                    }
                    this.currentPage = 1; // 重置到第一页
                },
                // IP地址转换为数字用于排序  
                ipToNumber(ip) {
                    if (!ip) return 0;
                    const parts = ip.split('.');
                    return parts.reduce((acc, part, index) => {
                        return acc + (parseInt(part) || 0) * Math.pow(256, 3 - index);
                    }, 0);
                },
                setFilter(filter) {  
                    this.currentFilter = filter;  
                    this.currentPage = 1;  
                },  
                prevPage() {  
                    if (this.currentPage > 1) this.currentPage--;  
                },  
                nextPage() {  
                    if (this.currentPage < this.totalPages) this.currentPage++;  
                },  
                logout() {  
                    document.cookie = 'auth_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';  
                    document.cookie = 'gateway_ip=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';  
                    window.location.href = window.location.origin + '/room';  
                }  
            }  
        }).mount('#app');  
    </script>  
</body>  
</html>`;
  }

  // 获取测试模态框HTML
  getTestModalHTML(statusData) {
    return `<!DOCTYPE html>  
<html lang="zh-CN">  
<head>  
    <meta charset="UTF-8">  
    <meta name="viewport" content="width=device-width, initial-scale=1.0">  
    <title>服务状态 - VNT</title>  
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>  
    <style>  
        * {  
            margin: 0;  
            padding: 0;  
            box-sizing: border-box;  
        }  
          
        body {  
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;  
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);  
            min-height: 100vh;  
            animation: gradientShift 10s ease infinite;  
            display: flex;  
            align-items: center;  
            justify-content: center;  
        }  
          
        @keyframes gradientShift {  
            0%, 100% { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }  
            50% { background: linear-gradient(135deg, #764ba2 0%, #667eea 100%); }  
        }  
          
        .modal {  
            display: block;  
            position: relative;  
            background: rgba(255, 255, 255, 0.96);  
            width: calc(100vw - 48px);  
            max-width: 600px;  
            min-width: 320px;  
            padding: 36px 32px;  
            border-radius: 16px;  
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.28);  
            backdrop-filter: blur(10px);  
            animation: modalSlideIn 0.3s ease;  
        }  
          
        @keyframes modalSlideIn {  
            from {  
                opacity: 0;  
                transform: translateY(-50px);  
            }  
            to {  
                opacity: 1;  
                transform: translateY(0);  
            }  
        }  
          
        .modal h2 {  
            margin-bottom: 30px;  
            text-align: center;  
            background: linear-gradient(45deg, #667eea, #764ba2);  
            -webkit-background-clip: text;  
            -webkit-text-fill-color: transparent;  
            font-size: 24px;  
        }  
          
        .status-item {  
            display: flex;  
            justify-content: space-between;  
            align-items: center;  
            padding: 12px 0;  
            border-bottom: 1px solid #e0e0e0;  
        }  
          
        .status-item:last-child {  
            border-bottom: none;  
        }  
          
        .status-label {  
            font-weight: 500;  
            color: #333;  
        }  
          
        .status-value {  
            color: #666;  
            font-weight: 400;  
        }  
          
        .status-value.online {  
            color: #4caf50;  
            font-weight: 500;  
        }  
          
        .latency-display {  
            text-align: center;  
            margin: 20px 0;  
            padding: 20px;  
            border-radius: 12px;  
            background: #f5f5f5;  
            transition: all 0.3s ease;  
        }  
          
        .latency-value {  
            font-size: 36px;  
            font-weight: bold;  
            margin-bottom: 8px;  
        }  
          
        .latency-label {  
            font-size: 14px;  
            color: #666;  
        }  
          
        .latency-excellent {  
            background: linear-gradient(135deg, #4caf50, #45a049);  
            color: white;  
        }  
          
        .latency-good {  
            background: linear-gradient(135deg, #8bc34a, #7cb342);  
            color: white;  
        }  
          
        .latency-fair {  
            background: linear-gradient(135deg, #ff9800, #f57c00);  
            color: white;  
        }  
          
        .latency-poor {  
            background: linear-gradient(135deg, #f44336, #d32f2f);  
            color: white;  
        }  
          
        .test-btn {  
            display: block;  
            margin: 20px auto 0;  
            padding: 12px 40px;  
            background: linear-gradient(45deg, #667eea, #764ba2);  
            color: white;  
            border: none;  
            border-radius: 8px;  
            font-size: 16px;  
            font-weight: 500;  
            cursor: pointer;  
            transition: all 0.3s ease;  
        }  
          
        .test-btn:hover {  
            transform: translateY(-2px);  
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);  
        }  
          
        .test-btn:disabled {  
            opacity: 0.6;  
            cursor: not-allowed;  
            transform: none;  
        }  
          
        .test-btn.stop {  
            background: linear-gradient(45deg, #f44336, #e91e63);  
        }  
          
        .test-btn.stop:hover {  
            box-shadow: 0 5px 15px rgba(244, 67, 54, 0.3);  
        }  
          
        .pulse {  
            animation: pulse 2s infinite;  
        }  
          
        @keyframes pulse {  
            0% { transform: scale(1); }  
            50% { transform: scale(1.05); }  
            100% { transform: scale(1); }  
        }  
          
        /* 桌面端样式 */  
        @media (min-width: 768px) {  
            .modal {  
                padding: 50px;  
                max-width: 700px;  
            }  
              
            .modal h2 {  
                font-size: 28px;  
                margin-bottom: 35px;  
            }  
        }  
          
        /* 移动端样式 */  
        @media (max-width: 767px) {  
            .modal {  
                padding: 30px 20px;  
                width: 95%;  
                max-width: none;  
            }  
              
            .modal h2 {  
                font-size: 22px;  
                margin-bottom: 25px;  
            }  
              
            .latency-value {  
                font-size: 28px;  
            }  
        }  
    </style>  
</head>  
<body>  
    <div id="app">  
        <div class="modal">  
            <h2>服务状态检测</h2>  
              
            <div class="status-item">  
                <span class="status-label">WebSocket服务：</span>  
                <span class="status-value online">{{ status.WebSocket服务 }}</span>  
            </div>  
              
            <div class="status-item">  
                <span class="status-label">启动时间：</span>  
                <span class="status-value">{{ status.启动时间 }}</span>  
            </div>  
              
            <div class="status-item">  
                <span class="status-label">已运行：</span>  
                <span class="status-value">{{ status.已运行 }}</span>  
            </div>  
              
            <div class="status-item">  
                <span class="status-label">支持协议：</span>  
                <span class="status-value">{{ status.支持协议 }}</span>  
            </div>  
              
            <div class="status-item">  
                <span class="status-label">服务状态：</span>  
                <span class="status-value online">{{ status.服务状态 }}</span>  
            </div>  
              
            <div class="status-item">  
                <span class="status-label">Token使用数：</span>  
                <span class="status-value">{{ status.Token使用数 }}</span>  
            </div>  
              
            <div class="status-item">  
                <span class="status-label">客户端在线数：</span>  
                <span class="status-value">{{ status.客户端在线数 }}</span>  
            </div>  
              
            <div class="latency-display" :class="latencyClass">  
                <div class="latency-value">{{ latency }}ms</div>  
                <div class="latency-label">{{ latencyText }}</div>  
            </div>  
              
            <button class="test-btn"   
                    :class="{ stop: autoDetecting }"   
                    @click="toggleAutoDetection"   
                    :disabled="testing">  
                {{ autoDetecting ? '停止自动检测延迟' : '开始自动检测延迟' }}  
            </button>  
        </div>  
    </div>  
      
    <script>  
        const { createApp } = Vue;  
        createApp({  
            data() {  
                return {  
                    status: ${JSON.stringify(statusData)},  
                    latency: 0,  
                    testing: false,  
                    autoDetecting: true,  
                    latencyClass: '',  
                    latencyText: '点击检测延迟',  
                    autoDetectInterval: null  
                };  
            },  
            mounted() {  
                this.testLatency();  
                this.startAutoDetection();  
            },  
            beforeUnmount() {  
                this.stopAutoDetection();  
            },  
            methods: {  
                async testLatency() {  
                    this.testing = true;  
                    const startTime = performance.now();  
                      
                    try {  
                        // 使用HEAD请求检测延迟  
                        const response = await fetch(window.location.href, {  
                            method: 'HEAD',  
                            cache: 'no-cache'  
                        });  
                          
                        const endTime = performance.now();  
                        this.latency = Math.round(endTime - startTime);  
                          
                        // 根据延迟设置颜色和文字  
                        if (this.latency < 50) {  
                            this.latencyClass = 'latency-excellent pulse';  
                            this.latencyText = '连接极佳';  
                        } else if (this.latency < 100) {  
                            this.latencyClass = 'latency-good';  
                            this.latencyText = '连接良好';  
                        } else if (this.latency < 200) {  
                            this.latencyClass = 'latency-fair';  
                            this.latencyText = '连接一般';  
                        } else {  
                            this.latencyClass = 'latency-poor';  
                            this.latencyText = '连接较差';  
                        }  
                    } catch (error) {  
                        this.latency = 999;  
                        this.latencyClass = 'latency-poor';  
                        this.latencyText = '检测失败';  
                    } finally {  
                        this.testing = false;  
                    }  
                },  
                  
                startAutoDetection() {  
                    if (this.autoDetectInterval) return;  
                      
                    this.autoDetecting = true;  
                    this.autoDetectInterval = setInterval(() => {  
                        if (!this.testing && this.autoDetecting) {  
                            this.testLatency();  
                        }  
                    }, 5000);  
                },  
                  
                stopAutoDetection() {  
                    if (this.autoDetectInterval) {  
                        clearInterval(this.autoDetectInterval);  
                        this.autoDetectInterval = null;  
                    }  
                    this.autoDetecting = false;  
                },  
                  
                toggleAutoDetection() {  
                    if (this.autoDetecting) {  
                        this.stopAutoDetection();  
                    } else {  
                        this.startAutoDetection();  
                    }  
                }  
            }  
        }).mount('#app');  
    </script>  
</body>  
</html>`;
  }

  // 处理日志端点
  async handleLogEndpoint(request) {
    const clientIp = this.getClientIp(request);
    const url = new URL(request.url);

    // 检查是否启用了日志密码
    if (!this.env.LOG_PASSWORD) {
      return new Response("Not Found", { status: 404 });
    }

    // 检查登录状态
    const cookieHeader = request.headers.get("Cookie") || "";
    const cookies = this.parseCookies(cookieHeader);

    if (cookies.log_auth === this.env.LOG_PASSWORD) {
      // 已登录，显示日志页面
      return await this.getLogViewerHTML();
    }

    // 检查是否被锁定
    const attempts = this.loginAttempts.get(clientIp) || {
      count: 0,
      lockUntil: 0,
    };
    if (attempts.lockUntil > Date.now()) {
      return new Response(this.getLogLoginHTML("密码错误次数过多，已锁定！"), {
        status: 429,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    // 处理登录提交
    if (request.method === "POST") {
      const formData = await request.formData();
      const password = formData.get("password");

      if (password === this.env.LOG_PASSWORD) {
        // 登录成功，设置cookie
        const expires = new Date();
        expires.setTime(expires.getTime() + 1 * 60 * 60 * 1000); // 1小时

        const response = new Response(this.getLogViewerHTML(), {
          status: 200,
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Set-Cookie": `log_auth=${
              this.env.LOG_PASSWORD
            }; expires=${expires.toUTCString()}; path=/`,
          },
        });

        // 清除失败计数
        this.loginAttempts.delete(clientIp);
        return response;
      } else {
        // 登录失败
        attempts.count++;
        if (attempts.count >= 3) {
          attempts.lockUntil = Date.now() + 60 * 60 * 1000; // 锁定1小时
        }
        this.loginAttempts.set(clientIp, attempts);

        return new Response(this.getLogLoginHTML("密码错误，请重试"), {
          status: 401,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }
    }

    // 显示登录页面
    return new Response(this.getLogLoginHTML(), {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  // 获取日志登录页面HTML
  getLogLoginHTML(errorMessage = null) {
    return `<!DOCTYPE html>      
<html lang="zh-CN">      
<head>      
    <meta charset="UTF-8">      
    <meta name="viewport" content="width=device-width, initial-scale=1.0">      
    <title>日志验证 - VNT</title>      
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>      
    <style>      
        * {      
            margin: 0;      
            padding: 0;      
            box-sizing: border-box;      
        }      
              
        body {      
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;      
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);      
            min-height: 100vh;      
            animation: gradientShift 10s ease infinite;      
            display: flex;      
            align-items: center;      
            justify-content: center;      
        }      
              
        @keyframes gradientShift {      
            0%, 100% { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }      
            50% { background: linear-gradient(135deg, #764ba2 0%, #667eea 100%); }      
        }      
              
        .modal {      
    		display: block;      
    		position: relative;      
    		background: rgba(255, 255, 255, 0.96);      
    		width: calc(100vw - 48px);     
    		max-width: 400px;       
    		min-width: 280px;     
    		padding: 36px 32px;      
    		border-radius: 16px;      
    		box-shadow: 0 20px 60px rgba(0, 0, 0, 0.28);      
    		backdrop-filter: blur(10px);      
    		animation: modalSlideIn 0.3s ease;      
	}     
              
        @keyframes modalSlideIn {      
            from {      
                opacity: 0;      
                transform: translateY(-50px);      
            }      
            to {      
                opacity: 1;      
                transform: translateY(0);      
            }      
        }      
              
        .modal h2 {      
            margin-bottom: 30px;      
            text-align: center;      
            background: linear-gradient(45deg, #667eea, #764ba2);      
            -webkit-background-clip: text;      
            -webkit-text-fill-color: transparent;      
            font-size: 24px;      
        }      
              
        .form-group {      
            margin-bottom: 20px;      
        }      
              
        .form-group label {      
            display: block;      
            margin-bottom: 8px;      
            font-weight: 500;      
            color: #333;      
        }      
              
        .form-group input {      
            width: 100%;      
            padding: 12px;      
            border: 2px solid #e0e0e0;      
            border-radius: 8px;      
            font-size: 14px;      
            transition: border-color 0.3s ease;      
        }      
              
        .form-group input:focus {      
            outline: none;      
            border-color: #667eea;      
        }      
              
        .submit-btn {      
    		display: block;      
    		margin: 0 auto;      
    		padding: 12px 40px;     
    		background: linear-gradient(45deg, #667eea, #764ba2);      
    		color: white;      
    		border: none;      
    		border-radius: 8px;      
    		font-size: 16px;      
    		font-weight: 500;      
    		cursor: pointer;      
    		transition: all 0.3s ease;      
	}      
              
        .submit-btn:hover {      
            transform: translateY(-2px);      
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);      
        }      
              
        /* 错误提示样式 */    
        .error-message {      
            background: #ffebee;      
            color: #c62828;      
            padding: 12px;      
            border-radius: 8px;      
            margin-bottom: 20px;      
            border: 1px solid #ef5350;      
            font-size: 14px;      
            animation: errorShake 0.5s ease;      
        }      
              
        @keyframes errorShake {      
            0%, 100% { transform: translateX(0); }      
            25% { transform: translateX(-5px); }      
            75% { transform: translateX(5px); }      
        }      
    </style>      
</head>      
<body>      
    <div id="app">      
        <div class="modal">      
            <h2>日志验证</h2>  
            <form method="POST" action="" @submit.prevent="login">    
            <!-- 错误提示区域 -->    
            <div v-if="showError" class="error-message">{{ errorMessage }}</div>      
            <div class="form-group">      
                <!-- <label>日志密码：</label> -->  
                <input v-model="loginForm.password" type="password" placeholder="请输入日志密码" @keyup.enter="login" />      
            </div>      
            <button class="submit-btn">确认登录</button> 
            </form>     
        </div>      
    </div>      
    <script>      
        const { createApp } = Vue;      
        createApp({      
            data() {      
                return {      
                    loginForm: {      
                        password: ''      
                    },      
                    showError: ${errorMessage ? "true" : "false"},      
                    errorMessage: ${
                      errorMessage ? JSON.stringify(errorMessage) : "''"
                    }      
                };      
            },      
            methods: {      
                login() {      
                    if (!this.loginForm.password) {      
                        this.showError = true;      
                        this.errorMessage = '请输入密码！';      
                        return;      
                    }      
                          
                    // 设置1小时有效期的cookies      
                    const expires = new Date();      
                    expires.setTime(expires.getTime() + (1 * 60 * 60 * 1000));      
                          
                    document.cookie = \`log_auth=\${this.loginForm.password}; expires=\${expires.toUTCString()}; path=/\`;      
                          
                    event.target.submit();     
                }      
            }      
        }).mount('#app');      
    </script>      
</body>      
</html>`;
  }

  // 获取日志查看页面HTML
  async getLogViewerHTML() {
    try {
      // 从storage获取日志
      const logData = (await this.state.storage.get("operationLogs")) || [];

      const htmlContent = `<!DOCTYPE html>  
<html lang="zh-CN">  
<head>  
    <meta charset="UTF-8">  
    <meta name="viewport" content="width=device-width, initial-scale=1.0">  
    <title>服务日志 - VNT</title>  
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>  
    <style>  
        * { margin: 0; padding: 0; box-sizing: border-box; }  
        body {  
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;  
            background: #f5f5f5;  
        }  
        .header {  
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);  
            color: white;  
            padding: 20px;  
            display: flex;  
            justify-content: space-between;  
            align-items: center;  
        }  
        .title {  
            font-size: 24px;  
            font-weight: bold;  
        }  
        .logout-btn, .clear-btn {  
            background: rgba(255, 255, 255, 0.2);  
            color: white;  
            border: 1px solid rgba(255, 255, 255, 0.3);  
            padding: 8px 16px;  
            border-radius: 20px;  
            cursor: pointer;  
            transition: all 0.3s ease;  
            margin-left: 10px;  
        }  
        .logout-btn:hover, .clear-btn:hover {  
            background: rgba(255, 255, 255, 0.3);  
        }  
        .clear-btn {  
            background: rgba(244, 67, 54, 0.8);  
            border-color: rgba(244, 67, 54, 0.9);  
        }  
        .clear-btn:hover {  
            background: rgba(244, 67, 54, 0.9);  
        }  
        .container {  
            max-width: 1200px;  
            margin: 0 auto;  
            padding: 20px;  
        }  
        .log-container {  
            background: white;  
            border-radius: 10px;  
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);  
            overflow: hidden;  
        }  
        .log-item {  
            padding: 12px 20px;  
            border-bottom: 1px solid #f0f0f0;  
            font-family: 'Consolas', 'Monaco', monospace;  
            font-size: 13px;  
            line-height: 1.5;  
        }  
        .log-item:last-child {  
            border-bottom: none;  
        }  
        .log-time {  
            color: #666;  
            margin-right: 15px;  
        }  
        .log-level {  
            padding: 2px 8px;  
            border-radius: 4px;  
            font-weight: bold;  
            margin-right: 15px;  
            min-width: 50px;  
            text-align: center;  
        }  
        .level-error {  
            background: #ffebee;  
            color: #c62828;  
        }  
        .level-warn {  
            background: #fff3e0;  
            color: #ef6c00;  
        }  
        .level-info {  
            background: #e3f2fd;  
            color: #1565c0;  
        }  
        .level-debug {  
            background: #f3e5f5;  
            color: #7b1fa2;  
        }  
        .log-message {  
            color: #333;  
        }  
        .empty-logs {  
            text-align: center;  
            padding: 60px 20px;  
            color: #999;  
        }
        /* 成功提示样式 */  
	.success-message {  
    		background: #e8f5e8;  
    		color: #2e7d32;  
    		padding: 12px;  
    		border-radius: 8px;  
    		margin-bottom: 20px;  
    		border: 1px solid #4caf50;  
    		font-size: 14px;  
    		animation: successSlideIn 0.5s ease;  
	}  
  
	@keyframes successSlideIn {  
    		from {  
        		opacity: 0;  
        		transform: translateY(-20px);  
    		}  
    		to {  
        		opacity: 1;  
        		transform: translateY(0);  
    		}  
	}
	/* 错误提示样式 */  
	.error-message {  
    		background: #ffebee;  
    		color: #c62828;  
    		padding: 12px;  
    		border-radius: 8px;  
    		margin-bottom: 20px;  
    		border: 1px solid #ef5350;  
    		font-size: 14px;  
    		animation: errorShake 0.5s ease;  
	}  
  
	@keyframes errorShake {  
    		0%, 100% { transform: translateX(0); }  
    		25% { transform: translateX(-5px); }  
    		75% { transform: translateX(5px); }  
	}
	.back-to-top {
    		position: fixed;
    		bottom: 20px;
    		right: 20px;
    		width: 50px;
    		height: 50px;
    		border-radius: 50%;
    		background: linear-gradient(135deg, #667eea, #764ba2);
    		color: white;
    		font-size: 24px;
    		font-weight: bold;
    		text-align: center;
    		cursor: pointer;
    		box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    		transition: all 0.3s ease;
    		z-index: 9999;
    		justify-content: center;
    		align-items: center;
    		opacity: 0;
    		pointer-events: none;
	}
	.back-to-top.show {
    		opacity: 1;
    		pointer-events: auto;
	}
	.back-to-top:hover {
    		transform: translateY(-2px);
    		box-shadow: 0 4px 15px rgba(0,0,0,0.3);
	}
    </style>  
</head>  
<body>  
    <div id="app">  
        <div class="header">  
            <div class="title">服务运行日志</div>  
            <div>  
                <button class="clear-btn" @click="clearLogs">清空日志</button>  
                <button class="logout-btn" @click="logout">退出</button>  
            </div>  
        </div>  
        <div class="container">
        	<!-- 提示消息区域 -->  
    		<div v-if="showNotification"   
         		:class="notificationType === 'success' ? 'success-message' : 'error-message'">  
        		{{ notificationMessage }}  
    		</div>
            <div class="log-container">  
                <div v-if="logs.length === 0" class="empty-logs">  
                    暂无日志记录  
                </div>  
                <div v-for="log in logs" :key="log.timestamp" class="log-item" ref="logItems">  
                    <span class="log-time">{{ formatTime(log.timestamp) }}</span>  
                    <span :class="'log-level level-' + log.level">{{ log.level.toUpperCase() }}</span>  
                    <span class="log-message">{{ log.message }}</span>  
                </div>  
            </div>  
        </div>
    <button class="back-to-top" @click="scrollToTop" :class="{ show: showBackToTop }">🔝</button>
    </div>
    <script>  
        const { createApp } = Vue;  
        createApp({  
            data() {  
                return {  
                    logs: ${JSON.stringify(logData)},
                    showBackToTop: false,
                    showNotification: false,  
                    notificationType: '',  
                    notificationMessage: ''
                };  
            },  
            mounted() {
            	window.addEventListener('scroll', this.handleScroll);
                // 自动滚动到底部  
                this.$nextTick(() => {  
                    if (this.$refs.logItems && this.$refs.logItems.length > 0) {  
                        const lastItem = this.$refs.logItems[this.$refs.logItems.length - 1];  
                        lastItem.scrollIntoView({ behavior: 'smooth' });  
                    }  
                });  
            },
            beforeUnmount() {  
    		window.removeEventListener('scroll', this.handleScroll);  
	    },  
            methods: {
            	handleScroll() {  
        		// 当滚动超过200px时显示按钮  
        		this.showBackToTop = window.scrollY > 200;  
    	 	},  
    		scrollToTop() {  
        		window.scrollTo({  
            			top: 0,  
            			behavior: 'smooth'  
        		});  
    		},
                formatTime(timestamp) {  
                    const date = new Date(timestamp);  
                    return date.toLocaleString('zh-CN', {  
                        year: 'numeric',  
                        month: '2-digit',  
                        day: '2-digit',  
                        hour: '2-digit',  
                        minute: '2-digit',  
                        second: '2-digit'  
                    });  
                },  
                logout() {  
                    document.cookie = 'log_auth=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';  
                    window.location.reload();  
                },  
                async clearLogs() {
                	if (!confirm('确定要清空所有日志吗？此操作不可恢复！')) {  
        			return;  
    			}
    			try {  
        			const response = await fetch(window.location.href + '/clear', {  
            			method: 'POST',  
            			headers: {  
                			'Content-Type': 'application/json'  
            			}  
        		});  
          
        		const result = await response.json();  
          
        		if (response.ok && result.status === 'ok') {  
            			this.logs = [];  
            			this.showNotification = true;  
            			this.notificationType = 'success';  
            			this.notificationMessage = '日志已成功清空';  
        		} else {  
            			this.showNotification = true;  
            			this.notificationType = 'error';  
            			this.notificationMessage = result.error || result.message || '清空日志失败';  
        		}  
          
        		// 4秒后自动隐藏提示  
        		setTimeout(() => {  
            			this.showNotification = false;  
       		 }, 4000);  
          
    			} catch (error) {  
        			this.showNotification = true;  
        			this.notificationType = 'error';  
        			this.notificationMessage = '网络错误，请稍后重试';  
          
        			setTimeout(() => {  
            				this.showNotification = false;  
        			}, 3000);  
    			}  
		} 
            }  
        }).mount('#app');  
    </script>  
</body>  
</html>`;
      return new Response(htmlContent, {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    } catch (error) {
      return new Response(
        `<html><body><h1>错误</h1><p>${error.message}</p></body></html>`,
        {
          status: 500,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        }
      );
    }
  }

  // 处理清空日志
  async handleClearLogs(request) {
    const clientIp = this.getClientIp(request);
    const cookieHeader = request.headers.get("Cookie") || "";
    const cookies = this.parseCookies(cookieHeader);

    // 验证登录状态
    if (cookies.log_auth !== this.env.LOG_PASSWORD) {
      // return new Response("未授权", { status: 401 });
      // 显示登录页面
      return new Response(this.getLogLoginHTML(), {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    try {
      // 清空日志
      await this.state.storage.delete("operationLogs");

      return new Response(
        JSON.stringify({
          status: "ok",
          message: "日志已清空",
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }
      );
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: "清空失败: " + error.message,
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
  }

  async fetch(request) {
    await this.init();
    const clientIp = this.getClientIp(request);
    const url = new URL(request.url);
    // logger.debug(`处理请求: ${url.pathname}`);
    // logger.info(`接收到客户端请求\n请求方法: ${request.method}\n请求路径: ${url.pathname}\n客户端IP: ${clientIp}\n用户代理: ${request.headers.get('User-Agent') || '未知'}\n来源页面: ${request.headers.get('Referer') || '无'}\n查询参数: ${JSON.stringify(Object.fromEntries(url.searchParams))}\n请求时间: ${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}\n内容类型: ${request.headers.get('Content-Type') || '无'}\n内容长度: ${request.headers.get('Content-Length') || '0'}\n请求协议: ${url.protocol}\n主机名: ${url.hostname}\n端口: ${url.port || '无'}`);

    const wsPath = "/" + this.env.WS_PATH || "/vnt";
    if (url.pathname === wsPath) {
      logger.info(`客户端IP: ${clientIp} 请求 VNT WebSocket 连接，开始处理`);
      return this.handleWebSocket(request, clientIp);
    }

    // 添加健康检查处理
    if (url.pathname === "/test") {
      logger.debug(`客户端IP: ${clientIp} 请求 /test 状态查询，开始处理`);
      if (!this.checkRateLimit(clientIp, "test")) {
        return new Response(
          JSON.stringify({
            错误: "您的请求过于频繁啦",
            提示:
              "每分钟最多" +
              this.rateLimitConfig.maxRequestsPerMinute +
              "次请求",
          }),
          {
            status: 429,
            headers: {
              "Content-Type": "application/json",
              "Retry-After": "60",
            },
          }
        );
      }
      const networkCount = this.packetHandler.cache?.networks?.size || 0;
      let totalOnlineClients = 0;

      // 统计所有网络中的在线客户端数
      if (this.packetHandler.cache?.networks) {
        for (const [token, networkInfo] of this.packetHandler.cache.networks) {
          for (const [virtualIp, client] of networkInfo.clients) {
            if (client.online) {
              totalOnlineClients++;
            }
          }
        }
      }
      const connectionCount = this.connections.size;
      const status = {
        WebSocket服务: "正常",
        启动时间: this.getStartTimeBeijing(),
        已运行: this.getRunningDuration(),
        支持协议: "VNT WebSocket",
        服务状态: connectionCount >= 0 ? "可用" : "异常",
        Token使用数: networkCount,
        客户端在线数: totalOnlineClients,
      };
      return new Response(this.getTestModalHTML(status), {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    // 添加设备列表查询处理
    if (url.pathname === "/room") {
      logger.debug(`客户端IP: ${clientIp} 请求 /room 设备列表查询，开始处理`);
      if (!this.checkRateLimit(clientIp, "room")) {
        return new Response(
          JSON.stringify({
            错误: "您的请求过于频繁啦",
            提示:
              "每分钟最多" +
              this.rateLimitConfig.maxRequestsPerMinute +
              "次请求",
          }),
          {
            status: 429,
            headers: {
              "Content-Type": "application/json",
              "Retry-After": "60",
            },
          }
        );
      }
      return this.handleDeviceListQuery(request);
    }

    if (url.pathname === "/log") {
      logger.debug(`客户端IP: ${clientIp} 请求 /log 日志查询，开始处理`);
      return this.handleLogEndpoint(request);
    }
    if (url.pathname === "/log/clear") {
      logger.debug(`客户端IP: ${clientIp} 请求 /log/clear 删除日志，开始处理`);
      return this.handleClearLogs(request);
    }

    // logger.debug(`客户端IP: ${clientIp} 请求了未知路径: ${url.pathname}，返回404`);
    return new Response("Not Found", { status: 404 });
  }

  async handleWebSocket(request, clientIp) {
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    const clientId = this.generateClientId(clientIp);
    const addr = this.parseClientAddress(request);

    // logger.info(`新的WebSocket连接: ${clientId} 来自 ${JSON.stringify(addr)}`);

    // 创建 VNT 上下文
    const context = new VntContext({
      linkAddress: addr,
      serverCipher: null,
    });

    this.contexts.set(clientId, context);
    this.connections.set(clientId, server);

    // 初始化连接状态
    this.initializeConnection(clientId, server);

    // 设置 WebSocket 消息处理
    server.addEventListener("message", async (event) => {
      await this.handleMessage(clientId, event.data);
    });

    server.addEventListener("close", (event) => {
      logger.info(`WebSocket关闭: ${clientId}`);
      this.handleClose(clientId);
    });

    server.addEventListener("error", (error) => {
      logger.error(`WebSocket错误 ${clientId}:`, error);
      this.handleClose(clientId);
    });

    // ping/pong 事件监听
    server.addEventListener("ping", () => {
      server.pong();
    });

    server.addEventListener("pong", () => {
      this.updateLastActivity(clientId);
    });
    // logger.debug(`WebSocket握手完成，返回101状态码`);

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  // 初始化连接管理
  initializeConnection(clientId, server) {
    logger.info(`初始化客户端连接: ${clientId}`);
    const connectionInfo = {
      server: server,
      lastActivity: Date.now(),
      clientId: clientId,
      isAlive: true,
      p2p_list: [],
      up_stream: 0,
      down_stream: 0,
      is_cone: false,
      last_status_update: new Date().toISOString(),
    };

    this.connectionInfos.set(clientId, connectionInfo);
    // logger.debug(`客户端 ${clientId} 连接信息已存储`);

    // 启动心跳定时器
    this.startHeartbeat(clientId);

    // 启动定期健康检查
    if (!this.healthCheckInterval) {
      // 从环境变量读取健康检查间隔，默认300秒（5分钟）
      const healthCheckSeconds = parseInt(
        this.env.HEALTH_CHECK_INTERVAL || "300"
      );
      const healthCheckMs = healthCheckSeconds * 1000;
      this.healthCheckInterval = setInterval(() => {
        this.checkConnectionHealth();
      }, healthCheckMs);
      logger.info(
        `健康检查定时器已启动，间隔${healthCheckSeconds}秒，清理已断开连接的客户端`
      );
    }
  }

  // 启动心跳机制
  startHeartbeat(clientId) {
    const server = this.connections.get(clientId);
    if (!server) return;

    // 从环境变量读取心跳检查间隔，默认30秒
    const heartbeatSeconds = parseInt(this.env.HEARTBEAT_INTERVAL || "30");
    const heartbeatMs = heartbeatSeconds * 1000;
    const heartbeatId = setInterval(() => {
      try {
        // 只检查连接状态，不主动发送心跳包
        if (server.readyState !== WebSocket.OPEN) {
          // logger.debug(`连接 ${clientId} 已断开，清理资源`);
          this.handleClose(clientId);
        }
      } catch (error) {
        // logger.error(`心跳检查失败 ${clientId}:`, error);
        this.handleClose(clientId);
      }
    }, heartbeatMs); // 每30秒检查一次连接状态

    this.heartbeatTimers.set(clientId, heartbeatId);
    logger.info(
      `客户端 ${clientId} 心跳定时器已启动，间隔${heartbeatSeconds}秒`
    );
  }

  // 更新最后活动时间
  updateLastActivity(clientId) {
    const connectionInfo = this.getConnectionInfo(clientId);
    if (connectionInfo) {
      connectionInfo.lastActivity = Date.now();
      // logger.debug(`更新客户端 ${clientId} 最后活动时间`);
    } else {
      // logger.debug(`客户端 ${clientId} 连接信息不存在，无法更新活动时间`);
    }
  }

  // 获取连接信息
  getConnectionInfo(clientId) {
    if (!this.connectionInfos) {
      // logger.debug(`连接信息映射未初始化`);
      return null;
    }
    const connectionInfo = this.connectionInfos.get(clientId);
    if (!connectionInfo) {
      // logger.debug(`客户端 ${clientId} 无连接信息记录`);
    }
    return connectionInfo;
  }

  // 轻量级 VNT 头部解析（类似 easytier）
  parseVNTHeader(buffer) {
    if (!buffer || buffer.length < 12) {
      // logger.debug(`VNT头部解析失败：数据包长度不足 (${buffer?.length || 0} < 12)`);
      return null;
    }

    const header = {
      source:
        (buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | buffer[7],
      destination:
        (buffer[8] << 24) | (buffer[9] << 16) | (buffer[10] << 8) | buffer[11],
      protocol: buffer[1],
      transportProtocol: buffer[2],
    };

    // logger.debug(`VNT头部解析完成: 源=${this.packetHandler.formatIp(header.source)}, 目标=${this.packetHandler.formatIp(header.destination)}, 协议=${header.protocol}, 传输=${header.transportProtocol}`);
    return header;
  }

  // 快速转发判断
  shouldFastForward(data) {
    if (!data || data.length < 12) {
      // logger.debug(`快速转发判断失败：数据包长度不足`);
      return false;
    }

    const protocol = data[1];
    const transport = data[2];

    const shouldForward =
      // IPTURN 数据包（最常见）
      (protocol === 4 && transport === 4) ||
      // WGIpv4 数据包
      (protocol === 4 && transport === 2) ||
      // Ipv4Broadcast 数据包
      (protocol === 4 && transport === 3) ||
      // 注意：移除 IPTURN IPv4（ICMP ping）包
      false;

    // logger.debug(`是否快速转发判断: 协议=${protocol}, 传输=${transport}, 结果=${shouldForward ? "允许" : "拒绝"}`);
    return shouldForward;
  }

  // 需要完整解析的包
  requiresFullParsing(data) {
    if (!data || data.length < 12) {
      // logger.debug(`完整解析检查：数据包长度不足，需要完整解析`);
      return true;
    }

    const protocol = data[1];
    // SERVICE 协议和部分 CONTROL 协议需要完整解析
    const needsFullParsing = protocol === 1 || (protocol === 3 && data[2] >= 3);

    // logger.debug(`是否完整解析检查: 协议=${protocol}, 传输=${data[2]}, 结果=${needsFullParsing ? "需要" : "不需要"}`);
    return needsFullParsing;
  }

  async relayPacket(sourceClientId, data, header) {
    logger.debug(
      `开始转发数据包从 ${sourceClientId} 到 ${this.packetHandler.formatIp(
        header.destination
      )}`
    );

    // 检查是否禁用中继
    if (this.env.DISABLE_RELAY === "1") {
      logger.warn("中继转发已禁用，丢弃数据包");
      return;
    }

    // 获取源客户端的网络信息
    const sourceContext = this.contexts.get(sourceClientId);
    if (!sourceContext || !sourceContext.link_context) {
      logger.error(`源客户端 ${sourceClientId} 上下文不存在`);
      return;
    }

    // 查找同一网络中的所有在线客户端
    const networkInfo = sourceContext.link_context.network_info;
    const targetClient = networkInfo.clients.get(header.destination);

    if (targetClient && targetClient.online) {
      // 通过服务器中继到目标客户端
      for (const [clientId, server] of this.connections) {
        if (clientId === sourceClientId) continue;

        const clientContext = this.contexts.get(clientId);
        if (
          clientContext &&
          clientContext.link_context &&
          clientContext.link_context.virtual_ip === header.destination
        ) {
          try {
            server.send(data);
            // logger.info(`数据包已转发到客户端 ${clientId}`);
            break;
          } catch (error) {
            logger.error(`转发到客户端 ${clientId} 失败:`, error);
          }
        }
      }
    } else {
      logger.warn(
        `目标客户端 ${this.packetHandler.formatIp(
          header.destination
        )} 不在线或不存在`
      );
    }
  }
  // 高性能消息处理
  async handleMessage(clientId, data) {
    try {
      // 确保数据是 Uint8Array
      let uint8Data;
      if (data instanceof ArrayBuffer) {
        uint8Data = new Uint8Array(data);
      } else if (data instanceof Uint8Array) {
        uint8Data = data;
      } else {
        // logger.warn(`不支持的数据类型: ${typeof data}`);
        return;
      }

      // 更新活动时间
      this.updateLastActivity(clientId);
      const protocol = uint8Data[1];
      const transport = uint8Data[2];

      // 检测传输协议4的ping包
      if (protocol === 4 && transport === 4) {
        // logger.debug(`检测到传输协议4包，目标=${this.packetHandler.formatIp((uint8Data[8] << 24) | (uint8Data[9] << 16) | (uint8Data[10] << 8) | uint8Data[11])}`);
        const header = parseVNTHeaderFast(uint8Data);
        if (header && header.destination) {
          const gatewayIp = this.getGatewayIp(clientId);
          if (header.destination === gatewayIp) {
            // logger.debug(`检测到ping网关（传输协议4），直接响应`);
            const response = await this.handleGatewayPing(clientId, uint8Data);

            // 关键修复：发送响应包给客户端
            if (response) {
              const server = this.connections.get(clientId);
              if (server && server.readyState === WebSocket.OPEN) {
                server.send(response.buffer());
                // logger.debug(`ICMP响应已发送给客户端`);
              }
            }
            return;
          }
        }
      }

      // 优先检查快速转发
      if (this.shouldFastForward(uint8Data)) {
        const protocol = uint8Data[1];
        const transport = uint8Data[2];
        // logger.debug(`快速转发: 协议=${protocol}, 传输=${transport}`);

        return await this.fastForward(clientId, uint8Data);
      }

      // 完整解析路径
      const header = parseVNTHeaderFast(uint8Data);

      if (!header) {
        return await this.fullParsingPath(clientId, uint8Data);
      }

      // 控制包和服务包需要完整解析
      if (header.isControlPacket || header.isServicePacket) {
        return await this.fullParsingPath(clientId, uint8Data);
      }

      return await this.fastForward(clientId, uint8Data);
    } catch (error) {
      logger.error(`处理 ${clientId} 消息时出错:`, error);
    }
  }

  // 辅助函数：根据 IP 查找客户端
  findClientByIp(targetIp) {
    // logger.debug(`开始查找IP地址 ${targetIp} 对应的客户端`);
    for (const [clientId, context] of this.contexts) {
      if (
        context.link_context &&
        context.link_context.virtual_ip === targetIp
      ) {
        // logger.debug(`找到客户端: ${targetIp} -> ${clientId}`);
        return clientId;
      }
    }
    // logger.debug(`未找到IP地址 ${targetIp} 对应的客户端`);
    return null;
  }

  // 快速转发路径
  async fastForward(clientId, data) {
    // logger.info(`开始快速转发数据包，来源客户端: ${clientId}`);

    let forwardedCount = 0;
    for (const [targetClientId, server] of this.connections) {
      if (targetClientId === clientId) continue;

      try {
        if (server.readyState === WebSocket.OPEN) {
          server.send(data);
          forwardedCount++;
          // logger.debug(`数据包已转发到客户端: ${targetClientId}`);
        } else {
          // logger.debug(`客户端 ${targetClientId} 连接未开启，跳过转发`);
        }
      } catch (error) {
        logger.error(`转发到客户端 ${targetClientId} 失败:`, error);
      }
    }

    // logger.info(`快速转发完成，成功转发到 ${forwardedCount} 个客户端`);
  }

  // 完整解析路径（保持 VNT 兼容性）
  async fullParsingPath(clientId, data) {
    const packet = NetPacket.parse(data);
    const context = this.contexts.get(clientId);
    const addr = context?.linkAddress || { ip: "unknown", port: 0 };

    // logger.debug(`开始完整VNT解析，客户端: ${clientId}`);
    // logger.debug(`数据包协议: ${packet.protocol}, 传输协议: ${packet.transportProtocol}`);

    // 检查是否是 P2P 状态报告包
    if (
      packet.protocol === PROTOCOL.SERVICE &&
      packet.transportProtocol === TRANSPORT_PROTOCOL.RegistrationRequest
    ) {
      try {
        const payload = packet.get_payload();
        if (payload && payload.p2p_status) {
          // logger.debug(`检测到P2P状态报告包，开始处理`);
          this.handleP2PStatusReport(clientId, payload.p2p_status);
        }
      } catch (e) {
        // 忽略解析错误  logger.debug(`P2P状态报告解析失败，忽略错误`);
      }
    }

    const response = await this.packetHandler.handle(
      context,
      packet,
      addr,
      clientId
    );

    if (response) {
      const server = this.connections.get(clientId);
      if (server && server.readyState === WebSocket.OPEN) {
        server.send(response.buffer());
        // logger.debug(`响应包已发送给客户端: ${clientId}`);
      }
    }

    // VNT 协议的广播逻辑
    if (this.shouldBroadcast(packet)) {
      // logger.info(`开始广播数据包，来源客户端: ${clientId}`);
      await this.broadcastPacket(clientId, packet);
    }
  }

  buildHandshakeResponse(clientId) {
    const context = this.contexts.get(clientId);
    // logger.debug(`构建客户端 ${clientId} 的握手响应`);
    const response = {
      // VNT 协议基础字段
      version: "cloudflare", // 协议版本 [1](#26-0)
      secret: false, // 是否启用加密 [2](#26-1)
      public_key: new Uint8Array(0), // 服务器公钥 [3](#26-2)
      key_finger: "", // 密钥指纹 [4](#26-3)

      // P2P 扩展字段
      p2p_targets: Array.from(this.p2p_connections.get(clientId) || []),
      request_p2p_status: true, // 请求客户端报告 P2P 状态
      server_p2p_support: true, // 服务器支持 P2P 智能判断
    };
    // logger.debug(`握手响应构建完成，P2P目标数量: ${p2pTargets.length}`);
    return response;
  }
  // 基于头部的转发
  async headerBasedForward(clientId, data, header) {
    // logger.info(`开始基于头部的转发，来源客户端: ${clientId}`);

    let forwardedCount = 0;
    for (const [targetClientId, server] of this.connections) {
      if (targetClientId === clientId) continue;

      try {
        if (server.readyState === WebSocket.OPEN) {
          server.send(data);
          forwardedCount++;
          // logger.debug(`数据包已转发到客户端: ${targetClientId}`);
        } else {
          // logger.debug(`客户端 ${targetClientId} 连接未开启，跳过转发`);
        }
      } catch (error) {
        logger.error(`头部转发到客户端 ${targetClientId} 失败:`, error);
      }
    }

    // logger.info(`头部转发完成，成功转发到 ${forwardedCount} 个客户端`);
  }

  // VNT 协议广播判断
  shouldBroadcast(packet) {
    // logger.debug(`判断数据包是否需要广播，协议: ${packet.protocol}`);
    // 保持原有的 VNT 广播逻辑
    if (packet.protocol === PROTOCOL.SERVICE) {
      // logger.debug(`SERVICE协议，不广播`);
      return false;
    }

    if (packet.protocol === PROTOCOL.ERROR) {
      // logger.debug(`ERROR协议，不广播`);
      return false;
    }

    // logger.debug(`协议 ${packet.protocol} 允许广播`);
    return true;
  }

  async broadcastPacket(senderId, packet) {
    const senderContext = this.contexts.get(senderId);

    for (const [clientId, server] of this.connections) {
      if (clientId === senderId) continue;

      try {
        if (this.shouldForward(senderContext, packet)) {
          // logger.debug(`广播数据包从 ${senderId} 到 ${clientId}`);

          const packetCopy = this.copyPacket(packet);
          server.send(packetCopy.buffer());
        }
      } catch (error) {
        logger.error(`广播到客户端 ${clientId} 失败:`, error);
      }
    }
  }

  copyPacket(originalPacket) {
    try {
      const buffer = originalPacket.buffer();
      const copiedBuffer = new Uint8Array(buffer.length);
      copiedBuffer.set(buffer);
      return NetPacket.parse(copiedBuffer);
    } catch (error) {
      logger.error(`复制数据包失败:`, error);
      return originalPacket;
    }
  }

  shouldForward(context, packet) {
    const shouldForward = packet.protocol !== PROTOCOL.SERVICE;
    // logger.debug(`转发判断: 协议=${packet.protocol}, 结果=${shouldForward ? "允许转发" : "拒绝转发"}`);
    return shouldForward;
  }

  handleClose(clientId) {
    logger.info(`开始清理连接: ${clientId}`);

    const context = this.contexts.get(clientId);

    if (context) {
      try {
        // 清理上下文（仅标记离线，不删除）
        this.packetHandler.leave(context);
      } catch (error) {
        logger.error(`清理 ${clientId} 上下文时出错:`, error);
      }
    }

    // 清理心跳定时器
    const heartbeatId = this.heartbeatTimers.get(clientId);
    if (heartbeatId) {
      logger.debug(`停止 ${clientId} 的心跳定时器`);
      clearInterval(heartbeatId);
      this.heartbeatTimers.delete(clientId);
    }

    // 清理连接和上下文
    this.contexts.delete(clientId);
    this.connections.delete(clientId);

    // 清理连接信息
    if (this.connectionInfos) {
      this.connectionInfos.delete(clientId);
    }

    // 如果没有活跃连接了，停止健康检查
    if (this.connections.size === 0 && this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
      logger.debug(`所有连接已断开，停止健康检查定时器`);
    }

    logger.info(`连接 ${clientId} 清理完成`);
    logger.info(`>========================<`);
  }

  generateClientId(clientIp) {
    const randomPart = Math.random().toString(36).substr(2, 9);
    const clientId = `${clientIp}_${randomPart}`;
    // logger.debug(`生成客户端ID: ${clientId}`);
    return clientId;
  }

  parseClientAddress(request) {
    // 优先从CF-Connecting-IP获取真实IP（不区分大小写）
    const headers = {};

    // 将所有header转换为小写key，实现不区分大小写查找
    for (const [key, value] of request.headers.entries()) {
      headers[key.toLowerCase()] = value;
    }

    const address = {
      ip:
        headers["cf-connecting-ip"] ||
        headers["x-real-ip"] ||
        headers["x-forwarded-for"] ||
        "unknown",
      port: 0,
    };

    // logger.debug(`解析客户端地址: ${JSON.stringify(address)}`);
    return address;
  }
  checkConnectionHealth() {
    logger.debug(`开始健康检查，当前连接数: ${this.connections.size}`);

    let cleanedCount = 0;
    for (const [clientId, server] of this.connections) {
      if (server.readyState !== WebSocket.OPEN) {
        logger.debug(`连接 ${clientId} 已断开，准备清理`);
        this.handleClose(clientId);
        cleanedCount++;
      }
    }

    logger.debug(`健康检查完成，清理了 ${cleanedCount} 个断开的连接`);
  }
}
