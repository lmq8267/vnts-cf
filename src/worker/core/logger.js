let globalLogger = null;
let isInitialized = false;

export class Logger {
  constructor(env) {
    this.env = env;

    // 调试输出：显示读取到的环境变量
    // console.log(`[Logger] 当前环境变量:`, JSON.stringify(env));
    // console.log(`[Logger] 日志等级:`, env.LOG_LEVEL || '未设置，使用默认值 warn');

    this.levels = {
      error: 0,
      warn: 1,
      info: 2,
      debug: 3,
    };

    // 获取配置的日志级别，支持大小写兼容
    const configLevel = (env.LOG_LEVEL || "warn").toLowerCase();
    this.currentLevel = this.levels[configLevel] ?? this.levels.warn;

    // console.log(`[Logger] 当前日志等级: ${configLevel} (级别: ${this.currentLevel})`);
  }

  shouldLog(level) {
    return this.levels[level] <= this.currentLevel;
  }

  formatTimestamp() {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, "0");
    const day = String(now.getDate()).padStart(2, "0");
    const hours = String(now.getHours()).padStart(2, "0");
    const minutes = String(now.getMinutes()).padStart(2, "0");
    const seconds = String(now.getSeconds()).padStart(2, "0");
    return `[${year}-${month}-${day} ${hours}:${minutes}:${seconds}]`;
  }

  // 中文日志级别映射
  getChineseLevel(level) {
    const levelMap = {
      error: "错误",
      warn: "警告",
      info: "信息",
      debug: "调试",
    };
    return levelMap[level] || level.toUpperCase();
  }

  createLogMessage(level, ...args) {
    const timestamp = this.formatTimestamp();
    const chineseLevel = this.getChineseLevel(level);
    const message = args
      .map((arg) =>
        typeof arg === "object" ? JSON.stringify(arg) : String(arg)
      )
      .join(" ");

    return `${timestamp} [${chineseLevel}] : ${message}`;
  }

  error(...args) {
    if (this.shouldLog("error")) {
      console.error(this.createLogMessage("error", ...args));
    }
  }

  warn(...args) {
    if (this.shouldLog("warn")) {
      console.warn(this.createLogMessage("warn", ...args));
    }
  }

  info(...args) {
    if (this.shouldLog("info")) {
      console.log(this.createLogMessage("info", ...args));
    }
  }

  debug(...args) {
    if (this.shouldLog("debug")) {
      console.log(this.createLogMessage("debug", ...args));
    }
  }
}

// 日志初始化函数 - 支持 Cloudflare Worker 环境变量设置
function autoInitialize() {
  if (isInitialized) return;

  // 尝试多种方式获取环境变量
  let env = { LOG_LEVEL: "warn" };
  let foundSource = "默认值";

  // 方式1: 从globalThis.env获取（Cloudflare Worker Durable Object）
  if (
    typeof globalThis !== "undefined" &&
    globalThis.env &&
    globalThis.env.LOG_LEVEL
  ) {
    env = globalThis.env;
    foundSource = "globalThis.env";
    // console.log('[Logger] 从globalThis.env获取环境变量:', JSON.stringify(env));
  }
  // 方式2: 从globalThis获取（如果已设置）
  else if (typeof globalThis !== "undefined" && globalThis.LOG_LEVEL) {
    env = { LOG_LEVEL: globalThis.LOG_LEVEL };
    foundSource = "globalThis.LOG_LEVEL";
    // console.log('[Logger] 从globalThis.LOG_LEVEL获取LOG_LEVEL:', globalThis.LOG_LEVEL);
  }
  // 方式3: 从全局变量获取（兼容性）
  else if (typeof LOG_LEVEL !== "undefined") {
    env = { LOG_LEVEL: LOG_LEVEL };
    foundSource = "全局变量LOG_LEVEL";
    // console.log('[Logger] 从全局变量获取LOG_LEVEL:', LOG_LEVEL);
  }
  // 方式4: 从process.env获取（Node.js环境）
  else if (
    typeof process !== "undefined" &&
    process.env &&
    process.env.LOG_LEVEL
  ) {
    env = { LOG_LEVEL: process.env.LOG_LEVEL };
    foundSource = "process.env";
    // console.log('[Logger] 从process.env获取LOG_LEVEL:', process.env.LOG_LEVEL);
  } else {
    // console.log('[Logger] 未找到环境变量，使用默认值 warn');
  }

  // console.log(`[Logger] 使用来源: ${foundSource}`);
  globalLogger = new Logger(env);
  isInitialized = true;
}

// 导出全局logger，自动初始化
export const logger = {
  error: (...args) => {
    if (!isInitialized) autoInitialize();
    globalLogger?.error(...args);
  },
  warn: (...args) => {
    if (!isInitialized) autoInitialize();
    globalLogger?.warn(...args);
  },
  info: (...args) => {
    if (!isInitialized) autoInitialize();
    globalLogger?.info(...args);
  },
  debug: (...args) => {
    if (!isInitialized) autoInitialize();
    globalLogger?.debug(...args);
  },
};

// 可选：手动设置全局日志级别
export function setGlobalLogLevel(level) {
  // console.log(`[Logger] 日志级别设置为: ${level}`);
  if (typeof globalThis !== "undefined") {
    globalThis.LOG_LEVEL = level;
  }
  // 重新初始化
  globalLogger = new Logger({ LOG_LEVEL: level });
  isInitialized = true;
}
