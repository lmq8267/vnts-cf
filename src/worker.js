// Cloudflare Worker entry for VNT WebSocket relay backed by Durable Object
// Module syntax is required for Durable Objects.
import { RelayRoom } from "./worker/relay_room";

export { RelayRoom };

export default {
  async fetch(request, env, ctx) {
    // 自动设置全局环境变量，让logger能够读取
    if (typeof globalThis !== "undefined") {
      globalThis.env = env;
    }
    const url = new URL(request.url);
    const { pathname, searchParams } = url;

    const wsPath = "/" + env.WS_PATH || "/vnt";
    if (pathname === wsPath || pathname === wsPath + "/") {
      if (request.headers.get("Upgrade") !== "websocket") {
        return new Response("Expected WebSocket upgrade", { status: 400 });
      }

      const roomId = searchParams.get("room") || "default";
      const roomStub = env.RELAY_ROOM.get(env.RELAY_ROOM.idFromName(roomId));
      return roomStub.fetch(request);
    }

    // 健康检查转发到 RelayRoom
    if (pathname === "/test") {
      const roomId = searchParams.get("room") || "default";
      const roomStub = env.RELAY_ROOM.get(env.RELAY_ROOM.idFromName(roomId));
      return roomStub.fetch(request);
    }

    // 添加设备列表查询端点
    if (pathname === "/room") {
      const roomId = searchParams.get("room") || "default";
      const roomStub = env.RELAY_ROOM.get(env.RELAY_ROOM.idFromName(roomId));
      return roomStub.fetch(request);
    }

    // 添加日志端点
    if (pathname === "/log" || pathname === "/log/clear") {
      // 检查是否启用了日志密码  
      if (!env.LOG_PASSWORD || env.LOG_PASSWORD.trim() === "") {  
        return new Response("Not found", { status: 404 });  
      }
      const roomId = searchParams.get("room") || "default";
      const roomStub = env.RELAY_ROOM.get(env.RELAY_ROOM.idFromName(roomId));
      return roomStub.fetch(request);
    }

    return new Response("Not found", { status: 404 });
  },
};
