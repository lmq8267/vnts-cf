# JavaScript版vnts的实现，cloudflare worker

[VNT](https://github.com/vnt-dev/vnt) 是一个简便高效的异地组网、内网穿透工具，源项目使用 Rust 实现。本项目使用 Cloudflare Worker + Durable Object 实现了 JavaScript 版本的 WebSocket vnts 服务端，支持网络中继转发与 P2P 打洞信息交换。

> **注意：本项目仅供学习交流使用**

## 本地测试

```
cd vnts-cf
sudo docker build -t vnts-cf .

sudo rm -rf node_modules .wrangler
sudo docker run --rm -it -p 29872:8787 -v $(pwd):/app -v /app/node_modules vnts-cf
```

## CF部署

1.fork此仓库

2.登陆CF，管理worekes 新建链接到github仓库为刚刚fork的，直接部署

3.添加自定义域名

4.vnt客户端采用 `-s wss://域名/vnt` 连接

**测试服务是否正常 `http://域名/test`**

<img width="547" height="478" alt="图片" src="https://github.com/user-attachments/assets/559db0f5-8683-45ba-ab78-8c9cc562dc8f" />

**查看设备连接状态 `http://域名/room`**

<img width="1227" height="338" alt="图片" src="https://github.com/user-attachments/assets/7ee7e4b6-9622-4ed0-98bb-d90e5fd5778c" />


## 仅 P2P 模式

在 `wrangler.toml` 的 `[vars]` 中配置：
- `DISABLE_RELAY`: `"1"` 开启仅 P2P 直连模式，默认 `"0"`

