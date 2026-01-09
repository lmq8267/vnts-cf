# JavaScript版vnts的实现，cloudflare worker

#### [VNT](https://github.com/vnt-dev/vnt) 是一个简便高效的异地组网、内网穿透工具，源项目使用 Rust 实现。本项目使用 Cloudflare Worker + Durable Object 实现了 JavaScript 版本的 WebSocket [VNTS](https://github.com/vnt-dev/vnts) 服务端，支持网络中继转发与 P2P 打洞信息交换。

#### 本项目由 <a href="https://deepwiki.com/lmq8267/vnts-cf"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a> 搓出来，已知问题是不能使用 `-W` 服务端加密 参数，其他暂未发现，可以测试反馈或帮忙修复优化！

> **注意：本项目仅供学习交流使用**

## 本地测试

```
# git clone
cd vnts-cf
sudo docker build -t vnts-cf .

sudo docker run --rm -it -p 29872:8787 -v $(pwd):/app -v /app/node_modules vnts-cf
```

vnt客户端采用 `-s ws://ip:29872/vnt` 连接

## CF部署

1.fork此仓库

2.登录[Cloudflare Dashboard](https://dash.cloudflare.com)

3.进入 Workers & Pages → 创建应用程序（Create Application） →  Workers →  链接到github仓库 选择你刚刚fork的仓库，直接部署

4.绑定自定义域名：打开 Worker 设置 → Triggers(域和路由) → 添加 → Custom Domains(自定义域名)，添加你的域名并保存。

5.vnt客户端采用 `-s wss://域名/vnt` 连接

**测试服务是否正常 `http://域名/test`**

<img width="547" height="478" alt="图片" src="https://github.com/user-attachments/assets/559db0f5-8683-45ba-ab78-8c9cc562dc8f" />

**查看设备连接状态 `http://域名/room`**

<img width="1227" height="338" alt="图片" src="https://github.com/user-attachments/assets/7ee7e4b6-9622-4ed0-98bb-d90e5fd5778c" />

**查看访问CF里的运行日志 `http://域名/log`** 需要设置 `LOG_PASSWORD` 才能开放

<img width="1284" height="375" alt="image" src="https://github.com/user-attachments/assets/ad855b2f-1982-4cce-b8aa-4173aabc71ab" />


## 仅 P2P 模式

在 `wrangler.toml` 的 `[vars]` 中找到配置：
- `DISABLE_RELAY`: `"1"` 开启仅 P2P 直连模式，默认 `"0"`

## 开启Token白名单

在 `wrangler.toml` 的 `[vars]` 中找到配置：
- `WHITE_TOKEN`: `"token1,token2,token3"` 填写对应的token即可开启，多个token用逗号分隔，默认 `""` 留空任何token都可以连接注册使用

## 开启CF日志

在 `wrangler.toml` 的 `[vars]` 中找到配置：
- `LOG_PASSWORD`: `"password"` 设置密码即可开启，默认 `""` 留空不开启，注意：开启日志会消耗免费额度，日常使用请勿开启！


## 免责声明

本项目仅供学习交流使用，请勿用于任何商业用途或非法用途。使用本项目代码所产生的任何后果，均由使用者自行承担。作者不对使用本项目代码可能引起的任何直接或间接损害负责。
