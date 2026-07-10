# Lufei-ClashBoard

Lufei-ClashBoard 是基于 Vue 3、TypeScript、Vite、Express 的 Clash / Mihomo / OpenClash / Nikki / sing-box 面板。

本项目在 AnGe-ClashBoard / zashboard 基础上加入了路飞自用的自定义规则集能力，重点适合在 OpenWrt + OpenClash 环境中维护个人分流规则。

## 主要功能

- Clash / Mihomo 控制器面板
- OpenClash / Nikki 规则源 SSH 检测
- 自定义规则集页面：支持添加域名、URL、IP、CIDR
- `ziyong.list` 本地规则地址输出
- 一键写入当前 OpenClash / Nikki YAML
- 写入前自动备份远程 YAML
- 路飞自用面板设置一键导入
- 路飞策略组默认图标配置
- Docker / 本地 Node.js 部署

## 自定义规则集

部署后访问面板左侧：

```text
自定义规则
```

默认规则地址：

```text
http://<面板IP>:<端口>/ziyong.list
```

YAML 中会使用类似配置：

```yaml
proxy-groups:
  - {name: 自定义, <<: *default}

rules:
  - RULE-SET,LuFei / Custom,自定义

rule-providers:
  LuFei / Custom: {<<: *class, url: "http://<面板IP>:<端口>/ziyong.list"}
```

也可以在面板中配置规则源 SSH 后，点击“一键写入当前 YAML”。

## 本地开发

```bash
pnpm install
pnpm dev:full
```

## 构建

```bash
pnpm build:no-fonts
```

## 后端启动

```bash
pnpm start
```

默认端口：

```text
2048
```

可以通过环境变量修改：

```bash
PORT=2048 pnpm start
```

## Docker

```bash
docker build -t lufei-clashboard .
docker run -d \
  --name lufei-clashboard \
  -p 2048:2048 \
  -v ./data:/app/data \
  lufei-clashboard
```

访问：

```text
http://服务器IP:2048
```

## 规则源 SSH 用途

规则源 SSH 用来让面板登录 OpenWrt，读取当前 OpenClash / Nikki 正在使用的 YAML，并提取或写入 `rule-providers`、`rules`、`proxy-groups`。

它不是代理控制 API。代理控制 API 仍然是 Mihomo / OpenClash 的 controller 地址和 secret。

## 验证命令

```bash
pnpm type-check
pnpm test:server
pnpm build:no-fonts
```

## 来源

基于 AnGe-ClashBoard / zashboard 二次调整。
