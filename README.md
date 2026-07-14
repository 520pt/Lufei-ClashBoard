# Lufei-ClashBoard

Lufei-ClashBoard 是基于 Vue 3、TypeScript、Vite、Express 的 Clash / Mihomo / OpenClash / Nikki / sing-box 面板。

本项目在 AnGe-ClashBoard / zashboard 基础上加入了路飞自用的自定义规则集能力，重点适合在 OpenWrt + OpenClash 环境中维护个人分流规则。

## 主要功能

- Clash / Mihomo 控制器面板
- OpenClash / Nikki 规则源 SSH 检测
- 自定义规则集页面：支持添加域名、URL、IP、CIDR
- `ziyong.list` 代理规则地址输出
- `ziyong-direct.list` 直连规则地址输出
- 一键写入当前 OpenClash / Nikki YAML
- 写入前自动备份远程 YAML
- 路飞自用面板设置一键导入
- 路飞策略组默认图标配置
- Docker / 本地 Node.js 部署
- Chrome / Microsoft Edge 浏览器插件，一键把当前网站加入自定义代理或直连规则

## 自定义规则集

部署后访问面板左侧：

```text
自定义规则
```

默认规则地址：

```text
代理：http://<面板IP>:<端口>/ziyong.list
直连：http://<面板IP>:<端口>/ziyong-direct.list
```

YAML 中会使用类似配置：

```yaml
proxy-groups:
  - {name: 自定义-代理, <<: *default}
  - {name: 自定义-直连, type: select, proxies: [DIRECT]}

rules:
  - RULE-SET,LuFei / Custom,自定义-代理
  - RULE-SET,LuFei / Custom Direct,自定义-直连

rule-providers:
  LuFei / Custom: {<<: *class, url: "http://<面板IP>:<端口>/ziyong.list"}
  LuFei / Custom Direct: {<<: *class, url: "http://<面板IP>:<端口>/ziyong-direct.list"}
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

推荐使用 Docker Compose，这样 `./data` 会固定挂载到容器的 `/app/data`，自定义规则、后端配置和 SQLite 数据库在更新重建后都不会丢失：

```bash
docker compose up -d
```

更新镜像并重建：

```bash
docker compose pull
docker compose up -d
```

如果需要本地构建：

```bash
docker build -t lufei-clashboard .
docker run -d \
  --name lufei-clashboard \
  --restart unless-stopped \
  -p 2048:2048 \
  -v ./data:/app/data \
  lufei-clashboard
```

Windows 本地重建可以直接运行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/restart-docker.ps1
```

注意：不要删除 `data` 目录，也不要使用 `docker compose down -v` 或删除对应 volume，否则持久化数据会被清空。

访问：

```text
http://服务器IP:2048
```


## 浏览器插件

项目内置 Chrome / Microsoft Edge 通用的 Manifest V3 插件，目录：

```text
browser-extension
```

插件用于把当前网页一键添加到 Lufei-ClashBoard 自定义规则集，适合日常浏览时快速把域名加入“自定义-代理”或“自定义-直连”。

### 插件功能

- 点击插件图标，直接在弹窗里完成全部操作
- 默认面板地址为 `http://127.0.0.1:2048`
- 首次安装会自动扫描常见局域网地址的 `2048` 端口，确认是 Lufei-ClashBoard 后自动填入面板地址
- 弹窗内可手动设置面板地址并测试连接
- 自动识别当前网页：
  - 域名网页 → `DOMAIN-SUFFIX`
  - IP 网页 → `IP-CIDR`
- 规则类型会自动选中识别结果，也可以手动改成 `DOMAIN` / `IP-CIDR` / `原始规则`
- 添加成功后会自动请求面板刷新对应的自定义规则源
- 会显示当前网站是否已在自定义代理/直连中
- 支持在插件里删除当前网站规则
- 支持一键把当前网站在代理和直连之间切换
- 支持添加到：
  - 自定义-代理
  - 自定义-直连
- 支持手动填写目标，例如：
  - `example.com`
  - `1.1.1.1`
  - `https://www.example.com/path`
- 支持右键菜单：
  - 添加当前网站到自定义代理
  - 添加当前网站到自定义直连

### 安装到 Chrome

1. 打开 `chrome://extensions/`
2. 开启右上角“开发者模式”
3. 点击“加载已解压的扩展程序”
4. 选择本项目目录下的 `browser-extension`

### 安装到 Edge

1. 打开 `edge://extensions/`
2. 开启左侧“开发人员模式”
3. 点击“加载解压缩的扩展”
4. 选择本项目目录下的 `browser-extension`

### 插件使用

#### 方式一：点击插件图标

1. 打开任意网站
2. 点击浏览器右上角 LuFei 插件图标
3. 首次安装后插件会自动尝试发现局域网内的面板；如果没有发现，就会显示默认地址：

```text
http://127.0.0.1:2048
```

4. 如需手动设置，在弹窗内填写“面板地址”，例如：

```text
http://10.0.0.11:2048
```

5. 点击“测试连接”确认可访问
6. 确认或手动修改“规则类型”
7. 选择“代理”或“直连”
8. 点击“添加到自定义规则”
9. 如果当前网站已存在，可以直接点击“删除规则”或“切换策略”

#### 方式二：右键菜单

在网页里右键：

- 添加当前网站到自定义代理
- 添加当前网站到自定义直连

### 插件面板地址说明

不要填 OpenWrt 无法访问的 `127.0.0.1`。如果部署在 NAS 上，填 NAS 的局域网地址，例如：

```text
http://10.0.0.20:2048
```

如果部署在当前电脑，通常填当前电脑的局域网 IP，例如：

```text
http://10.0.0.11:2048
```

### 插件调用接口

插件调用当前面板的接口：

```http
POST /api/custom-rules
```

域名网页请求示例：

```json
{
  "target": "example.com",
  "kind": "domain_suffix",
  "policy": "proxy"
}
```

IP 网页请求示例：

```json
{
  "target": "1.1.1.1",
  "kind": "ip_cidr",
  "policy": "direct"
}
```

`policy` 可选：

- `proxy`：自定义代理
- `direct`：自定义直连

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
