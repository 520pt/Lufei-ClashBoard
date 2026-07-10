# LuFei 自定义规则浏览器插件

这个目录是 Chrome / Microsoft Edge 通用的 Manifest V3 插件，用来把当前网页一键添加到 Lufei-ClashBoard 自定义规则集。

## 功能

- 点击插件图标，读取当前网页域名
- 一键添加到：
  - 自定义-代理
  - 自定义-直连
- 支持规则类型：
  - DOMAIN-SUFFIX
  - DOMAIN
  - 自动
  - IP-CIDR
- 支持右键菜单：
  - 添加当前网站到自定义代理
  - 添加当前网站到自定义直连
- 支持设置面板地址、默认策略、默认规则类型

## 安装到 Chrome

1. 打开 `chrome://extensions/`
2. 开启右上角“开发者模式”
3. 点击“加载已解压的扩展程序”
4. 选择本目录：`browser-extension`

## 安装到 Edge

1. 打开 `edge://extensions/`
2. 开启左侧“开发人员模式”
3. 点击“加载解压缩的扩展”
4. 选择本目录：`browser-extension`

## 初次设置

安装后右键插件图标，打开“扩展选项”，确认面板地址：

```text
http://10.0.0.11:2048
```

不要填 OpenWrt 无法访问的 `127.0.0.1`。如果部署在 NAS 上，填 NAS 的局域网地址，例如：

```text
http://10.0.0.20:2048
```

## 使用

### 方式一：点击插件图标

1. 打开任意网站
2. 点击浏览器右上角 LuFei 插件图标
3. 选择“代理”或“直连”
4. 点击“添加当前网站”

### 方式二：右键菜单

在网页里右键：

- 添加当前网站到自定义代理
- 添加当前网站到自定义直连

## 调用接口

插件调用当前面板的接口：

```http
POST /api/custom-rules
```

请求示例：

```json
{
  "target": "example.com",
  "kind": "domain_suffix",
  "policy": "proxy"
}
```

`policy` 可选：

- `proxy`：自定义代理
- `direct`：自定义直连
