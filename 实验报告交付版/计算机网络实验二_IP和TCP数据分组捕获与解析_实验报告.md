# 计算机网络实验二：IP 和 TCP 数据分组的捕获和解析

> **说明**：本文中的图片均保留为“插图占位”。每个占位块均给出了建议插入的 Git 仓库图片路径和图片用途说明，后续可手动替换为 Markdown 图片语法或直接插入到 Word/PDF 报告中。

## 实验基本信息

| 项目 | 内容 |
|---|---|
| 实验名称 | IP 和 TCP 数据分组的捕获和解析 |
| 实验类别 | 协议分析型 |
| 实验学时 | 4 学时 |
| 实验组人数 | 单人 1 组 |
| 学生姓名 | 杨龙驹 |
| 学号 | 2024211139 |
| 班级 | 2024211308 |
| 实验日期 | 2026 年 6 月 1 日 |
| 实验地点 | 本地电脑 |
| 抓包工具 | Wireshark 4.6.6 |

## 摘要

本实验围绕主机连接 Internet 和访问 Web 服务过程中产生的典型网络报文展开，使用 Wireshark 在 Windows 主机的 WLAN 网卡上捕获并分析 DHCP、ARP、ICMP、IPv4、IPv4 分片以及 TCP 报文。实验首先通过 `ipconfig /release` 和 `ipconfig /renew` 主动触发 DHCP 地址释放与重新申请过程，观察 DHCP Release、Discover、Offer、Request、ACK 报文序列，分析主机获得 IP 地址、子网掩码、默认网关和 DNS 服务器的过程。随后通过 ping 命令观察 ARP 地址解析和 ICMP Echo Request/Reply 报文，进一步分析普通 IPv4 数据分组首部字段。为理解 IP 分片机制，实验使用 `ping -4 -l 8000 www.bupt.edu.cn` 构造大于常见以太网 MTU 的 IP 数据报，结合 MF 标志位、Fragment Offset 和 Identification 字段分析分片与重组过程。最后，实验选取一条完整的 TCP 流 `tcp.stream eq 75`，分析 TCP 三次握手、HTTP GET/200 OK 数据传输以及 FIN/ACK 连接拆除流程。通过本实验，可以将 DHCP、ARP、ICMP、IP 分片和 TCP 可靠传输机制串联起来，形成对一次真实网络通信过程的整体理解。

**关键词**：Wireshark；DHCP；ARP；ICMP；IPv4；IP 分片；TCP 三次握手；TCP 连接拆除

## 目录

- [1 实验任务与完成情况概述](#1-实验任务与完成情况概述)
- [2 实验环境与抓包方法](#2-实验环境与抓包方法)
- [3 协议基础与实验分析框架](#3-协议基础与实验分析框架)
- [4 DHCP 报文捕获与地址获取过程分析](#4-dhcp-报文捕获与地址获取过程分析)
- [5 ARP 报文捕获与局域网地址解析分析](#5-arp-报文捕获与局域网地址解析分析)
- [6 ICMP 报文捕获与 ping 过程分析](#6-icmp-报文捕获与-ping-过程分析)
- [7 普通 IPv4 数据分组结构分析](#7-普通-ipv4-数据分组结构分析)
- [8 大 IP 数据分组分片传输过程分析](#8-大-ip-数据分组分片传输过程分析)
- [9 TCP 流选择与整体通信过程概览](#9-tcp-流选择与整体通信过程概览)
- [10 TCP 三次握手过程分析](#10-tcp-三次握手过程分析)
- [11 TCP 数据通信与 HTTP 报文分析](#11-tcp-数据通信与-http-报文分析)
- [12 TCP 连接拆除过程分析](#12-tcp-连接拆除过程分析)
- [13 实验结果汇总与跨协议关联分析](#13-实验结果汇总与跨协议关联分析)
- [14 实验中遇到的问题与解决方法](#14-实验中遇到的问题与解决方法)
- [15 实验总结与个人收获](#15-实验总结与个人收获)
- [参考资料](#参考资料)
- [附录 A 实验截图索引](#附录-a-实验截图索引)
- [附录 B 抓包文件索引](#附录-b-抓包文件索引)

---

# 1 实验任务与完成情况概述

## 1.1 实验背景

计算机接入 Internet 并完成一次网络通信，并不是单个协议独立完成的过程，而是多个协议在不同层次上协同工作的结果。主机首先需要通过 DHCP 获得可用的 IP 地址、子网掩码、默认网关和 DNS 等网络配置；在局域网中转发 IP 数据报时，需要借助 ARP 将下一跳 IP 地址解析为 MAC 地址；使用 ping 命令测试连通性时，ICMP 报文被封装在 IPv4 数据报中传输；当数据报长度超过链路层 MTU 时，IPv4 层需要进行分片；在访问 Web 服务时，TCP 通过三次握手建立连接，通过序号和确认号保证数据可靠传输，并通过 FIN/ACK 报文完成连接释放。

因此，本实验并不是简单地截取若干孤立报文，而是通过抓包工具观察主机从“获得网络参数”到“完成应用层访问”的完整过程，并从报文字段角度验证网络协议的工作机制。

## 1.2 实验要求分解

本实验按照实验指导书要求，主要完成以下任务：

| 实验要求 | 本次实验完成内容 | 报告对应章节 | 主要证据材料 |
|---|---|---|---|
| 捕获 DHCP 报文并分析 | 通过释放和重新申请 IP 地址，捕获 DHCP Release、Discover、Offer、Request、ACK 报文 | 第 4 章 | 阶段二、阶段三相关截图与 `阶段二数据.pcapng` |
| 捕获 ARP 报文并分析 | 执行 ping 观察 ARP 请求与应答，分析 IP-MAC 映射 | 第 5 章 | 阶段四 ARP 截图与 `阶段四ARP.pcapng` |
| 捕获 ICMP 报文并分析 | 使用 ping 命令捕获 Echo Request/Reply 报文 | 第 6 章 | 阶段四 ICMP 截图与 `阶段四ICMP.pcapng` |
| 分析普通 IP 数据分组 | 展开 IPv4 首部字段，分析 Version、Header Length、Total Length、TTL、Protocol、Flags、Fragment Offset 等字段 | 第 7 章 | 阶段五 IPv4 截图 |
| 分析 IP 分片结构 | 使用大包 ping 触发 IPv4 分片，分析 MF、Offset、Identification 和重组关系 | 第 8 章 | 阶段六截图与 `阶段六.pcapng` |
| 分析 TCP 通信过程 | 选择一条完整 TCP 流，分析三次握手、HTTP 数据通信和连接拆除过程 | 第 9—12 章 | 阶段八至阶段十一 TCP 截图 |

## 1.3 实验完成度说明

本次实验覆盖了从网络接入到应用访问的主要协议过程。DHCP 部分观察了地址申请的完整交互，ARP 和 ICMP 部分体现了局域网地址解析与连通性测试过程，IPv4 部分分析了普通数据报和大数据报分片结构，TCP 部分选取同一条 TCP stream 对建立连接、数据传输和拆除连接进行了连续分析。报告中所有关键结论均对应具体报文序列或字段截图，能够从实际抓包数据验证协议原理。

---

# 2 实验环境与抓包方法

## 2.1 软件与硬件环境

本实验在 Windows 主机上完成，抓包工具为 Wireshark 4.6.6。实验使用主机真实联网的 WLAN 网卡进行捕获，而不是 VPN、Loopback 或 VMware 虚拟网卡。通过命令行查看网络配置，可获得如下实验环境参数：

| 参数 | 实验观察值 |
|---|---|
| 操作系统 | Windows |
| 抓包工具 | Wireshark 4.6.6 |
| 抓包网卡 | WLAN |
| 网卡型号 | Intel(R) Wi-Fi 6E AX211 160MHz |
| 本机 MAC 地址 | D4-F3-2D-97-C7-4B |
| 本机 IPv4 地址 | 10.21.213.119 |
| 子网掩码 | 255.255.128.0 |
| 默认网关 | 10.21.128.1 |
| DHCP 服务器 | 10.3.9.2 |
| DNS 服务器 | 10.3.9.5、10.3.9.4、10.3.9.6 |

> **图 2-1 插图占位：本机 WLAN 网络参数**  
> 建议插入图片：`image/CMD无线网卡参数.png`  
> 图片描述：展示 Windows 命令行中 WLAN 网卡的 IPv4 地址、子网掩码、默认网关、DHCP 服务器、DNS 服务器和无线网卡型号，是实验环境参数的主要依据。

## 2.2 Wireshark 网卡选择与捕获确认

启动 Wireshark 后，首先需要选择实际承载当前网络流量的接口。实验环境中同时存在 WLAN、Radmin VPN、Loopback、VMware Network Adapter VMnet1/VMnet8、蓝牙网络连接等多个接口。如果选择虚拟网卡或未活动网卡，将导致抓不到目标报文。因此本实验选取流量波形明显、且与实际无线联网相对应的 WLAN 接口。

> **图 2-2 插图占位：Wireshark 网卡选择界面**  
> 建议插入图片：`image/Wireshark 网卡选择界面.png`  
> 图片描述：展示 Wireshark 启动界面中各网卡接口的流量波形，WLAN 接口被选中，说明后续抓包基于真实无线网络接口。

在正式实验前，还进行了短时间抓包测试，确认 WLAN 接口能够捕获 DNS、TCP 等实际网络报文，避免后续 DHCP、ARP、ICMP、TCP 分析建立在错误接口上。

> **图 2-3 插图占位：Wireshark 短抓包测试界面**  
> 建议插入图片：`image/Wireshark 短抓包测试界面.png`  
> 图片描述：展示 WLAN 接口短时间抓包结果，其中可见 DNS 和 TCP 报文，说明所选接口能够正常捕获网络通信数据。

## 2.3 抓包过滤器与分析策略

为了减少无关报文干扰，本实验根据不同协议对象设置显示过滤器。各阶段主要过滤器如下：

| 分析对象 | Wireshark 过滤器 | 作用 |
|---|---|---|
| DHCP | `udp.port == 68` | 仅显示 DHCP 客户端端口相关报文 |
| ARP 与 ICMP | `arp || icmp` | 同时观察地址解析和 ping 过程 |
| IPv4 普通报文 | `ip` 或展开 ICMP 报文中的 IPv4 层 | 分析 IP 首部字段 |
| IP 分片 | `icmp || ip.flags.mf == 1 || ip.frag_offset > 0` | 显示 ICMP 大包及其分片 |
| TCP 流 | `tcp.stream eq 75` | 固定分析同一条完整 TCP 连接 |

本实验的分析方法不是只看报文列表，而是结合 Wireshark 的三层视图：上方报文列表用于确定报文序列，中间协议树用于展开字段，下方十六进制视图用于确认报文原始字节。正文重点采用“报文序列 + 字段表 + 机制解释”的方式组织。

## 2.4 抓包数据与材料组织

实验材料主要包括两类：一类是 `.pcapng` 原始抓包文件，保留完整报文数据，便于复现分析；另一类是 `image` 目录中的截图，用于报告正文引用。原始抓包文件包括 `阶段二数据.pcapng`、`阶段四ARP.pcapng`、`阶段四ICMP.pcapng` 和 `阶段六.pcapng`，分别对应 DHCP、ARP、ICMP 和 IP 分片实验。

---

# 3 协议基础与实验分析框架

## 3.1 TCP/IP 协议栈中的实验对象

本实验涉及的协议分布在 TCP/IP 协议体系的不同层次：

| 层次 | 协议 | 本实验中的作用 |
|---|---|---|
| 应用层 | HTTP | 通过 GET 请求和 200 OK 响应体现应用层数据交换 |
| 传输层 | TCP | 为 HTTP 通信提供面向连接、可靠、有序的字节流传输 |
| 网络层 | IPv4 | 提供主机到主机的逻辑寻址，并负责分片相关处理 |
| 网络层 | ICMP | 支撑 ping 连通性测试，并作为大包分片实验的承载数据 |
| 网络层/链路层辅助协议 | ARP | 将同一局域网内的下一跳 IP 地址解析为 MAC 地址 |
| 应用层/网络配置协议 | DHCP | 为主机动态分配 IP 地址、默认网关、DNS 等参数 |
| 数据链路层 | Ethernet II | 承载上层 IP/ARP 报文，在局域网中以 MAC 地址转发 |

虽然 DHCP 通常归入应用层协议，但在本实验任务中它用于观察主机连接 Internet 过程中产生的关键网络配置报文；ARP 虽不属于 IPv4 数据报本身，却是 IPv4 在局域网中转发时不可缺少的地址解析机制。

## 3.2 从上网过程理解本实验主线

本实验可以抽象为如下主线：

```text
主机连接 WLAN
  ↓
DHCP 获取 IP 地址、网关、DNS 等网络参数
  ↓
ARP 解析网关或局域网目标的 MAC 地址
  ↓
ICMP Echo Request/Reply 验证网络连通性
  ↓
大包 ping 触发 IPv4 分片，观察 MF 与 Fragment Offset
  ↓
访问 HTTP 站点产生 TCP 连接
  ↓
TCP 三次握手 → HTTP 数据传输 → TCP 连接拆除
```

从这个角度看，DHCP、ARP、ICMP、IPv4 分片和 TCP 并不是相互割裂的实验对象，而是同一次网络接入和通信过程中的不同环节。后续章节将按照这一顺序展开分析。

---

# 4 DHCP 报文捕获与地址获取过程分析

## 4.1 实验操作

DHCP 报文通常只在主机申请、续租或释放地址时明显出现。为了主动触发 DHCP 过程，本实验在 Wireshark 开始捕获后，先在命令行执行：

```bash
ipconfig /release
```

释放当前已获得的 IPv4 地址，然后执行：

```bash
ipconfig /renew
```

重新申请地址。在 Wireshark 中设置显示过滤器：

```text
udp.port == 68
```

由于 DHCP 客户端使用 UDP 68 端口，服务器使用 UDP 67 端口，该过滤器可以较好地显示主机侧 DHCP 报文。

> **图 4-1 插图占位：执行 `ipconfig /release` 释放地址**  
> 建议插入图片：`image/阶段二CMD-1.png`  
> 图片描述：展示在 Windows 命令行中执行 `ipconfig /release` 后，WLAN 接口释放 IPv4 地址的过程，是触发 DHCP 地址重新申请的前置步骤。

> **图 4-2 插图占位：执行 `ipconfig /renew` 重新申请地址**  
> 建议插入图片：`image/阶段二CMD-2.png`  
> 图片描述：展示在 Windows 命令行中执行 `ipconfig /renew` 后，主机重新从 DHCP 服务器获取网络配置的过程。

## 4.2 DHCP 报文序列总览

在 DHCP 过滤结果中，可以观察到一次地址释放和一次完整地址申请过程。抓包列表如下：

| 帧号 | 源地址 | 目的地址 | 协议 | 长度 | DHCP 类型 | Transaction ID | 作用 |
|---:|---|---|---|---:|---|---|---|
| 39 | 10.21.213.119 | 10.3.9.2 | DHCP | 342 | Release | 0x54112bdf | 客户端释放原有地址 |
| 40 | 0.0.0.0 | 255.255.255.255 | DHCP | 344 | Discover | 0xf18cd434 | 客户端广播寻找 DHCP 服务器 |
| 41 | 10.3.9.2 | 10.21.213.119 | DHCP | 342 | Offer | 0xf18cd434 | 服务器提供可用地址 |
| 42 | 0.0.0.0 | 255.255.255.255 | DHCP | 370 | Request | 0xf18cd434 | 客户端请求使用该地址 |
| 43 | 10.3.9.2 | 10.21.213.119 | DHCP | 342 | ACK | 0xf18cd434 | 服务器确认租约并下发配置 |

> **图 4-3 插图占位：DHCP 报文列表**  
> 建议插入图片：`image/阶段二.png`  
> 图片描述：展示 `udp.port == 68` 过滤后的 DHCP 报文序列，包括 Release、Discover、Offer、Request 和 ACK 报文，可用于说明 DHCP 地址释放和重新申请过程。

其中，帧 40—43 使用相同的 Transaction ID `0xf18cd434`，说明它们属于同一次 DHCP 地址申请会话。客户端在 Discover 和 Request 阶段源地址为 `0.0.0.0`，目的地址为 `255.255.255.255`，这是因为客户端尚未完成地址配置，需要通过广播方式与 DHCP 服务器通信。服务器返回 Offer 和 ACK 后，客户端获得地址 `10.21.213.119` 以及其他网络参数。

> **图 4-4 插图占位：DHCP ACK 报文总览与字段展开**  
> 建议插入图片：`image/阶段二-2.png`  
> 图片描述：展示 DHCP ACK 报文在 Wireshark 中的列表位置和 BOOTP/DHCP 协议字段展开，是分析 ACK 报文结构的辅助图。

## 4.3 DHCP ACK 关键字段解析

DHCP ACK 是 DHCP 服务器对客户端地址申请的最终确认。实验中 ACK 报文字段如下：

| 字段 | 实验观察值 | 含义 |
|---|---|---|
| Message Type | DHCP ACK | 服务器确认客户端可以使用该租约 |
| Transaction ID | 0xf18cd434 | 标识本次 DHCP 地址申请会话 |
| Your client IP address | 10.21.213.119 | DHCP 服务器分配给客户端的 IPv4 地址 |
| Client MAC address | d4:f3:2d:97:c7:4b | 客户端无线网卡 MAC 地址 |
| DHCP Server Identifier | 10.3.9.2 | 提供租约的 DHCP 服务器 |
| IP Address Lease Time | 1 hour，3600 seconds | 地址租约时长 |
| Subnet Mask | 255.255.128.0 | 本机所在网络的子网掩码 |
| Router | 10.21.128.1 | 默认网关地址 |
| Domain Name Server | 10.3.9.5、10.3.9.4、10.3.9.6 | DNS 服务器地址 |

> **图 4-5 插图占位：DHCP ACK 详细字段**  
> 建议插入图片：`image/阶段三-1.png`  
> 图片描述：展示 DHCP ACK 报文的 Options 字段，包括 DHCP Message Type、Server Identifier、Lease Time、Subnet Mask、Router 和 DNS Server，是分析 DHCP 参数下发过程的主要依据。

## 4.4 DHCP 过程分析

DHCP 的核心作用是让客户端在不知道自身网络参数的情况下，通过广播和服务器响应自动完成网络配置。实验中可以观察到如下特点：

首先，客户端释放地址时，已经拥有 IP 地址 `10.21.213.119`，因此 Release 报文可以直接发往 DHCP 服务器 `10.3.9.2`。其次，在重新申请地址时，客户端尚未确认可以使用哪个地址，所以 Discover 和 Request 报文使用 `0.0.0.0` 作为源地址，并以 `255.255.255.255` 作为目的地址进行广播。最后，服务器通过 Offer 提供地址，再通过 ACK 确认该地址租约，同时下发网关、DNS 和子网掩码等信息。

DHCP 过程完成后，主机获得了进行后续网络通信所必需的配置：IP 地址用于网络层寻址，子网掩码用于判断目标是否在同一网段，默认网关用于跨网段转发，DNS 服务器用于域名解析。这些参数为后续 ARP、ICMP 和 TCP 通信奠定了基础。

---

# 5 ARP 报文捕获与局域网地址解析分析

## 5.1 实验操作与过滤器

在完成 DHCP 地址配置后，主机具备了发送 IP 数据报的基本条件。但在以太网环境中，实际发送帧还需要知道下一跳设备的 MAC 地址。因此，本实验执行 ping 命令，并在 Wireshark 中使用如下过滤器观察 ARP 和 ICMP 报文：

```text
arp || icmp
```

该过滤器可以同时展示 ARP 地址解析过程和随后的 ICMP Echo Request/Reply 报文，便于观察二者之间的关系。

> **图 5-1 插图占位：ARP 与 ICMP 过滤结果**  
> 建议插入图片：``image/阶段四-Wireshark 中 `arp.png``  
> 图片描述：展示使用 `arp || icmp` 过滤器后，Wireshark 中同时出现 ARP 和 ICMP 报文的结果，用于说明 ping 过程中地址解析和连通性测试的关系。

## 5.2 ARP 请求与应答过程

在抓包结果中，观察到网关与本机之间的 ARP 交互。关键报文如下：

| 帧号 | 源 | 目的 | 协议 | 长度 | Info | 说明 |
|---:|---|---|---|---:|---|---|
| 196 | HewlettPacka_6c:24:00 | Intel_97:c7:4b | ARP | 60 | Who has 10.21.213.119? Tell 10.21.128.1 | 网关询问本机 IP 对应的 MAC 地址 |
| 197 | Intel_97:c7:4b | HewlettPacka_6c:24:00 | ARP | 42 | 10.21.213.119 is at d4:f3:2d:97:c7:4b | 本机回复自己的 MAC 地址 |

> **图 5-2 插图占位：ARP 请求与应答报文列表**  
> 建议插入图片：`image/阶段四ARP截获.png`  
> 图片描述：展示 ARP Request 和 ARP Reply 报文，其中可见 “Who has 10.21.213.119? Tell 10.21.128.1” 以及 “10.21.213.119 is at d4:f3:2d:97:c7:4b”。

从报文含义看，`10.21.128.1` 是默认网关，`10.21.213.119` 是本机地址。网关需要将发往本机的以太网帧投递到正确的 MAC 地址，因此通过 ARP 查询本机 IP 地址对应的 MAC 地址。本机随后回复自身 MAC 地址 `d4:f3:2d:97:c7:4b`。

## 5.3 ARP Reply 详细字段解析

对第 197 帧 ARP Reply 报文展开后，可以看到如下字段：

| 字段 | 实验观察值 | 含义 |
|---|---|---|
| Hardware type | Ethernet (1) | 硬件类型为以太网 |
| Protocol type | IPv4 (0x0800) | 被解析的协议地址类型为 IPv4 |
| Hardware size | 6 | MAC 地址长度为 6 字节 |
| Protocol size | 4 | IPv4 地址长度为 4 字节 |
| Opcode | reply (2) | 当前报文为 ARP 应答 |
| Sender MAC address | d4:f3:2d:97:c7:4b | 应答方，即本机 MAC 地址 |
| Sender IP address | 10.21.213.119 | 应答方，即本机 IP 地址 |
| Target MAC address | 10:4f:58:6c:24:00 | 查询方，即网关 MAC 地址 |
| Target IP address | 10.21.128.1 | 查询方，即默认网关 IP 地址 |

> **图 5-3 插图占位：ARP Reply 详细字段**  
> 建议插入图片：`image/阶段四ARP 详细字段截图.png`  
> 图片描述：展示第 197 帧 ARP Reply 的详细字段，包括硬件类型、协议类型、Opcode、Sender MAC/IP 和 Target MAC/IP，可用于验证 ARP 报文格式。

## 5.4 ARP 作用总结

ARP 的作用可以概括为：在已知目标 IP 或下一跳 IP 的情况下，获得对应的 MAC 地址，从而让 IP 数据报能够被封装进以太网帧并在局域网中发送。IP 层解决“到哪个主机或下一跳”的问题，以太网层解决“发给哪个 MAC 地址”的问题，ARP 则是二者之间的桥梁。

本实验中的 ARP 交互表明，本机和网关之间的通信不仅依赖 IP 地址，还依赖链路层 MAC 地址映射。如果没有 ARP 或 ARP 缓存中的映射关系，主机即使知道网关 IP，也无法在以太网中正确发送帧。

---

# 6 ICMP 报文捕获与 ping 过程分析

## 6.1 ICMP Echo Request/Reply 报文序列

ping 命令使用 ICMP Echo Request 和 Echo Reply 报文测试网络连通性。在实验中，本机 `10.21.213.119` 向默认网关 `10.21.128.1` 发送 ICMP Echo Request，网关返回 Echo Reply。部分报文如下：

| 帧号 | 源地址 | 目的地址 | 协议 | 长度 | Info | 说明 |
|---:|---|---|---|---:|---|---|
| 592 | 10.21.213.119 | 10.21.128.1 | ICMP | 74 | Echo request，ttl=128 | 本机向网关发送 ping 请求 |
| 593 | 10.21.128.1 | 10.21.213.119 | ICMP | 74 | Echo reply，ttl=64 | 网关返回 ping 应答 |
| 598 | 10.21.213.119 | 10.21.128.1 | ICMP | 74 | Echo request，ttl=128 | 后续 ping 请求 |
| 599 | 10.21.128.1 | 10.21.213.119 | ICMP | 74 | Echo reply，ttl=64 | 后续 ping 应答 |

> **图 6-1 插图占位：ICMP Echo Request/Reply 列表**  
> 建议插入图片：`image/阶段四ARP截获.png`  
> 图片描述：该图同时展示了 ICMP Echo Request/Reply 和 ARP 报文，可用于说明 ping 过程中 ICMP 请求与应答的基本方向和序列。

## 6.2 ICMP 请求报文字段解析

对第 592 帧 ICMP Echo Request 展开后，可以看到其由 Ethernet II、IPv4 和 ICMP 三层结构组成。IPv4 层源地址为 `10.21.213.119`，目的地址为 `10.21.128.1`，上层协议为 ICMP。ICMP 层字段如下：

| 字段 | 实验观察值 | 含义 |
|---|---|---|
| Type | 8 | Echo Request，请求报文 |
| Code | 0 | Echo Request 的代码字段为 0 |
| Identifier | 0x0001 | 标识同一次 ping 会话 |
| Sequence Number | 1/256 或后续递增值 | 区分同一会话中的不同请求 |
| Data | 32 bytes | Windows 默认 ping 数据区长度 |

> **图 6-2 插图占位：ICMP Echo Request 详细字段**  
> 建议插入图片：`image/阶段四arp展开.png`  
> 图片描述：展示 ICMP Echo Request 的详细字段，包括 Type=8、Code=0、Identifier、Sequence Number 和 32 字节数据区。

## 6.3 ICMP 应答报文分析

ICMP Echo Reply 与 Echo Request 的主要区别在于 Type 字段。Echo Request 的 Type 为 8，Echo Reply 的 Type 为 0。实验中 Echo Reply 的源地址和目的地址与请求方向相反，即网关 `10.21.128.1` 返回给本机 `10.21.213.119`。在报文列表中还可以观察到请求报文 TTL 为 128，应答报文 TTL 为 64，这反映了两端设备或操作系统初始 TTL 取值的差异。

> **图 6-3 插图占位：ICMP Echo Request/Reply 详细字段截图**  
> 建议插入图片：`image/阶段四展开 ICMP Echo Request  Reply 详细字段的截图.png`  
> 图片描述：展示 ICMP Echo Request 或 Reply 的协议树展开结果，可用于说明 ICMP 报文被封装在 IPv4 数据报中，以及 Type、Code、Identifier、Sequence Number 等字段的含义。

## 6.4 ping 过程中 ICMP 与 IP 的关系

ping 命令产生的是 ICMP 报文，但 ICMP 不能单独在链路上传输，而是需要封装在 IPv4 数据报中。实验中第 592 帧的封装关系为：

```text
Ethernet II
  └── Internet Protocol Version 4
        └── Internet Control Message Protocol
```

其中，Ethernet II 层负责局域网帧传输，IPv4 层负责源主机到目的主机的逻辑寻址，ICMP 层提供 Echo Request/Reply 的连通性测试语义。通过该结构可以看出，ping 的结果不仅反映 ICMP 层是否收到应答，也依赖底层 ARP、以太网帧转发和 IPv4 路由是否正常。

---

# 7 普通 IPv4 数据分组结构分析

## 7.1 样例报文选取

本节选取第 592 帧 ICMP Echo Request 中的 IPv4 数据报作为普通 IPv4 数据分组样例。该报文没有发生分片，便于观察 IPv4 首部基本字段。其整体封装长度为 74 字节，其中以太网帧头 14 字节，IPv4 数据报总长度为 60 字节。

> **图 7-1 插图占位：普通 IPv4 数据分组字段截图**  
> 建议插入图片：`image/阶段五 IPv4 普通数据分组截图.png`  
> 图片描述：展示普通 IPv4 数据分组的协议树字段，包括 Version、Header Length、Total Length、Identification、Flags、Fragment Offset、TTL、Protocol、Source Address 和 Destination Address。

## 7.2 IPv4 首部字段解析

第 592 帧 IPv4 首部字段如下：

| 字段 | 实验观察值 | 含义 |
|---|---|---|
| Version | 4 | 使用 IPv4 协议 |
| Header Length | 20 bytes | IPv4 首部长度为 20 字节，没有额外选项 |
| Differentiated Services Field | 0x00 | 普通服务类型，无特殊 DSCP/ECN 标记 |
| Total Length | 60 | IPv4 数据报总长度为 60 字节 |
| Identification | 0x97f4，38900 | 用于标识 IP 数据报，分片重组时使用 |
| Flags | 0x0 | 未设置 DF/MF 标志 |
| Fragment Offset | 0 | 当前报文未发生分片 |
| Time to Live | 128 | 生存时间，防止报文在网络中无限循环 |
| Protocol | ICMP (1) | 上层承载协议为 ICMP |
| Header Checksum | 0x0000，validation disabled | Wireshark 未验证或网卡卸载导致显示未校验 |
| Source Address | 10.21.213.119 | 本机 IP 地址 |
| Destination Address | 10.21.128.1 | 默认网关 IP 地址 |

## 7.3 IPv4 字段含义分析

IPv4 首部中的 Total Length 表示整个 IP 数据报长度，包括 IP 首部和 IP 载荷。该报文 Total Length 为 60 字节，其中 IP 首部为 20 字节，剩余 40 字节为 ICMP 报文。由于 ICMP Echo Request 包含 8 字节 ICMP 首部和 32 字节数据区，因此可以得到：

```text
IPv4 Total Length = IPv4 Header Length + ICMP Header + ICMP Data
                  = 20 + 8 + 32
                  = 60 bytes
```

该计算与 Wireshark 显示的 Total Length 一致。

Flags 和 Fragment Offset 用于 IP 分片。该普通报文中 Flags 为 0x0，MF 未设置，Fragment Offset 为 0，说明该数据报没有被分片。TTL 为 128，表示报文每经过一个路由器 TTL 减 1，当 TTL 变为 0 时被丢弃，从而避免路由环路导致报文无限存在。Protocol 字段为 ICMP (1)，说明 IP 载荷应交给 ICMP 模块处理。

---

# 8 大 IP 数据分组分片传输过程分析

## 8.1 实验操作与分片触发条件

为了观察 IPv4 分片，本实验使用 Windows ping 命令构造较大的 ICMP 数据报：

```bash
ping -4 -l 8000 www.bupt.edu.cn
```

其中，`-4` 指定使用 IPv4，`-l 8000` 指定 ICMP 数据部分长度为 8000 字节。常见以太网 MTU 为 1500 字节，而 IP 数据报还需要包含 20 字节 IPv4 首部。一个不含 IP 选项的 IPv4 分片在以太网上最多可承载的数据部分为：

```text
每个非最后分片的 IP 载荷 = 1500 - 20 = 1480 bytes
```

由于 ICMP Echo Request 的数据部分为 8000 字节，ICMP 首部为 8 字节，因此需要被 IP 层承载的 ICMP 报文总长度为：

```text
ICMP 总长度 = ICMP Header + ICMP Data = 8 + 8000 = 8008 bytes
```

8008 字节远大于单个 IP 数据报在该链路上的可承载载荷，因此会触发 IPv4 分片。

> **图 8-1 插图占位：大包 ping 命令执行结果**  
> 建议插入图片：`image/阶段六CMD执行结果.png`  
> 图片描述：展示执行 `ping -4 -l 8000 www.bupt.edu.cn` 的命令行结果，用于说明实验通过大数据区 ICMP 报文触发 IPv4 分片。

## 8.2 分片报文列表观察

在 Wireshark 中使用过滤器：

```text
icmp || ip.flags.mf == 1 || ip.frag_offset > 0
```

可以观察到多个 `Fragmented IP protocol (proto=ICMP 1, ...)` 报文。这说明 Wireshark 捕获到了同一个 ICMP Echo Request 被拆分后的多个 IPv4 分片，以及对应 Echo Reply 的分片。以第 3251—3256 帧为例，它们属于同一个从本机 `10.21.213.119` 发往 `10.3.19.2` 的 ICMP 请求分片组，Identification 为 `0xc689`。

> **图 8-2 插图占位：IP 分片报文列表**  
> 建议插入图片：`image/阶段六Wireshark 中 IP 分片报文列表.png`  
> 图片描述：展示 Wireshark 中 IP 分片报文列表，可见多个 `Fragmented IP protocol (proto=ICMP 1)` 报文以及最后重组出的 ICMP Echo Request/Reply 报文。

## 8.3 单个分片组字段分析

选取帧 3251—3256 这一组分片进行分析。Wireshark 中显示的 Length 列为以太网帧长度，包括 14 字节以太网头；IP 层的 Total Length 则不包含以太网头。

| 帧号 | 源地址 | 目的地址 | 以太网帧长度 | IP Total Length | Fragment Offset | MF | IP 载荷长度 | 说明 |
|---:|---|---|---:|---:|---:|---:|---:|---|
| 3251 | 10.21.213.119 | 10.3.19.2 | 1514 | 1500 | 0 | 1 | 1480 | 第一个分片 |
| 3252 | 10.21.213.119 | 10.3.19.2 | 1514 | 1500 | 1480 | 1 | 1480 | 中间分片 |
| 3253 | 10.21.213.119 | 10.3.19.2 | 1514 | 1500 | 2960 | 1 | 1480 | 中间分片 |
| 3254 | 10.21.213.119 | 10.3.19.2 | 1514 | 1500 | 4440 | 1 | 1480 | 中间分片 |
| 3255 | 10.21.213.119 | 10.3.19.2 | 1514 | 1500 | 5920 | 1 | 1480 | 中间分片 |
| 3256 | 10.21.213.119 | 10.3.19.2 | 642 | 628 | 7400 | 0 | 608 | 最后一个分片 |

第一个分片的 IP Total Length 为 1500，Fragment Offset 为 0，MF 标志位为 1，表示该分片从原始 IP 载荷起始位置开始，且后续还有更多分片。最后一个分片的 IP Total Length 为 628，Fragment Offset 为 7400，MF 标志位为 0，表示这是该原始数据报的最后一个分片。

> **图 8-3 插图占位：第一个 IP 分片详细字段**  
> 建议插入图片：`image/阶段六第一个 IP 分片详细字段.png`  
> 图片描述：展示帧 3251 的 IPv4 字段，可见 Total Length=1500、Identification=0xc689、More fragments=Set、Fragment Offset=0、Protocol=ICMP、Data=1480 bytes。

> **图 8-4 插图占位：最后一个 IP 分片详细字段**  
> 建议插入图片：`image/阶段六最后一个 IP 分片详细字段.png`  
> 图片描述：展示帧 3256 的 IPv4 字段，可见 Total Length=628、Identification=0xc689、More fragments=Not set、Fragment Offset=7400，并显示该数据报由多个 IPv4 分片重组而成。

## 8.4 分片长度与 Fragment Offset 计算

从计算角度验证分片结果：

```text
原始 ICMP 报文总长度 = 8000 + 8 = 8008 bytes
非最后分片载荷长度 = 1500 - 20 = 1480 bytes
前 5 个分片载荷总和 = 1480 × 5 = 7400 bytes
最后一个分片载荷长度 = 8008 - 7400 = 608 bytes
最后一个分片 IP Total Length = 20 + 608 = 628 bytes
最后一个分片以太网帧长度 = 14 + 628 = 642 bytes
```

这与 Wireshark 中第一片帧长度 1514、IP Total Length 1500，以及最后一片帧长度 642、IP Total Length 628 的观察结果一致。

Fragment Offset 字段用于指示当前分片数据在原始 IP 载荷中的位置。Wireshark 显示的偏移量为字节偏移，因此分片 Offset 依次为 0、1480、2960、4440、5920 和 7400。由于 IPv4 首部中的 Fragment Offset 实际以 8 字节为单位编码，所以除最后一片外，每个分片的数据长度必须是 8 的整数倍。1480 能被 8 整除，因此符合 IPv4 分片要求。

## 8.5 IP 分片机制总结

IPv4 分片机制依赖三个关键字段：Identification、MF 和 Fragment Offset。Identification 用于让接收方判断哪些分片属于同一个原始 IP 数据报；MF 表示后面是否还有更多分片；Fragment Offset 表示该分片在原始数据报中的相对位置。接收端只有在收到同一 Identification 下所有分片后，才能根据 Offset 将其重组为完整数据报。

本实验通过大包 ping 直观验证了 IPv4 分片机制。分片能够让较大的 IP 数据报通过 MTU 较小的链路，但也会带来额外开销和风险：如果任意一个分片丢失，接收端就无法正确重组整个原始数据报。因此，在实际网络中，减少不必要的分片通常有助于提高传输效率和可靠性。

---

# 9 TCP 流选择与整体通信过程概览

## 9.1 TCP 流筛选方法

访问网页或系统进行网络连通性检测时，主机可能同时产生多条 TCP 连接。为了避免将不同连接的报文混在一起分析，本实验选择一条完整 TCP 流，并使用如下过滤器固定观察对象：

```text
tcp.stream eq 75
```

该 TCP 流的通信双方为：

| 角色 | IP 地址 | TCP 端口 |
|---|---|---:|
| 客户端 | 10.21.213.119 | 33481 |
| 服务器 | 23.212.62.78 | 80 |

端口 80 表明该连接用于 HTTP 通信。该 TCP 流中可以连续观察到三次握手、HTTP GET 请求、HTTP/1.1 200 OK 响应，以及后续 FIN/ACK 连接拆除过程。

> **图 9-1 插图占位：TCP Stream 75 报文列表**  
> 建议插入图片：`image/阶段八TCP Stream 报文列表.png`  
> 图片描述：展示 `tcp.stream eq 75` 过滤结果，包括 TCP 三次握手、HTTP GET、HTTP 200 OK、FIN/ACK 和最终 ACK，是后续 TCP 分析的总览图。

## 9.2 TCP 流全过程时间线

该 TCP 流可分为三个阶段：建立连接、数据通信和连接拆除。

| 阶段 | 典型帧号 | 方向 | 报文类型 | 作用 |
|---|---:|---|---|---|
| 建立连接 | 1786 | 客户端 → 服务器 | SYN | 客户端请求建立 TCP 连接 |
| 建立连接 | 1791 | 服务器 → 客户端 | SYN, ACK | 服务器确认请求并同步自己的初始序列号 |
| 建立连接 | 1793 | 客户端 → 服务器 | ACK | 客户端确认服务器初始序列号，连接建立完成 |
| 数据通信 | 1795 | 客户端 → 服务器 | HTTP GET | 客户端请求 `/connecttest.txt` |
| 数据通信 | 1803 | 服务器 → 客户端 | ACK | 服务器确认收到客户端 111 字节请求数据 |
| 数据通信 | 1805 | 服务器 → 客户端 | HTTP/1.1 200 OK | 服务器返回文本响应 |
| 连接拆除 | 1807 | 服务器 → 客户端 | FIN, ACK | 服务器发起关闭连接 |
| 连接拆除 | 1809 | 客户端 → 服务器 | ACK | 客户端确认服务器 FIN |
| 连接拆除 | 1811 | 客户端 → 服务器 | FIN, ACK | 客户端关闭自己的发送方向 |
| 连接拆除 | 1835 | 服务器 → 客户端 | ACK | 服务器最终确认，连接释放完成 |

从整个时间线可以看出，TCP 连接具有明确的状态转换过程。三次握手用于建立双方通信状态，数据传输阶段通过 Seq/Ack 保证字节流可靠传输，连接拆除阶段通过 FIN/ACK 分别关闭两个方向的数据流。

---

# 10 TCP 三次握手过程分析

## 10.1 三次握手报文列表

TCP 建立连接需要三次握手。实验中该过程由帧 1786、1791 和 1793 完成：

| 次序 | 帧号 | 源 | 目的 | 标志位 | Seq | Ack | Len | 说明 |
|---|---:|---|---|---|---:|---:|---:|---|
| 第一次握手 | 1786 | 10.21.213.119:33481 | 23.212.62.78:80 | SYN | 0 | — | 0 | 客户端请求建立连接 |
| 第二次握手 | 1791 | 23.212.62.78:80 | 10.21.213.119:33481 | SYN, ACK | 0 | 1 | 0 | 服务器确认客户端 SYN，并发送自己的 SYN |
| 第三次握手 | 1793 | 10.21.213.119:33481 | 23.212.62.78:80 | ACK | 1 | 1 | 0 | 客户端确认服务器 SYN，连接建立完成 |

> **图 10-1 插图占位：TCP 三次握手报文列表**  
> 建议插入图片：`image/阶段九三次握手报文列表.png`  
> 图片描述：展示 TCP Stream 75 中前三条握手报文，分别为客户端 SYN、服务器 SYN/ACK 和客户端 ACK。

## 10.2 第一次握手：SYN 报文解析

第一次握手由客户端 `10.21.213.119:33481` 发往服务器 `23.212.62.78:80`。该报文只设置 SYN 标志位，表示客户端希望建立 TCP 连接并同步初始序列号。

关键字段如下：

| 字段 | 实验观察值 | 含义 |
|---|---|---|
| Source Port | 33481 | 客户端临时端口 |
| Destination Port | 80 | HTTP 服务端口 |
| Sequence Number | 0，相对序号 | 客户端初始序列号的相对表示 |
| Acknowledgment Number | 0 | 第一次握手中 ACK 标志未置位，确认号无效 |
| Flags | 0x002，SYN | 请求建立连接 |
| Window | 65535 | 客户端接收窗口 |
| MSS | 1460 | 客户端声明最大报文段长度 |
| Window Scale | 256 | 窗口扩大因子 |
| SACK Permitted | 存在 | 支持选择确认 |

> **图 10-2 插图占位：第一次握手 SYN 详细字段**  
> 建议插入图片：`image/阶段九第一次握手 SYN 报文详细字段.png`  
> 图片描述：展示帧 1786 的 TCP 详细字段，重点体现 SYN 标志位、源端口 33481、目的端口 80、Seq=0、Window、MSS、SACK 等选项。

第一次握手虽然不携带应用层数据，但 SYN 会消耗一个序号。因此服务器在第二次握手中的确认号为 1，表示期望客户端下一个发送的字节序号为 1。

## 10.3 第二次握手：SYN/ACK 报文解析

第二次握手由服务器 `23.212.62.78:80` 返回给客户端 `10.21.213.119:33481`。该报文同时设置 SYN 和 ACK 标志位，一方面确认客户端的 SYN，另一方面发送服务器自己的初始序列号。

关键字段如下：

| 字段 | 实验观察值 | 含义 |
|---|---|---|
| Source Port | 80 | HTTP 服务端口 |
| Destination Port | 33481 | 客户端临时端口 |
| Sequence Number | 0，相对序号 | 服务器初始序列号的相对表示 |
| Acknowledgment Number | 1 | 确认客户端 SYN，占用一个序号 |
| Flags | 0x012，SYN, ACK | 同步序列号并确认客户端请求 |
| Window | 64240 | 服务器接收窗口 |
| MSS | 1386 | 服务器声明最大报文段长度 |
| Window Scale | 128 | 窗口扩大因子 |
| SACK Permitted | 存在 | 支持选择确认 |

> **图 10-3 插图占位：第二次握手 SYN/ACK 详细字段**  
> 建议插入图片：`image/阶段九第二次握手 SYN ACK 报文详细字段.png`  
> 图片描述：展示帧 1791 的 TCP 详细字段，重点体现 Flags=0x012、SYN 和 ACK 均被置位、Seq=0、Ack=1，以及服务器端 TCP 选项。

## 10.4 第三次握手：ACK 报文解析

第三次握手由客户端再次发往服务器，用于确认服务器的 SYN。该报文只设置 ACK 标志位，不携带应用层数据。

关键字段如下：

| 字段 | 实验观察值 | 含义 |
|---|---|---|
| Source Port | 33481 | 客户端临时端口 |
| Destination Port | 80 | 服务器 HTTP 端口 |
| Sequence Number | 1 | 客户端 SYN 已占用一个序号 |
| Acknowledgment Number | 1 | 确认服务器 SYN 已收到 |
| Flags | 0x010，ACK | 确认报文 |
| TCP Len | 0 | 不携带应用层数据 |

> **图 10-4 插图占位：第三次握手 ACK 详细字段**  
> 建议插入图片：`image/阶段九第三次握手  ACK 报文详细字段.png`  
> 图片描述：展示帧 1793 的 TCP 详细字段，重点体现 ACK 标志位、Seq=1、Ack=1、Len=0，说明 TCP 连接建立完成。

## 10.5 三次握手机制总结

三次握手的本质是双方同步初始序列号并确认彼此具备发送和接收能力。第一次握手证明客户端可以发送，第二次握手证明服务器可以接收客户端报文并可以发送，第三次握手证明客户端可以接收服务器报文。至此，双方都知道对方的初始序列号，后续应用层数据就可以作为 TCP 字节流进行传输。

需要注意的是，SYN 虽然不携带应用数据，但会消耗一个序号。因此第一次握手后服务器确认号为 1，第二次握手后客户端确认号也为 1。这一规律在后续 FIN 报文中同样适用。

---

# 11 TCP 数据通信与 HTTP 报文分析

## 11.1 数据通信报文列表

TCP 连接建立后，客户端立即发送 HTTP GET 请求，请求路径为 `/connecttest.txt`，服务器随后返回 HTTP/1.1 200 OK 响应。该过程的关键报文如下：

| 帧号 | 方向 | 协议 | 长度 | TCP 信息 | 说明 |
|---:|---|---|---:|---|---|
| 1795 | 客户端 → 服务器 | HTTP | 165 | `Seq=1 Ack=1 Len=111` | HTTP GET 请求 |
| 1803 | 服务器 → 客户端 | TCP | 60 | `Seq=1 Ack=112 Len=0` | 确认收到客户端请求 |
| 1805 | 服务器 → 客户端 | HTTP | 241 | `Seq=1 Ack=112 Len=187` | HTTP/1.1 200 OK 响应 |
| 1807 | 服务器 → 客户端 | TCP | 60 | `FIN, ACK Seq=188 Ack=112 Len=0` | 服务器开始关闭连接 |

> **图 11-1 插图占位：TCP 数据通信报文列表**  
> 建议插入图片：`image/阶段十TCP 数据通信报文列表.png`  
> 图片描述：展示 TCP Stream 75 中 HTTP GET、服务器 ACK、HTTP 200 OK 以及后续 FIN/ACK 报文，红框部分对应数据通信阶段。

## 11.2 客户端 HTTP GET 请求分析

帧 1795 是客户端发送的 HTTP GET 请求。其 TCP 层源端口为 33481，目的端口为 80，Seq=1，Ack=1，TCP Len=111，表示该 TCP 段携带了 111 字节应用层数据。

HTTP 层关键字段如下：

| 字段 | 实验观察值 | 含义 |
|---|---|---|
| Request Method | GET | 请求服务器资源 |
| Request URI | `/connecttest.txt` | 请求的资源路径 |
| HTTP Version | HTTP/1.1 | 使用 HTTP/1.1 协议 |
| Host | `www.msftconnecttest.com` | 请求目标主机名 |
| Connection | close | 请求完成后关闭连接 |
| User-Agent | Microsoft NCSI | 客户端网络连通性检测组件 |
| Full request URI | `http://www.msftconnecttest.com/connecttest.txt` | 完整请求 URI |
| TCP Len | 111 | TCP 段携带的 HTTP 请求数据长度 |

> **图 11-2 插图占位：客户端 HTTP GET 请求详细字段**  
> 建议插入图片：`image/阶段十客户端 HTTP GET 请求报文详细字段.png`  
> 图片描述：展示帧 1795 的 TCP 和 HTTP 字段，包括 GET `/connecttest.txt`、Host、Connection、User-Agent、Full request URI 以及 TCP Len=111。

该 GET 请求体现了 HTTP 报文作为应用层数据被封装在 TCP 中。TCP 不理解 HTTP 语义，只负责可靠地传输字节流；HTTP 层解释这些字节为请求行、请求头和请求体。

## 11.3 服务器 ACK 确认机制分析

帧 1803 是服务器对客户端 GET 请求的 TCP ACK。该报文不携带应用层数据，TCP Len=0，但其 Acknowledgment Number 为 112。由于客户端 GET 报文的相对 Seq=1，Len=111，因此服务器收到该报文后期望客户端下一个字节序号为：

```text
Ack = Seq + Len = 1 + 111 = 112
```

这与 Wireshark 中显示的 Ack=112 完全一致，说明 TCP 的确认号表示“期望收到的下一个字节序号”，而不是已经收到的最后一个字节序号。

> **图 11-3 插图占位：第 1803 帧 ACK 确认报文**  
> 建议插入图片：`image/阶段十第 1803 帧 ACK 确认报文.png`  
> 图片描述：展示服务器返回的纯 ACK 报文，重点体现 Seq=1、Ack=112、Len=0，用于说明 TCP 确认号与数据长度的关系。

## 11.4 服务器 HTTP 200 OK 响应分析

帧 1805 是服务器返回的 HTTP 响应，状态行为 `HTTP/1.1 200 OK`，说明客户端请求成功。TCP 层显示该报文 Seq=1，Ack=112，Len=187，表示服务器向客户端发送 187 字节应用层数据。

HTTP 层关键字段如下：

| 字段 | 实验观察值 | 含义 |
|---|---|---|
| Status Line | HTTP/1.1 200 OK | 请求成功 |
| Content-Length | 22 | 响应体长度为 22 字节 |
| Content-Type | text/plain | 响应内容为纯文本 |
| Cache-Control | max-age=30, must-revalidate | 缓存控制策略 |
| Request in frame | 1795 | 对应前面的 GET 请求 |
| Time since request | 约 188.1558 ms | 从请求到响应的时间间隔 |
| TCP Len | 187 | TCP 段携带的 HTTP 响应数据长度 |

> **图 11-4 插图占位：服务器 HTTP 200 OK 响应详细字段**  
> 建议插入图片：`image/阶段十服务器 HTTP 200 OK 响应报文详细字段.png`  
> 图片描述：展示帧 1805 的 HTTP 响应字段，包括 HTTP/1.1 200 OK、Content-Length=22、Content-Type=text/plain、Request in frame=1795 和响应耗时。

服务器响应的 TCP Len=187 大于 Content-Length=22，是因为 TCP 载荷中不仅包含 22 字节响应体，还包含 HTTP 状态行和响应头。Content-Length 只描述响应体长度，不包括 HTTP 头部。

## 11.5 TCP 数据通信总结

TCP 数据通信阶段体现了可靠字节流传输的核心机制：发送方用 Seq 标识当前段中第一个字节的位置，接收方用 Ack 表示希望接收的下一个字节位置。客户端发送 111 字节 GET 请求后，服务器返回 Ack=112；服务器发送 187 字节响应后，其下一个相对序号变为 188。后续连接拆除阶段中服务器 FIN 报文的 Seq=188，正好承接了 HTTP 响应数据的序号范围。

这说明 TCP 的序号空间贯穿整个连接生命周期，握手、数据传输和连接拆除不是孤立事件，而是同一个有序字节流状态机的不同阶段。

---

# 12 TCP 连接拆除过程分析

## 12.1 连接拆除报文列表

HTTP 响应完成后，由服务器一侧首先发起连接关闭。TCP 是全双工协议，两个方向的数据流需要分别关闭，因此优雅释放通常表现为 FIN/ACK、ACK、FIN/ACK、ACK 的过程。本实验中连接拆除相关报文如下：

| 次序 | 帧号 | 方向 | 标志位 | Seq | Ack | Len | 说明 |
|---|---:|---|---|---:|---:|---:|---|
| 第一次 | 1807 | 服务器 → 客户端 | FIN, ACK | 188 | 112 | 0 | 服务器表示不再发送数据 |
| 第二次 | 1809 | 客户端 → 服务器 | ACK | 112 | 189 | 0 | 客户端确认服务器 FIN |
| 第三次 | 1811 | 客户端 → 服务器 | FIN, ACK | 112 | 189 | 0 | 客户端表示不再发送数据 |
| 第四次 | 1835 | 服务器 → 客户端 | ACK | 189 | 113 | 0 | 服务器最终确认客户端 FIN |

> **图 12-1 插图占位：TCP 连接拆除报文列表**  
> 建议插入图片：`image/阶段十一TCP 连接拆除报文列表.png`  
> 图片描述：展示 TCP Stream 75 中连接拆除阶段的四个关键报文：服务器 FIN/ACK、客户端 ACK、客户端 FIN/ACK、服务器最终 ACK。

## 12.2 服务器 FIN/ACK 报文解析

帧 1807 由服务器 `23.212.62.78:80` 发往客户端 `10.21.213.119:33481`，标志位为 FIN, ACK。服务器在此前发送 HTTP 响应时使用了 Seq=1、Len=187，因此其下一个序号为 188。FIN 报文使用 Seq=188，表示服务器已完成数据发送，准备关闭服务器到客户端方向的数据流。

> **图 12-2 插图占位：服务器发送 FIN/ACK 详细字段**  
> 建议插入图片：`image/阶段十一服务器发送 FIN, ACK 报文详细字段.png`  
> 图片描述：展示帧 1807 的 TCP 字段，包括 Seq=188、Ack=112、Flags=0x011(FIN, ACK)，说明服务器主动发起连接关闭。

FIN 与 SYN 一样会消耗一个序号，因此客户端对该 FIN 的确认号应为：

```text
Ack = 188 + 1 = 189
```

## 12.3 客户端 ACK 报文解析

帧 1809 是客户端对服务器 FIN 的确认，标志位为 ACK，Seq=112，Ack=189，Len=0。Ack=189 说明客户端已经收到服务器的 FIN，并确认服务器方向的数据流关闭请求。

> **图 12-3 插图占位：客户端确认服务器关闭请求 ACK**  
> 建议插入图片：`image/阶段十一客户端确认服务器关闭请求的 ACK 报文.png`  
> 图片描述：展示帧 1809 的 TCP 字段，重点体现客户端返回 ACK，Seq=112、Ack=189、Len=0，用于说明 FIN 消耗一个序号。

## 12.4 客户端 FIN/ACK 报文解析

服务器方向关闭后，客户端也需要关闭自己到服务器方向的数据流。帧 1811 由客户端发往服务器，标志位为 FIN, ACK，Seq=112，Ack=189，Len=0。客户端此前发送 GET 请求后下一个序号已经是 112，因此 FIN 使用 Seq=112。

> **图 12-4 插图占位：客户端发送 FIN/ACK 详细字段**  
> 建议插入图片：`image/阶段十一客户端发送 FIN, ACK 报文详细字段.png`  
> 图片描述：展示帧 1811 的 TCP 字段，包括 Seq=112、Ack=189、Flags=0x011(FIN, ACK)，说明客户端关闭自己的发送方向。

同样地，客户端 FIN 也消耗一个序号，因此服务器最终确认号应为：

```text
Ack = 112 + 1 = 113
```

## 12.5 服务器最终 ACK 报文解析

帧 1835 是服务器对客户端 FIN 的最终确认，Seq=189，Ack=113，Len=0。Ack=113 与前一节计算一致，说明服务器确认收到客户端的 FIN。至此，双方发送方向均已关闭，该 TCP 连接完成优雅拆除。

> **图 12-5 插图占位：服务器最终 ACK 详细字段**  
> 建议插入图片：`image/阶段十一服务器最终确认 ACK 报文详细字段.png`  
> 图片描述：展示帧 1835 的 TCP 字段，包括 Seq=189、Ack=113、Flags=ACK，是 TCP 连接拆除完成的最终确认报文。

## 12.6 TCP 拆除机制总结

TCP 连接是全双工的，客户端到服务器、服务器到客户端两个方向可以分别关闭。因此，连接拆除并不是简单的一次请求和一次响应，而是双方分别发送 FIN，并分别收到对方 ACK 的过程。本实验中服务器先发起关闭，客户端确认后再关闭自己的发送方向，最后服务器确认客户端 FIN。通过 Seq/Ack 的变化可以验证：FIN 虽然不携带应用数据，但会消耗一个序号，这一点与 SYN 相同。

---

# 13 实验结果汇总与跨协议关联分析

## 13.1 各协议关键字段汇总

| 协议 | 关键字段或现象 | 实验观察值 | 说明 |
|---|---|---|---|
| DHCP | 地址申请序列 | Discover、Offer、Request、ACK | 客户端通过 DHCP 获取网络配置 |
| DHCP | 分配地址 | 10.21.213.119 | 本机获得的 IPv4 地址 |
| DHCP | 默认网关 | 10.21.128.1 | 后续跨网段通信的下一跳 |
| DHCP | DNS 服务器 | 10.3.9.5、10.3.9.4、10.3.9.6 | 用于域名解析 |
| ARP | Opcode | Request/Reply | 完成 IP-MAC 地址映射 |
| ARP | Sender MAC/IP | d4:f3:2d:97:c7:4b / 10.21.213.119 | 本机回复自身地址映射 |
| ICMP | Type | 8 / 0 | Echo Request / Echo Reply |
| IPv4 | Total Length | 60 | 普通 ICMP 报文的 IP 总长度 |
| IPv4 | TTL | 请求 128，应答 64 | 不同方向报文的 TTL 取值不同 |
| IPv4 分片 | MF | 非最后分片为 1，最后分片为 0 | 表示是否还有后续分片 |
| IPv4 分片 | Fragment Offset | 0、1480、2960、4440、5920、7400 | 标识每个分片在原始数据报中的位置 |
| TCP | 三次握手 | SYN、SYN/ACK、ACK | 建立可靠连接 |
| TCP | 数据确认 | GET Len=111，ACK=112 | 确认号表示期望的下一个字节序号 |
| TCP | 连接拆除 | FIN/ACK、ACK、FIN/ACK、ACK | 双方分别关闭发送方向 |

## 13.2 从一次上网行为看协议协同

本实验最重要的收获是可以把多个协议放在同一条网络通信链路中理解。DHCP 首先为主机提供 IP 地址、子网掩码、默认网关和 DNS 服务器等基本配置。获得配置后，主机可以判断目的地址是否在本地网络内；如果需要与默认网关通信，则通过 ARP 获得网关或本机对应的 MAC 地址。随后，ICMP Echo Request/Reply 用于验证网络连通性，普通 IPv4 首部字段说明了 IP 数据报如何进行寻址和承载上层协议。当 ICMP 数据区被扩大到 8000 字节时，IPv4 层根据链路 MTU 将其拆分为多个分片，并通过 Identification、MF 和 Fragment Offset 支持接收端重组。最后，在访问 HTTP 服务时，TCP 先完成三次握手，再承载 HTTP GET 与 HTTP 200 OK 报文，并在通信结束后通过 FIN/ACK 完成连接拆除。

因此，一次看似简单的网页访问背后实际包含了从地址配置、链路层寻址、网络层转发、分片处理到传输层可靠通信的完整协议协作过程。

## 13.3 本实验观察到的典型现象

第一，DHCP 申请初期客户端使用 `0.0.0.0` 和广播地址通信，这是因为客户端尚未确认自己可以使用哪个 IP 地址。第二，ARP 报文说明 IP 地址不能直接用于以太网帧转发，必须解析为 MAC 地址后才能在局域网中发送。第三，普通 IPv4 报文未发生分片时，MF 未设置且 Fragment Offset 为 0；而大包 ping 触发分片后，非最后分片 MF=1，最后分片 MF=0。第四，TCP 的序号和确认号贯穿连接生命周期：SYN 和 FIN 都会消耗序号，数据段的确认号按照数据长度递增。第五，HTTP 报文本身只是 TCP 载荷，TCP 通过 Seq/Ack 对这些应用层字节进行可靠传输。

---

# 14 实验中遇到的问题与解决方法

## 14.1 网卡选择问题

实验环境中存在多个网络接口，包括 WLAN、VPN、Loopback、VMware 虚拟网卡和蓝牙网卡。如果选择错误接口，Wireshark 可能无法捕获实际 Internet 通信报文。解决方法是在 Wireshark 启动界面观察各接口流量波形，并结合 `ipconfig` 输出确认实际联网接口。本实验最终选择 WLAN 接口进行抓包。

## 14.2 DHCP 抓包不明显的问题

DHCP 报文不是持续出现的普通流量，如果直接开始抓包，可能无法捕获完整的 Discover/Offer/Request/ACK 过程。解决方法是在 Wireshark 开始捕获后主动执行 `ipconfig /release` 和 `ipconfig /renew`，强制触发地址释放与重新申请过程，并使用 `udp.port == 68` 过滤 DHCP 客户端端口相关报文。

## 14.3 ARP 报文不容易出现的问题

如果主机或网关已有 ARP 缓存，执行 ping 时可能不会立即产生新的 ARP 请求。解决方法包括：等待 ARP 缓存过期、访问新的目标地址、重新连接网络，或者在抓包列表中同时观察与网关相关的 ARP 交互。本实验通过 `arp || icmp` 过滤器同时观察 ARP 和 ICMP，最终捕获到网关查询本机 MAC 以及本机回复的 ARP 报文。

## 14.4 IP 分片不明显的问题

普通 ping 默认数据区较小，不会超过常见以太网 MTU，因此不会触发 IPv4 分片。解决方法是使用 `ping -4 -l 8000 www.bupt.edu.cn` 构造大于 8000 字节的 ICMP 数据报，并通过 `ip.flags.mf == 1 || ip.frag_offset > 0` 过滤分片报文。分析时还需要区分 Wireshark 报文列表中的 Length 列和 IPv4 层 Total Length 字段，前者包含以太网头，后者只表示 IP 数据报长度。

## 14.5 TCP 流筛选问题

访问网页或系统网络检测可能产生多条 TCP 连接，如果只按 `tcp` 或 `http` 过滤，容易把不同连接的报文混在一起。解决方法是在 Wireshark 中选择一条目标 TCP 报文，查看其 TCP Stream 编号，再使用 `tcp.stream eq 75` 固定同一连接。这样可以保证三次握手、HTTP 数据传输和连接拆除属于同一条 TCP 流。

---

# 15 实验总结与个人收获

通过本次实验，我对计算机接入 Internet 和完成一次 TCP/HTTP 通信的过程有了更直观、系统的理解。

在 DHCP 部分，我观察到主机从释放地址到重新获得地址的完整过程，理解了 Discover、Offer、Request、ACK 四类核心报文的作用，也认识到 IP 地址、网关、DNS 等网络参数并非静态存在，而是可以通过 DHCP 动态分配。在 ARP 和 ICMP 部分，我理解了 IP 层地址与以太网 MAC 地址之间的关系：ping 命令虽然表现为 ICMP 请求和应答，但其正常执行依赖于底层链路层地址解析。在 IPv4 分析部分，我掌握了 IPv4 首部中 Total Length、Identification、TTL、Protocol、Flags 和 Fragment Offset 等字段的作用。

IP 分片实验是本次实验中最能体现字段分析能力的部分。通过 `ping -4 -l 8000` 构造大报文后，可以清楚看到原始 8008 字节 ICMP 报文被划分为多个 IP 分片。非最后分片的 IP 载荷长度均为 1480 字节，最后一个分片载荷为 608 字节；MF 标志位和 Fragment Offset 字段共同支持接收端重组。这一过程使我理解到，分片是网络层为了适配链路 MTU 而进行的机制，并且分片虽然解决了大报文传输问题，但也会带来额外开销和丢包风险。

在 TCP 部分，我通过同一条 TCP stream 连续观察了三次握手、HTTP 数据通信和连接拆除过程。三次握手验证了双方初始序列号同步过程，HTTP GET 和 200 OK 说明应用层数据如何封装在 TCP 中传输，ACK=112 等字段则直接验证了确认号等于“期望收到的下一个字节序号”的规则。连接拆除阶段进一步说明 TCP 是全双工连接，双方发送方向需要分别关闭，SYN 和 FIN 都会消耗一个序号。

总体而言，本实验不仅训练了 Wireshark 的使用方法，也训练了从报文列表定位问题、从协议树提取字段、从字段变化推导协议机制的能力。通过将 DHCP、ARP、ICMP、IPv4 分片和 TCP 放在同一条网络通信链路中分析，我对网络协议分层协作和真实上网过程形成了更加完整的认识。

---

# 参考资料

1. 北京邮电大学计算机学院：《计算机网络实验指导书：实验二 IP 和 TCP 数据分组的捕获和解析》。
2. Wireshark 官方文档：Wireshark User's Guide。
3. RFC 791：Internet Protocol。
4. RFC 792：Internet Control Message Protocol。
5. RFC 793：Transmission Control Protocol。
6. RFC 9293：Transmission Control Protocol (TCP)。
7. RFC 2131：Dynamic Host Configuration Protocol。

---

# 附录 A 实验截图索引

| 图号 | 建议图片路径 | 图片用途 |
|---|---|---|
| 图 2-1 | `image/CMD无线网卡参数.png` | 展示 WLAN 网卡 IP、网关、DHCP、DNS 等环境参数 |
| 图 2-2 | `image/Wireshark 网卡选择界面.png` | 展示 Wireshark 选择 WLAN 接口 |
| 图 2-3 | `image/Wireshark 短抓包测试界面.png` | 展示 WLAN 抓包测试结果 |
| 图 4-1 | `image/阶段二CMD-1.png` | 展示执行 `ipconfig /release` |
| 图 4-2 | `image/阶段二CMD-2.png` | 展示执行 `ipconfig /renew` |
| 图 4-3 | `image/阶段二.png` | 展示 DHCP Release、Discover、Offer、Request、ACK 列表 |
| 图 4-4 | `image/阶段二-2.png` | 展示 DHCP ACK 总览与字段展开 |
| 图 4-5 | `image/阶段三-1.png` | 展示 DHCP ACK 的租约、网关、DNS 等字段 |
| 图 5-1 | ``image/阶段四-Wireshark 中 `arp.png`` | 展示 `arp || icmp` 过滤结果 |
| 图 5-2 | `image/阶段四ARP截获.png` | 展示 ARP 请求与应答列表 |
| 图 5-3 | `image/阶段四ARP 详细字段截图.png` | 展示 ARP Reply 详细字段 |
| 图 6-2 | `image/阶段四arp展开.png` | 展示 ICMP Echo Request 详细字段 |
| 图 6-3 | `image/阶段四展开 ICMP Echo Request  Reply 详细字段的截图.png` | 展示 ICMP Echo Request/Reply 字段 |
| 图 7-1 | `image/阶段五 IPv4 普通数据分组截图.png` | 展示普通 IPv4 数据报首部字段 |
| 图 8-1 | `image/阶段六CMD执行结果.png` | 展示大包 ping 命令执行结果 |
| 图 8-2 | `image/阶段六Wireshark 中 IP 分片报文列表.png` | 展示 IP 分片报文列表 |
| 图 8-3 | `image/阶段六第一个 IP 分片详细字段.png` | 展示第一个 IP 分片字段 |
| 图 8-4 | `image/阶段六最后一个 IP 分片详细字段.png` | 展示最后一个 IP 分片字段 |
| 图 9-1 | `image/阶段八TCP Stream 报文列表.png` | 展示 TCP Stream 75 全流程 |
| 图 10-1 | `image/阶段九三次握手报文列表.png` | 展示 TCP 三次握手列表 |
| 图 10-2 | `image/阶段九第一次握手 SYN 报文详细字段.png` | 展示第一次握手 SYN 字段 |
| 图 10-3 | `image/阶段九第二次握手 SYN ACK 报文详细字段.png` | 展示第二次握手 SYN/ACK 字段 |
| 图 10-4 | `image/阶段九第三次握手  ACK 报文详细字段.png` | 展示第三次握手 ACK 字段 |
| 图 11-1 | `image/阶段十TCP 数据通信报文列表.png` | 展示 TCP 数据通信报文列表 |
| 图 11-2 | `image/阶段十客户端 HTTP GET 请求报文详细字段.png` | 展示客户端 HTTP GET 字段 |
| 图 11-3 | `image/阶段十第 1803 帧 ACK 确认报文.png` | 展示服务器 ACK 确认报文 |
| 图 11-4 | `image/阶段十服务器 HTTP 200 OK 响应报文详细字段.png` | 展示服务器 HTTP 200 OK 响应字段 |
| 图 12-1 | `image/阶段十一TCP 连接拆除报文列表.png` | 展示 TCP 连接拆除报文列表 |
| 图 12-2 | `image/阶段十一服务器发送 FIN, ACK 报文详细字段.png` | 展示服务器 FIN/ACK 字段 |
| 图 12-3 | `image/阶段十一客户端确认服务器关闭请求的 ACK 报文.png` | 展示客户端 ACK 字段 |
| 图 12-4 | `image/阶段十一客户端发送 FIN, ACK 报文详细字段.png` | 展示客户端 FIN/ACK 字段 |
| 图 12-5 | `image/阶段十一服务器最终确认 ACK 报文详细字段.png` | 展示服务器最终 ACK 字段 |

---

# 附录 B 抓包文件索引

| 文件名 | 内容 | 对应章节 | 说明 |
|---|---|---|---|
| `阶段二数据.pcapng` | DHCP 报文 | 第 4 章 | 包含 DHCP Release、Discover、Offer、Request、ACK 报文 |
| `阶段四ARP.pcapng` | ARP 报文 | 第 5 章 | 包含 ARP Request/Reply 报文 |
| `阶段四ICMP.pcapng` | ICMP 报文 | 第 6、7 章 | 包含 ping Echo Request/Reply 和普通 IPv4 报文 |
| `阶段六.pcapng` | IP 分片报文 | 第 8 章 | 包含大包 ping 触发的 IPv4 分片与重组报文 |
