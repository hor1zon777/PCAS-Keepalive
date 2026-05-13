# 移动云电脑 PCAS_App 逆向分析报告

> 分析日期：2026-05-12
> 分析者：Claude（基于 jadx 1.5.5 + apktool 3.0.2 + readelf/strings 静态分析）
> 目标样本：`PCAS_App_V3.6.2.v1_260403_release_1f65af1b_arm64_v8a_prod_signed.apk`
> 工作目录：`E:\Desktop\foldder\Code\Claude\ydy`

---

## 0. 一句话结论

这是**中国移动「移动云电脑」**（包名 `com.cmss.cloudcomputer`，应用名"移动云电脑"）的 Android arm64-v8a 生产签名版客户端，本质上是一个 **Flutter 壳应用 + H3C VDI 2.0 C++ SDK + 中兴 ZTE mSPICE 串流栈 + 内嵌 RustDesk plugin** 的"四层套娃"远程桌面客户端，整包通过 **爱加密（Ijiami）SecLLVM 1.7.4.20 VMP + 抽取壳**对 Java 主 DEX 加固保护，原生 .so 与 Flutter 业务代码未单独混淆。

---

## 1. 样本元信息

| 项 | 值 |
|---|---|
| APK 文件名 | `PCAS_App_V3.6.2.v1_260403_release_1f65af1b_arm64_v8a_prod_signed.apk` |
| 文件大小 | 170,297,345 字节 (162.4 MB) |
| MD5 | `d6a7321613ebcde17f8d7783de289042` |
| SHA-256 | `5c2eab18a14ca0139df2774513841cf4baea373ffa8a107a8d30de25b1a1b013` |
| 包名 | `com.cmss.cloudcomputer` |
| 应用名 | 移动云电脑 |
| versionName / versionCode | `V3.6.2.v1` / `260403` |
| compileSdk / targetSdk / minSdk | 34 / 30 / 28 |
| 架构 | arm64-v8a only |
| Flutter 工程内部名 | `pcas_app`（PCAS = PC Access Service / Personal Cloud Access System） |
| 构建 commit | `1f65af1b`（文件名暴露） |
| Git 渠道 | `release` / `prod_signed` |

### 1.1 签名证书

| 项 | 值 |
|---|---|
| Subject / Issuer | `CN=cpa, OU=中国移动通信有限公司, O=中国移动通信有限公司, L=suzhou, ST=jiangsu, C=CN` |
| 序列号 | `c223722` |
| 算法 | SHA256withRSA, RSA-2048 |
| 有效期 | 2021-06-24 ~ **2103-08-14（82 年期，自签）** |
| SHA-1 | `57:52:5B:9E:F2:9E:EB:A5:0C:70:30:1F:F5:CB:AF:93:FD:D2:21:F8` |
| SHA-256 | `B2:F2:01:4E:88:68:C3:83:31:6B:C0:6F:12:F3:8E:72:7C:96:F9:53:B7:31:9B:6D:9F:25:83:C1:09:94:2B:02` |
| CN 含义 | `cpa` = Cloud PC Application；签名实体属于中国移动通信有限公司苏州团队（中国移动云能力中心） |

---

## 2. 整体架构与"协议四层"

```
┌──────────────────────────────────────────────────────────────────┐
│                  UI 层：Flutter（Dart AOT）                       │
│           libapp.so (18.5 MB AOT snapshot) + libflutter.so         │
│      pcas_app/* 673 个 Dart 文件 / 280 个二级模块 / 106 个页面       │
│      使用 Dio + Pigeon Platform Channel + flutter_rust_bridge       │
└──────────────────────────────────────────────────────────────────┘
                              │
       ┌──────────────────────┼────────────────────────────┐
       ▼                      ▼                            ▼
┌──────────────┐    ┌────────────────────┐     ┌───────────────────────┐
│  Java 业务层 │    │  H3C VDI 协议栈      │     │   RustDesk 协议栈     │
│  (爱加密保护) │    │ libcmccsdk →        │     │ assets/rustdesk/      │
│  ijiami.dat  │    │   libVdpServer       │     │   librustdesk.so      │
│  (7.6 MB)    │    │   + libvdcore        │     │ MainService Java JNI  │
│              │    │   → libspice_h3c     │     │ HBBS + Rendezvous     │
│  真实包名:    │    │   + libgstreamer_h3c │     │ /api/oidc/auth ...    │
│  com.cmss.   │    │   + libnebula        │     │                       │
│   cloud-     │    │  com.company.android.│     │ com.carriez.          │
│   computer   │    │   syydn.H3C* JNI     │     │  flutter_hbb.         │
│   .App       │    │                       │     │  MainService JNI      │
│              │    │  中兴 mSPICE 衍生 +   │     │                       │
│              │    │  CMSS/H3C 双定制     │     │                       │
└──────────────┘    └────────────────────┘     └───────────────────────┘
                              │
                              ▼
                  ┌─────────────────────────────┐
                  │  传输/外设/QoE 子模块        │
                  │ libRapPlugins (中兴 RAP)    │
                  │ libQoeInterface (中兴 QoE)  │
                  │ libzxsecrity (中兴 AES-256) │
                  │ libusbredirect* (SPICE USB) │
                  │ libeveusb* (USB/IP)         │
                  │ libgrpc/libcurl/libssl      │
                  │ libavcodec/libavformat ...  │
                  │ FFmpeg + GStreamer + MPV    │
                  └─────────────────────────────┘
```

### 2.1 协议栈分工

| 协议 | 实现 | 用途 |
|---|---|---|
| **gRPC over TLS** | libVdpServer.so | 控制面 RPC（认证/资源/会话/水印策略） |
| **VDP** | H3C 自研虚拟桌面协议（基于 SPICE 改造） | 数据面（桌面像素流/键鼠/音频） |
| **SPICE** | libspice.so + libspice_h3c.so + libspice_cmss.so（**三定制版**） | 远程显示协议核心 |
| **USB/IP** | libeveusb*.so（中兴 EveUSB）+ assets/usbconfig/usbip.conf | USB 设备透传 |
| **SPICE USB Redir** | libusbredirect*.so | SPICE 通道内 USB 重定向 |
| **RustDesk (HBB)** | librustdesk.so + flutter_rust_bridge | 备用/特定场景的开源远程桌面 |
| **MQTT** | `com.cmic.promopush.push.base.MqttService`（中国移动推送） | 消息推送通道 |

---

## 3. AndroidManifest 详解

### 3.1 应用属性

```xml
<application
    android:name="s.h.e.l.l.S"                      <!-- 爱加密 Stub Application -->
    android:allowBackup="false"
    android:extractNativeLibs="true"
    android:networkSecurityConfig="@xml/network_security_config"
    android:requestLegacyExternalStorage="true"
    android:usesCleartextTraffic="true">             <!-- ⚠️ 允许明文 HTTP -->
```

### 3.2 入口与 Deep Link

| 入口 | 说明 |
|---|---|
| `com.cmss.cloudcomputer.ui.MainActivity` | Flutter 主活动，`android:launchMode="singleTop"` |
| Deep Link 1 | `cca://login`（CCA = Cloud Computer App 自有 scheme） |
| Deep Link 2 | `venusgroup://com.cmss.cloudcomputer/signIn`（合作伙伴接入） |
| `CloudPCActivity` | 横屏全屏，云电脑桌面会话承载 |
| `EmptyTransitionActivity` | 横屏过渡页 |

### 3.3 关键权限

| 权限 | 风险 / 用途 |
|---|---|
| `INTERNET`、`ACCESS/CHANGE_NETWORK_STATE`、`ACCESS/CHANGE_WIFI_STATE` | 网络基础 |
| `CAMERA`、`RECORD_AUDIO` | 摄像头/麦克风重定向给云端 |
| **`READ_PRIVILEGED_PHONE_STATE`** | ⚠️ **签名级私有权限**（普通 App 拿不到，可能用于一键登录获取 IMSI） |
| **`MOUNT_UNMOUNT_FILESYSTEMS`** | ⚠️ 系统权限，挂载远程磁盘？ |
| **`OVERRIDE_WIFI_CONFIG`** | ⚠️ 系统权限 |
| `READ_LOGS` | ⚠️ 危险，读取 logcat |
| `MANAGE_EXTERNAL_STORAGE` | 完全外存管理（target API 30+） |
| `SYSTEM_ALERT_WINDOW`、`SYSTEM_OVERLAY_WINDOW` | 悬浮窗 |
| `REQUEST_INSTALL_PACKAGES` | 应用内安装升级包 |
| `BLUETOOTH_*`、`ACCESS_*_LOCATION` | 蓝牙外设、定位 |
| `READ_PHONE_STATE` | 设备指纹 |

### 3.4 自定义权限

```xml
<permission android:name="com.cmss.cloudcomputer.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
            android:protectionLevel="signature"/>
```

### 3.5 关键四大组件

| 类型 | 名称 | 备注 |
|---|---|---|
| Service | `com.cmic.promopush.push.base.MqttService` | 中国移动 CMIC promopush + MQTT |
| Service | `com.zte.rap.unify.service.QoeService` | 中兴 RAP/QoE 监控服务 |
| Provider | `com.cmss.desktopsdk.init.CloudComputerInitializer` | 通过 androidx.startup 启动桌面 SDK |
| Provider | `com.cmss.cloudcomputer.fileProvider` | FileProvider |
| Provider | `com.cmss.cloudcomputer.flutter.image_provider` | Flutter 图片选择 |

### 3.6 网络安全配置（`res/xml/network_security_config.xml`）

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>   <!-- ⚠️ 信任用户级 CA -->
        </trust-anchors>
    </base-config>
</network-security-config>
```

⚠️ **mitm 抓包友好**：用户自签 CA 自动被信任，未启用证书 pinning（应用内部也未见 SHA-256/SPKI pin 字符串）。

---

## 4. 爱加密整壳保护（Ijiami）

### 4.1 加固证据

- `assets/ijiami.dat` (7.6 MB) — 主 DEX 加密包
- `assets/ijiami.ajm` (1.8 MB, magic `indl01`) — 加固配置
- `assets/IJMDal.Data` (132 KB) — DAL 元数据
- `assets/ijm_lib/{arm64-v8a,x86_64}/libexec.so` + `libexecmain.so` — 运行时解壳引擎
- `s.h.e.l.l.S` / `s.h.e.l.l.C` / `s.h.e.l.l.N` — Java stub
- `apktool` 视角下 smali 目录里只有 3 个 `.smali` 文件
- `jadx` 视角下只反编出 5 个 `.java`（R.java + 3 stub + 1 Kotlin stub）

### 4.2 解壳流程（基于 `s.h.e.l.l.S.attachBaseContext / onCreate`）

```
super.attachBaseContext(ctx)
  ├─► S.l(ctx)
  │    ├─► 读 /system/bin/linker 或 linker64 第 18 字节，识别架构（armeabi/arm64-v8a/x86/x86_64）
  │    ├─► 从 APK assets/ijm_lib/{abi}/libexec.so 与 libexecmain.so 抽取到 filesDir
  │    └─► 与 CRC32 比对避免重复抽取
  ├─► N.l(this, "com.cmss.cloudcomputer")            ◀── native 校验
  ├─► N.r(this, "com.cmss.cloudcomputer.App")        ◀── 准备替换 Application 类
  └─► (在 onCreate 中) N.ra(this, "com.cmss.cloudcomputer.App")
       └─► 通过 ActivityThread 反射把真实 Application 注入为 mInitialApplication

S.sp()  // 还预留了 com.ijm.dataencryption.DETool.loadDEso(apkPath, filesDir, "com.cmss.cloudcomputer")
        // 来对剩余 .so 做"DESO（DEX/SO 加密资源）"模式加载
```

### 4.3 壳引擎细节

`libexec.so` 字符串泄露：

```
ijm_vmp
ptrace
ijiami
/proc/self/maps
re ijm
ijiami SecLLVM compiler 1.7.4.20
ijiami.dat
```

→ **爱加密 SecLLVM 1.7.4.20 VMP**（基于 LLVM 改造的 VM 保护）+ ptrace 反调试 + `/proc/self/maps` 自检。

`libexecmain.so` 含 `getOpCode`，即 VMP 字节码解释器入口。

### 4.4 真实业务 Application

加固还原后的 Application：**`com.cmss.cloudcomputer.App`**（在 `ijiami.dat` 内）。

通过 JNI 包名推断，真实 Java 业务代码至少包含：

```
com.cmss.cloudcomputer.App
com.cmss.cloudcomputer.ui.MainActivity        ← Manifest 显式声明
com.cmss.cloudcomputer.ui.CloudPCActivity
com.cmss.cloudcomputer.ui.EmptyTransitionActivity
com.cmss.desktopsdk.init.CloudComputerInitializer
com.company.android.syydn.H3CSDKInitializer   ← JNI 桥
com.company.android.syydn.H3CSession
com.company.android.syydn.H3CDesktop
com.company.android.syydn.H3CCapacity
com.company.android.syydn.H3CDevice
com.company.android.syydn.H3CLogUtil
com.company.android.syydn.H3CWindow
com.zte.mspice.starter.QoeInterface           ← 中兴 QoE JNI
com.carriez.flutter_hbb.MainService           ← RustDesk Android Service JNI
com.cmic.promopush.push.base.MqttService      ← 中国移动 CMIC 推送
com.zte.rap.unify.service.QoeService          ← 中兴 RAP/QoE 服务
```

---

## 5. 原生库（111 个 .so）分类清单

| 类别 | 库 | 备注 |
|---|---|---|
| **Flutter 引擎** | `libflutter.so`、`libapp.so` (18.5 MB Dart AOT) | |
| **CMSS 主 SDK** | `libcmccsdk.so` | 编译路径泄露 `/home/vdi/hrw/cmcc/h3c-vdi-2.0/cmcc/cmccsdk/` |
| **H3C VDP 协议核心** | `libVdpServer.so` (11.2 MB)、`libvdcore.so`、`libVdconnSdk.so`、`libVdconnSdk_cmss.so` | gRPC v1.28.1 + protobuf |
| **SPICE 协议（三定制版）** | `libspice.so`、`libspice_cmss.so`、`libspice_h3c.so` | 中兴 mSPICE 衍生 |
| **GStreamer / 媒体** | `libgstplayer.so`、`libgstreamer_android.so`、`libgstreamer_android_h3c.so` | H3C 定制 GStreamer |
| **MPV / 播放器** | `libmpv.so` | |
| **FFmpeg 全套** | `libavcodec.so`、`libavfilter.so`、`libavformat.so`、`libavutil.so`、`libswresample.so`、`libswscale.so`、`libpostproc.so`、`libopenh264.so` | |
| **中兴 RAP / QoE** | `libRapPlugins.so`、`libQoeInterface.so`、`libqoelog.so`、`libnebula.so` | RAP=Remote Access Platform，Nebula 接入网关 |
| **中兴安全 / 加密** | `libzxsecrity.so`（拼写笔误：security→secrity）、`libdes.so`、`libzxCString.so` | AES-256-CBC + DES/3DES + dlsym 重定向反 hook |
| **OpenSSL 三版本共存** | `libcrypto.so` / `libcrypto.1.1.so` / `libcrypto.3.so`、`libssl.so` / `libssl.1.1.so` / `libssl.3.so` | ⚠️ 版本碎片，相同符号冲突风险 |
| **gRPC + protobuf** | `libgrpc.so`、`libgrpc++.so`、`libgpr.so`、`libupb.so`、`libaddress_sorting.so`、`libprotobuf.so` | gRPC v1.28.1 |
| **Google Abseil** | `libabsl_*.so` × 14 | gRPC 依赖 |
| **网络** | `libcurl.so`、`libsnmp++.so`、`libcjson.so` | |
| **USB 透传（USB/IP + SPICE）** | `libusb1.0.so/27.so/_cmss_mobile.so`、`libeveusb.so`、`libeveusbd.so`、`libusbMsg*.so`、`libusbredirect*.so`、`libusbcheck_cmss.so`、`libusbtrace.so`、`libhidapi.so`、`libtwaindcm_usb.so`(TWAIN 扫描仪)、`libblkid_usb.so`、`libsysfs_usb.so`、`libjpeg_usb.so`、`libgzip_usb.so`、`libz_usb.so`、`libiconv_usb.so` | USB/IP + SPICE usbredir 双轨 |
| **外设重定向** | `libprintredir.so`、`libprintservice.so`、`libcamrdr.so`、`libdevredir.so`、`libvideoRedirect.so` | 打印 / 摄像头 / 设备 / 视频 |
| **虚拟磁盘** | `libvdisk.so`、`libvdisk_cmss.so` | |
| **配置 / 驱动** | `libGeneralConfig.so`、`libCDriverMapping.so`、`libcag.so`（CAG=Cloud Access Gateway）、`liboutbandProxy.so` | |
| **CMCC SDK** | `libcmccsdk.so`、`libcmccsdk_cmss.so`（嵌于 cmss 系列） | |
| **存储 / 日志** | `libmmkv.so`（腾讯 MMKV）、`libspdlog.so`、`libsqlcipher.so` | |
| **图像 / ML Kit** | `libbarhopper_v3.so`（Google 条码核心）、`libimage_processing_util_jni.so`、`libimagepipeline.so`（FB Fresco）、`libnative-filters.so`、`libnative-imagetranscoder.so`、`libgifimage.so`、`libturbojpeg.so`、`libyuv.so` | |
| **图形渲染** | `libSDL2.so`、`libdrm.so` | |
| **C++ 运行时** | `libc++_shared.so`、`libuuid.so`、`libiconv.so`、`libjnidispatch.so`（JNA）、`libsoundtouch.so` | |
| **Flutter media_kit** | `libmedia_kit_native_event_loop.so`、`libmediakitandroidhelper.so` | |
| **RustDesk（Flutter assets 内）** | `assets/flutter_assets/assets/rustdesk/librustdesk.so` (19 MB, NDK r26b stripped) + 该子目录还自带 `libapp.so/libflutter.so/libssl.so/libcrypto.so/libc++_shared.so` 副本 | |

### 5.1 主要库依赖关系

```
libcmccsdk.so
   ├─ libVdpServer.so   (gRPC 控制面)
   ├─ libvdcore.so
   │   ├─ libspice_h3c.so
   │   │   ├─ libgstreamer_android_h3c.so
   │   │   └─ libnebula.so       (H3C Nebula 接入网关)
   │   ├─ libgstplayer.so
   │   ├─ libhidapi.so / libSDL2.so
   │   └─ libandroid.so / libdl.so
   ├─ libSDL2.so
   └─ libspdlog.so

libRapPlugins.so   ─→ libzxsecrity.so
libQoeInterface.so ─→ libzxsecrity.so + libGeneralConfig.so + libcurl + libssl.1.1
libVdconnSdk.so    ─→ libcurl + libssl.1.1   (走 OpenSSL 1.1)
libcag.so          ─→ libssl.3 + libcrypto.3 (走 OpenSSL 3.x)   ⚠️ 同进程多套 OpenSSL
```

---

## 6. Flutter 应用层（pcas_app）

### 6.1 工程指纹

- 工程名 `pcas_app`
- `package:pcas_app/` 路径下 **673 个 Dart 文件**、**280 个模块二级目录**、**106 个 tablet_page 子页面**
- Flutter 引擎包：`io.flutter.embedding`，meta `flutterEmbedding=2`
- Pigeon 平台通道：26 个 PlatformChannel + 8 个 CloudPCChannel + 多个 Peripherals/OneKey/Dialup/DeepLink 通道

### 6.2 顶层模块

```
pcas_app/
├── api/
│   ├── cem/        ← Cloud Edge Manager Web API 客户端
│   │   ├── login.dart / register.dart / client.dart / client_file.dart
│   │   ├── data_report.dart / device_manager.dart / feedback.dart
│   │   ├── history_orders.dart / hour_package.dart / machine.dart
│   │   ├── message_center.dart / outer.dart / peripherals.dart
│   │   ├── purchase.dart / system_reload_api.dart / transfer.dart
│   │   ├── upload_logs.dart / user_info_api.dart
│   ├── normal/     ← 非 cem 模块
│   │   ├── behavior_record_api.dart / buried_point_api.dart
│   │   ├── enabled_function_api.dart / lock_screen_api.dart
│   │   ├── login.dart / remote_con_api.dart
│   │   ├── software_control_api.dart / web_acl_api.dart
│   ├── http.dart                                  ← Dio 客户端基础
│   └── interceptor/
│       ├── cem_host_handle_interceptors.dart      ← host 拦截
│       ├── cem_rsa_encode_interceptors.dart       ⚠️ RSA 加密请求体
│       ├── cem_rsa_decode_interceptors.dart       ⚠️ RSA 解密响应体
│       ├── dialup_report_interceptor.dart
│       ├── dio_logging_interceptor.dart
│       ├── error_report_interceptor.dart
│       └── network_unavailable_interceptor.dart
├── common/
│   ├── cem_rsa.dart                ← RSA 加解密工具
│   ├── des_util.dart               ← DES 加密工具
│   ├── cloud_computer_related.dart
│   ├── double_stream/
│   │   ├── command/command.dart / connection_request_client.dart
│   │   ├── command/heart_beat_client.dart
│   │   └── decoder.dart / encoder.dart   ← gRPC 双向流封装
│   ├── network_detection/
│   │   ├── detector/cloud_management_service_detector.dart
│   │   ├── detector/internet_connection_detector.dart
│   │   ├── detector/local_network_detector.dart
│   │   ├── detector/service_domain_resolution_detector.dart
│   │   └── detector/upgrade_service_detector.dart
│   ├── agreement_files/
│   │   ├── appeal_and_unsealing_20250331.dart
│   │   ├── collection_personal_information_list.dart
│   │   └── latest_agreement_files_for_tablet/
│   │       ├── privacy_20231129.dart
│   │       └── service_20230412.dart
│   └── event_tracking/buried_point_reporting_monitor.dart
├── mixin/                 ← 32 个业务 mixin
│   ├── two_factors_authentication/   ← 双因子认证
│   ├── cloud_pc/                     ← 云电脑业务
│   ├── history/                      ← 历史订单 / 套餐续费 / 退订
│   ├── peripherals/                  ← 外设
│   ├── policy/                       ← 策略配置
│   ├── purchase/                     ← 购买
│   ├── register/                     ← 注册
│   ├── sign_in/                      ← 登录
│   ├── system_reload/                ← 系统重装
│   ├── transfer/                     ← 转移
│   ├── video_zone/                   ← 视频专区
│   ├── login_log/                    ← 登录日志
│   ├── network_detection/、proxy_setting/、message_center/、hour_package/
│   ├── account_info/、configuration/、change_password/、force_modify_password
├── tablet_page/           ← 106 个平板页面
│   ├── about / account_info / cloud_computer_detail
│   ├── cloud_pc / ecloud_purchase / history
│   ├── forget_password / reset_password / password_login
│   ├── phone_login / qr_code_login / one_click
│   ├── tablet_login_page / two_factors_authentication_page
│   ├── trust_device / trust_device_setting
│   ├── privacy_policy / privacy_policy_first
│   ├── purchase / message_center / setting / normal_setting
│   ├── network_detection / network_proxy / proxy_setting
│   ├── marketing_activities_dialog_page / marketing_activities_screen
│   ├── splash / register / system_reload / transfer
│   ├── upload_logs / video_zone / webview
├── models/   (各种 fromJson 模型)
├── widget / tablet_widget / theme / router / provider
├── pigeon/   (Pigeon 通道桩)
├── extension/、event_bus/
├── main.dart、app_component.dart
```

### 6.3 Pigeon 平台通道（Flutter ↔ 原生）

#### `PlatformChannelApi`（26 个方法）

- 设备信息：`getDeviceUid` / `getDeviceDisplayName` / `getDeviceIsTablet` / `getHardwareInfo` / `getIpAddress` / `getMacAddress` / `getPhoneState` / `getWifiRssi` / `getVersionName` / `getVersionCodeS` / `checkIfRuntimeIsArm64`
- 屏幕/UI：`setScreenOrientation` / `getScreenOrientation` / `setBottomBarHide` / `setStatusBarHide` / `moveToSysDesktop` / `dismissSplashScreenDialog`
- 权限：`doAfterPermCheck` / `startToModifyStoragePermission`
- 日志：`cancelGatherLog` / `gatherLogAndReturnPath` / `checkLogPathExist`
- 网络：`setNetworkProxy`
- 环境：`notifyAppEnvironment`
- **安全**：**`forbiddenScreenCapture`**（设置 `FLAG_SECURE`）、`getDesktopProtocol`（H3C 还是 RustDesk）

#### `CloudPCChannelApi`

- `checkIfCloudPcRunning` / `linkCloudPC` / `killLink` / `showPromptInCloudPC` / `notifyHourPackageRunOut` / `showSafeNotification`

#### `CloudPCChannelFlutterApi`（原生 → Flutter）

- `refreshCloudPcList` / `syncCloudPcConnectInfo` / `syncCloudPcNetworkInfo`
- `showErrorDialog` / `showAutoDisconnectDialog` / `launchCountdownAndShutdownEvent`
- `nativeNeedNetworkDetection` / `onDateChanged` / `setShouldShowSecurityLoginReminder`
- `reportKQIConnectionData`（KQI = Key Quality Indicator）
- `reportQKKRequestData`（QKK = 中国移动质量监控代号）

#### 其它

- `DeepLinkRelatedFlutterApi`: `notifyAppSignInParams`、`notifyCloudSpaceParams`（cca:// 与 venusgroup:// 触发）
- `DialupChannelApi.reportLoginForDialup`
- `FlutterNotifyUserPresentApi.onUserPresent`
- `OneKeyChannelApi`: `getToken`、`getUmcLoginPre`（中国移动一键登录 UMC）
- `PeripheralsFlutterApi`: `addPeripheralList` / `queryPeripheralList` / `retryPeripheralList` / `updatePeripheralList`
- `PeripheralsHostApi.setPeripheralWhiteListUpdate`

### 6.4 Flutter Dart 依赖（NOTICES.Z 解出 345 个）

精选关键：

- **HTTP/网络**：`dio` / `web_socket_channel` / `dart_ping` / `flutter_icmp_ping` / `connectivity_plus` / `http` / `shelf` / `shelf_static` / `shelf_web_socket`（注：客户端集成 `libmicrohttpd` 表明会启动本地 HTTP 服务端）
- **加密**：`crypto` / `encrypt` / `dart_des` / `pointycastle` / `asn1lib` / `boringssl` / `fallback_root_certificates`
- **WebView/浏览器**：`flutter_inappwebview` 全家桶 / `webview_flutter` 全家桶 / `flutter_html` / `flutter_widget_from_html_core` / `puppeteer`
- **媒体**：`media_kit` 全家桶 / `video_player` 全家桶 / `chewie` / `just_audio` / `audio_session`
- **远程桌面**：**`rustdesk_plugin`** / `flutter_rust_bridge` / `texture_rgba_renderer`
- **扫码/二维码**：`mobile_scanner` / `zxing2` / `qr` / `pretty_qr_code`
- **桌面平台**：`window_manager` / `window_size` / `screen_retriever` / `desktop_drop` / `desktop_multi_window` / `flutter_custom_cursor`（说明同源代码也用于桌面端 Windows/macOS/Linux 客户端）
- **存储**：`sqflite` / `shared_preferences` / `safe_local_storage`
- **设备信息/权限**：`device_info_plus` / `package_info_plus` / `permission_handler`
- **国际化**：`intl` / `icu`
- **底层 C/C++（Flutter bundle 带）**：`boringssl`、`libpng`、`libwebp`、`libtess2`、`libjxl`、`freetype2`、`harfbuzz`、`zlib`、`xxhash`、`flatbuffers`、`rapidjson`、`inja`、**`libmicrohttpd`**（嵌入式 HTTP 服务端）、**`libnatpmp`**（NAT-PMP NAT 穿透）、`wuffs`、`cpu_features`

---

## 7. 服务端接入面

### 7.1 域名清单（来自 libapp.so 字符串）

| 域名 | 类别 | 备注 |
|---|---|---|
| `pcas.cloudtrust.com.cn` | **生产 PCAS API 主域** | |
| `pcas-test-back.cloudtrust.com.cn` | ⚠️ **测试后端**（生产 APK 仍含） | |
| `cloud-computer-h3-admin01-dongguan.cmecloud.cn` | ⚠️ **东莞 H3C 内部管理节点** | cmecloud.cn=中国移动内部云域 |
| `cloudpc.ecloud.10086.cn` | 中国移动云电脑生产 | |
| `ecloud.10086.cn` | 中国移动云主门户 | |
| `wap.cmpassport.com` | 中国移动统一身份认证（cmpassport） | |
| `www.zqdialup.cn:30080` | 隐私政策托管（zqdialup 合作） | 非标 30080 端口 |
| `app-store-test-1252715994.cos.ap-nanjing.myqcloud.com` | ⚠️ **腾讯云 COS 南京区测试桶**，存 app icons | |
| `124.221.195.174:21116` | ⚠️ **RustDesk hbbs（rendezvous）服务器**（腾讯云 IP，21116 = hbbs 默认端口） | |
| `10.253.198.194:8089` | ⚠️ **内网测试 IP 泄露** | 10.x 私网段 |

### 7.2 H3C VDP gRPC 控制面（`libVdpServer.so`）

#### gRPC 服务

- **`client.ClientCore`** — 主服务（108 个 RPC 方法）
- **`basicservice.BidiBasicServiceStream/BasicServiceRPC`** — 双向流基础服务

#### 完整 ClientCore RPC 列表（108 个）

```
ApplyForDeviceInfo / ApplyForEmailInfo / ApplyForVm
CheckAndSaveLdapPassword / CheckPassword / CheckTmpStorageSize
ClientReleasePassword / DeviceExisted
GetDesktopPoolById / GetLearningspaceDesktopPoolById / GetLsUserInfo
GetRemoteAppList / GetTemplatesOrIsos
Heartbeat / Login / LoginWorkspaceOnShareTerminal
ModifyPassword / ModifyVmName / OperateForVm
QueryNodes / RecoverVm / RegisterDevice / ReportSuccess
SaveTemplateInfo / Snapshot / USBNotify / Upgrade / WhoAreYou
adminLogin / applyForWebPageRedirection / authenticate
bindAndValidateGoogleCode / bindRemoteAccess / bindUserWithWechat
checkVerifyCode / clientCollectLog / clientReportMonitorResult
confirmQuantumBind / forceLoginWithWechatOpen
getCode / getComputerGroupList / getConnectAppInfo
getDoubleAuthType / getLSTermDataBKConfigByClientInfo
getLdapConf / getLoginConfig / getMonitorPolicy
getQuantumEncryptEnable / getRdpPort / getSoftwareDiskInfo
getTermBootTaskByClientInfo / getTermDataBKConfigByClientInfo
getVerifyCode / imageUploadPreCheck / keyEvent / loadVoiInfo
loginViaVerifyCode / modifyUserInfo / onekeyHelp / onekeyHelpUseGateway
passThroughMessageToAgent / queryAgentUseControllerIp / queryAuthStrategy
queryDeviceConfigInfo / queryEsConfig / queryExtraAuthStrategy
queryIndividualConfig / queryJitGwRandom / queryNextCloudInfo
querySMSCode / querySSOConfig / querySaasApp / querySaasAppList
querySessionPreLaunch / queryShareTerminalInfo / queryTerminalType
queryUsbPolicyForAgent / queryUserInfo / queryVdpHostInfo
queryVmDetailInfo / queryVoiImage / queryVoiRunningMode
queryWebPageRedirStrategy / registerShareTerminal / registerUserWithWechat
reportClipboardLog / reportLSTermDataBKFileReceipt / reportRedirectStatus
reportSoftwareDiskResult / reportTermDataBKFileReceipt
resetPasswordViaSmsOrEmail / samlSSO / saveVoiInfo
sendExchangeDataToGuest / submitRestoreStatus
transferDesktopToShareTerminal / unbindRemoteAccess / unbindThirdParty
unbindUserPhone / unbindWechat / updateDeviceStatus
updateTermBootTaskObject / validateGoogleCode / verifySMSCode
vmTransfer / webAppSetSave / webGetAppDownloadUrl
```

#### 关键能力面（从 RPC 反推）

| 能力 | 关键 RPC |
|---|---|
| **多因子认证** | LDAP / Google Authenticator (`bindAndValidate/validateGoogleCode`) / SAML SSO (`samlSSO`) / SMS (`querySMSCode/verifySMSCode/sendVerifySms`) / 微信 (`bindUserWithWechat/forceLoginWithWechatOpen`) / 一键登录 (`onekeyHelp/onekeyHelpUseGateway`) |
| **量子加密** | `getQuantumEncryptEnable/confirmQuantumBind` — 涉及国密量子密钥（可能与中国移动量子干线对接） |
| **VOI（Virtual OS Infrastructure）** | `loadVoiInfo/queryVoiImage/queryVoiRunningMode/saveVoiInfo` |
| **桌面池/学习空间** | `GetDesktopPoolById/GetLearningspaceDesktopPoolById` |
| **可信终端共享** | `LoginWorkspaceOnShareTerminal/registerShareTerminal/queryShareTerminalInfo/transferDesktopToShareTerminal` |
| **JIT 网关** | `queryJitGwRandom`（即时网关随机数挑战） |
| **水印策略** | `common::WatermarkPolicy` / `client::WatermarkPolicyContent`（protobuf message，桌面端嵌入式水印） |
| **网页重定向** | `applyForWebPageRedirection/queryWebPageRedirStrategy` |
| **剪贴板审计** | `reportClipboardLog` |
| **USB 策略** | `queryUsbPolicyForAgent/USBNotify` |
| **快照** | `Snapshot` |
| **系统重装** | `RecoverVm/submitRestoreStatus` |
| **资源转让** | `vmTransfer/transferResource` |
| **断点续传备份** | `getLSTermDataBKConfigByClientInfo/reportTermDataBKFileReceipt` |

#### proto schema 关键 message

```
common_message.AuthStrategyReq.DomainMacIpEntry / TerminalMacIpEntry
common_message.ExtraAuthStrategyReq.DomainMacIpEntry / TerminalMacIpEntry
common_message.WebPageRedirStrategyReq.DomainMacIpEntry / TerminalMacIpEntry
common_message.NetStrategyReq.MacIpEntry
common_message.PassThroughMessage / StreamMessage / MqStreamMessage
common_message.JoinComputerGroupResp / WebPageRedirStrategyResp
common_message.AgentUseControllerIpResp / ExtraAuthStrategyResp
common_message.AuthStrategyResp / TerminalTypeResp / EsConfigResp
common_message.PipelineLimitInfo / PipelineLimitPolicy
common_message.ProcessInformation
common_message.UsbWriteOrBlackListInfo
common_message.ProfileManagementMsg / ProfileManagementUser / ProfileManagementStorage / ProfileManagementAdvanced / ProfileManagementFolderRedirect
common_message.DiskResourceData / PartitionResourceData
common.WatermarkPolicy / client.WatermarkPolicy / client.WatermarkPolicyContent
common.StreamMessage / MqStreamMessage
```

### 7.3 CEM Web API（80 个，主域 `pcas.cloudtrust.com.cn`）

模式：`https://pcas.cloudtrust.com.cn/api/cem/gateway/outer/cem-webapi/<module>/<action>`

| 模块 | 数量 | 说明 |
|---|---|---|
| **user** | 27 | 用户/设备/密码/绑定/订单/可信设备 |
| **login** | 23 | 登录/验证码/SMS/SSO/二维码/统一令牌/双因子/Trust |
| **resource** | 6 | 资源池/转让/重装 |
| **client** | 6 | 错误上报/广播/系统配置/版本控制 |
| **extPolicy** | 5 | 扩展策略 |
| **userMessage** | 3 | 消息中心 |
| **clientlog** | 3 | 日志上传路径/结果 v1+v2 |
| **session** | 2 | machineConnect / updateSessionStatus |
| **machine** | 2 | 性能批量上报 / 连接事件 |
| **sso** / **malfunction** / **device** | 各 1 | |

完整 endpoint 见 `pcas_out/lib/arm64-v8a/libapp.so` 字符串提取结果。

### 7.4 旁路 API（非 cem-webapi）

```
/api/mb/active|behavior|blacklist|functional|machine|mobile|statistic|test|web-acl|whitelist
/api/mb/behavior/list-new / /api/mb/behavior/type / /api/mb//behavior/logo  ← (笔误双斜杠)
/api/org-am/machine
/api/query/clouddesktop / clouddesktopnew / emop / government / op-order-h5 / op-usercenter-h5
/api/web/clouddesktopnew
/ccabusiorder/ccaInstances/{getInstanceDetail, renewOrder, selectRenewOrderInfo, specRenewalRule, unsubscribe}
/ccabusiorder/ccaOrders/submitCcaOrder
```

### 7.5 RustDesk hbbs/hbbr 接口（`librustdesk.so`）

```
/api/oidc/auth                     ← OpenID Connect 登录
/api/oidc/auth-query
/api/heartbeat                     ← 心跳
/api/record                        ← 录屏上传
/api/audit                         ← 审计上报（默认 http://rustdesk.com/api/audit/）
```

- 默认配置：`<id>@<server_address>?key=<key_value>` 形式
- 内置示例：`9123456234@192.168.16.1:21117?key=5Qbwsde3unUcJBtrx9ZkvUmwFNoExHzpryHuPUdqlWM=.`
- 真实自建 hbbs：`124.221.195.174:21116`（腾讯云 IP）
- 编译路径：`/home/runner/work/rustdesk/rustdesk/` （**GitHub Actions runner，基于上游 RustDesk fork 构建**）
- Rust 工具链依赖：tokio 1.28.1 / serde_json 1.0.107 / flutter_rust_bridge 1.80.1 / hbb_common
- 完整集成 Server + File Transfer + Port Forward + Audit + Record 全功能

---

## 8. 关键安全发现（含合规加固建议）

> **声明**：本节面向"自有站点安全加固"。所有发现均基于离线静态分析，**未做任何越权探测、未触达活体服务**。下列建议为针对 PCAS_App 自身的改进意见。

### 8.1 ⚠️ 高危：客户端硬编码 RSA 1024-bit 私钥

- **位置**：`libapp.so`（Dart AOT snapshot）内
- **作用**：`cem_rsa_encode_interceptors.dart` 用公钥加密请求体、`cem_rsa_decode_interceptors.dart` 用对应私钥解密响应体（通过 `useIsolateRunCemRsaDecode` 在 Isolate 中执行）
- **公钥**（X.509 SPKI, Base64）：

  ```
  MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqisJL7YvdPC/gJA7fLrr1G+t6
  J0arJr0sVfieVJTXTclm/2afP/fjNYY/CFcg1MUx8KPmPC2CqsUHRMZq6Ev1/UNX
  E74I1TfJC/2b8aexcdZ+Lokj7AwzrM9yPy2qfV6vXtxyRrTs+JcFHVXtV6phNkor
  NyIahyfy46+iNB+FSQIDAQAB
  ```

- **私钥**（PKCS#8 PrivateKeyInfo, 同一密钥对）：

  ```
  MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKqKwkvti908L+Ak
  Dt8uuvUb63onRqsmvSxV+J5UlNdNyWb/Zp8/9+M1hj8IVyDUxTHwo+Y8LYKqxQdE
  xmroS/X9Q1cTvgjVN8kL/Zvxp7Fx1n4uiSPsDDOsz3I/Lap9Xq9e3HJGtOz4lwUd
  Ve1XqmE2Sis3IhqHJ/Ljr6I0H4VJAgMBAAECgYBD6lx0BlajtRtPxKxTfvWfNQ4y
  qD+BWz0M0fPfgcmAcI7bQKyqkLv0NNWQdo7UGUeqmq16u85X8g/i1CW8X2QYHOSY
  NBUWsK3k5gFT1wdk+bwuIMZqgjEc48TXzM4pidcplJLyD1tnNiubzcXIsZCIIuQ/
  GmWcuxn7ULHnXDsQMQJBANMl4V97be6fkd1beGqYZWIx3XNnL96AQsapBrEbbORT
  u/JnwTCRbsRWRBHU11FZuK85dBDXrH8reoAsgepmsF0CQQDOxL99OFjozj8g1weF
  GwI/otMKcPhkaslU2tj3QF44zT1TZiOZ710I8GQLPlKeu1yGWvVUwgH4bCY0M8M1
  /gndAkB9sU4RTeOqKjllwT7UjbXEl5SRTzrSxB18L0B5i67t2N7INXVumRSMMiJB
  TyeCGNv1C0mJgSoBZft9c4E+7TRNAkB+7Azza7Q/6+KaYQRPs32U3HkZbrE6ysYd
  XV1ToOJ1kZ60Y/00j9cXFqECudXzc+Ve39S6m4CkIpbs8l1A9ljNAkBy6Rp19R5w
  WMr/3feIMZ18akWXT5mgRvZpkT5MgmrjVu1lRv8bHsEsAzRYvdPSjzp0nCkUbOWU
  ITxWp7d//Fwc
  ```

- **风险**：
  1. 该"加密"无法防御真实攻击者——所有客户端 APK 都带相同私钥，提取即解密一切流量
  2. RSA 1024 已**低于 NIST/NESAS/GM/T 推荐强度**（≥ 2048）
  3. 业务可能误以为该层"加密"等效 HTTPS，导致**双重错觉**

- **加固建议**：
  - 立即**废弃客户端 RSA 解密响应**模式（让 TLS 来负责机密性）
  - 如必须做应用层加密，改用**服务端短期下发的 ECDH/X25519 会话密钥**+ AES-GCM，且每会话一密钥
  - 切勿在客户端内嵌持久私钥
  - 升级到 RSA-2048 / RSA-3072 / ECDSA P-256 至少

### 8.2 ⚠️ 高危：生产 APK 泄露测试环境与内网域名

| 类别 | 暴露内容 |
|---|---|
| 测试后端 | `https://pcas-test-back.cloudtrust.com.cn` |
| 测试 OSS | `https://app-store-test-1252715994.cos.ap-nanjing.myqcloud.com/` |
| 内部管理节点 | `cloud-computer-h3-admin01-dongguan.cmecloud.cn` （东莞 H3C 管理面） |
| 内网 IP | `http://10.253.198.194:8089`（私网测试服务器） |
| H3C gRPC 自签 cert | `assets/grpcserver.pem` CN=`justtest.h3c.com`, O=`YourCompany`, OU=`YourApp`，**显然未替换为正式证书** |

- **风险**：暴露测试/管理面，便于横向探测；自签 demo cert 在生产中使用降低信任面
- **加固建议**：
  - CI 流水线增加正则扫描，剔除任何 `*-test-*`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`*.cmecloud.cn(内部)`、demo CN
  - `assets/grpcserver.pem` 替换为正式签发的服务端证书，并在客户端做 SPKI pin

### 8.3 ⚠️ 中危：网络安全配置允许 user CA + 明文流量

```xml
<base-config cleartextTrafficPermitted="true">
    <trust-anchors>
        <certificates src="user"/>     <!-- 允许用户级 CA -->
        ...
    </trust-anchors>
</base-config>
```

- **风险**：mitm 工具（如 Burp/Charles+ Frida/Xposed 系列）安装用户 CA 即可拦截全部明文，进一步逆向 gRPC 与业务接口
- **加固建议**：
  - 生产版本移除 `<certificates src="user"/>`
  - 关闭 `cleartextTrafficPermitted="true"`，凡需明文调试，使用 BuildType-specific debug overlay
  - 引入 Network Security Config **per-domain pinning**（pin SPKI hash）
  - 对 `pcas.cloudtrust.com.cn`、`cloudpc.ecloud.10086.cn`、`ecloud.10086.cn` 等核心域强制 mTLS 或 SPKI pin

### 8.4 ⚠️ 中危：OpenSSL 三版本同进程共存

| 库 | OpenSSL 版本 |
|---|---|
| `libVdconnSdk.so` / `libQoeInterface.so` 等多数 | **OpenSSL 1.1**（`libcrypto.1.1.so` / `libssl.1.1.so`） |
| `libcag.so` 等 | **OpenSSL 3.x**（`libcrypto.3.so` / `libssl.3.so`） |
| Flutter 自带 BoringSSL & 默认 `libssl.so/libcrypto.so` | 第三套 |
| `libzxsecrity.so` | 调用 `AES_cbc_encrypt@OPENSSL_3.0.0`（依赖 3.x） |

- **风险**：符号同名（如 `EVP_*`、`RSA_*`）不同版本互相干扰；任一版本爆出 CVE（如 OpenSSL 1.1 已不再维护）不能简单升级，而需全栈协调
- **加固建议**：
  - 收敛到单一 OpenSSL 版本（推荐 3.0+ LTS）
  - 用 `--exclude-libs` + `LD_PRELOAD` 隔离冲突符号
  - 编译期标记每个 .so 的 OpenSSL 依赖版本，作为构建质量门

### 8.5 ⚠️ 中危：DES/3DES + 弱加密残留

- `libdes.so` 提供完整 DES/3DES/`des_ecb_encrypt`/`des_set_key`
- Flutter 端 `package:pcas_app/common/des_util.dart` 业务直接调用 DES 工具
- DES 已被 NIST 标记为不再安全（自 2005 年起），3DES 自 2023 起仅允许在合规场景过渡使用

- **加固建议**：
  - 全面迁移至 AES-128/256-GCM（已内置 `libzxsecrity.so` `CBC_AES256EncryptStr/DecryptStr`，方向正确）
  - 删除 `libdes.so` 与 `des_util.dart`，避免业务方误用

### 8.6 ⚠️ 中危：无证书绑定 / SSL Pinning

- libapp.so 中只发现 `SecureSocket_RegisterBadCertificateCallback`（Dart 标准回调），未发现任何 SHA-256/SPKI 指纹常量
- 等同于"接受所有可信 CA 即可"，结合 §8.3 用户 CA 信任，**mitm 抓包零门槛**

- **加固建议**：
  - 在 Dio `IOHttpClientAdapter.onHttpClientCreate` 中实现 SPKI pin
  - 或使用 Flutter 插件 `nb_utils` / `dio_certificate_pinning`
  - 至少 pin `pcas.cloudtrust.com.cn` 与 `cloudpc.ecloud.10086.cn` 两个核心域

### 8.7 ⚠️ 中危：Flutter 已含整套 RustDesk + 本地 HTTP/NAT 穿透能力

- `librustdesk.so`（19 MB）内含 RustDesk 完整 Server / File Transfer / Port Forward
- JNI: `com.carriez.flutter_hbb.MainService` 暴露 `startService` / `startServer` / `onVideoFrameUpdate` / `onAudioFrameUpdate` / `init` 等
- Flutter 依赖含 `libmicrohttpd`（本地 HTTP 服务端）+ `libnatpmp`（NAT-PMP 穿透）

- **潜在攻击面**：
  - 若 RustDesk 被错误配置或被恶意指令激活，应用进程会启动 RustDesk Server，**意味着 App 可以反向被远程控制**
  - libmicrohttpd 启动本地服务时如绑定 0.0.0.0 / 监听公网，存在被同网段设备访问的风险
- **加固建议**：
  - 明确 RustDesk 启停条件并写入文档；启动时强制要求服务端二次授权 + 一次性 token + 仅监听 `127.0.0.1`
  - libmicrohttpd 监听地址默认绑定 loopback，禁用 NAT-PMP / UPnP 自动打洞
  - 在 Manifest 中加入 `android:usesCleartextTraffic` per-domain 配置，禁止 RustDesk 走明文

### 8.8 ⚠️ 中危：测试性 / 内部敏感字符串泄露

| 来源 | 暴露 |
|---|---|
| `libapp.so` | RustDesk 配置示例硬编码 `key=5Qbwsde3unUcJBtrx9ZkvUmwFNoExHzpryHuPUdqlWM=` |
| `libcmccsdk.so` | 编译路径 `/home/vdi/hrw/cmcc/h3c-vdi-2.0/...` 暴露**开发者用户名 `hrw`** 与项目目录结构 |
| `libVdpServer.so` | 同上 + `vdi-client-3rdparty-mobile/grpc/include/grpc-v1.28.1/...` 暴露 gRPC 老版本（1.28.1，**2020 年发布**，已多个 CVE） |
| `librustdesk.so` | `/home/runner/work/rustdesk/rustdesk/`（GitHub Actions runner 路径） |

- **加固建议**：
  - 链接时使用 `-fdebug-prefix-map=$PWD=src` 或 `--strip-debug` 完整剥离调试路径
  - CI 阶段对 final `.so` 做 `strip -g` + `objcopy --strip-debug`
  - 升级 gRPC（1.28.1 → 1.60+ 或 最新 LTS）

### 8.9 ⚠️ 中危：自定义权限保护级别不够

```xml
<permission android:name="com.cmss.cloudcomputer.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
            android:protectionLevel="signature"/>
```

- 该自定义权限仅签名级，已规范。但未单独保护广播/服务的多数组件，意味着大部分 IPC 仍能被同签名 App 触达。

### 8.10 ⚠️ 低危：H3C VDI gRPC 自签 demo 证书

`assets/grpcserver.pem` 内容：

```
CN=justtest.h3c.com, OU=YourApp, O=YourCompany, ...
颁发: 2018-11-07 ~ 2028-11-04, 自签 RSA-1024
```

- **风险**：可能与正式 gRPC mTLS 流程混淆；若该证书并未在生产路径生效，移除即可；若是 fallback CA 则属于明显占位 cert
- **加固建议**：在 release 渠道剔除该 PEM 或替换为内部 CA 签发的正式服务端证书

### 8.11 ✅ 已较好做到的安全实践

- **整包爱加密 SecLLVM 1.7.4.20 VMP + 抽取壳**：Java 主 DEX 不可静态阅读
- **`FLAG_SECURE` 接入**：`PlatformChannelApi.forbiddenScreenCapture` 允许业务按需禁用截屏
- **桌面水印策略**：服务端 `WatermarkPolicy` + `WatermarkPolicyContent`，可在云电脑屏幕上叠加用户/工号水印威慑泄密
- **模拟器检测**：Flutter media_kit `MediaKitAndroidHelperIsEmulator` + 自定义 `Utils.IsEmulator`
- **行为审计**：`BehaviorRecordPage` + `BuriedPointReportingMonitor` + `reportClipboardLog`（剪贴板审计）
- **多因子认证**：LDAP / SAML SSO / SMS / 微信 / 谷歌 Authenticator / 量子加密绑定 6 通道
- **可信设备绑定**：`trustDevice/trustOrTemporaryDevice/getTrustDeviceList`
- **抢占式单点登录**：服务端 `desktop_occupied_kick_off` + `cloud_computer_preemptive_login_prompt`
- **超长自签证书有效期至 2103**：避免续签中断（也意味着丢失私钥就长期暴露，需企业级 HSM 保护）

---

## 9. 推荐继续分析方向（受限于离线静态分析无法触达的细节）

| 方向 | 工具 | 期望产出 |
|---|---|---|
| 脱壳获取 `ijiami.dat` 内真实 DEX | Frida + FRIDA-DEXDump / BlackDex / Xposed Hook ART | 真实 `com.cmss.cloudcomputer.App` 与 syydn JNI 业务 Java 代码 |
| H3C VDP gRPC 抓包 | Wireshark + 中间 mTLS 代理（合规授权前提下、仅自有测试环境） | 完整 .proto 还原 |
| Dart Isolate 内 RSA 密钥派生流程 | flutter_reverse_engineering（doldrums / blutter） | 还原 `cem_rsa.dart` 与 `des_util.dart` 真实逻辑 |
| RustDesk 内嵌目的与触发路径 | Frida hook `com.carriez.flutter_hbb.MainService.init/startServer` | 是否生产启用、启停条件 |
| `libmicrohttpd` 监听端口与接口面 | netstat + Frida hook MHD_start_daemon | 本地 HTTP 端口、绑定地址 |
| USB/IP（`libeveusbd.so`）服务端口 | bind 端口探测 | 是否存在公网/局域网监听 |
| `libzxsecrity.ZX*` 反 hook 详情 | IDA Pro + 跨引用 dlsym 调用 | 确认是否硬编码 libc 偏移 |

---

## 10. 关键文件落盘位置

```
E:\Desktop\foldder\Code\Claude\ydy\
├── PCAS_App_V3.6.2.v1_260403_release_1f65af1b_arm64_v8a_prod_signed.apk
├── PCAS_App_逆向分析报告.md        ← 本报告
└── pcas_out\
    ├── apktool_out\
    │   ├── AndroidManifest.xml
    │   ├── apktool.yml
    │   ├── assets\
    │   │   ├── ijiami.dat / ijiami.ajm / IJMDal.Data       ← 爱加密资源
    │   │   ├── ijm_lib\arm64-v8a\libexec.so / libexecmain.so
    │   │   ├── flutter_assets\                              ← 94 MB Flutter 资源
    │   │   │   ├── AssetManifest.json / NOTICES.Z
    │   │   │   ├── assets\rustdesk\librustdesk.so (19 MB)   ← 内嵌 RustDesk
    │   │   ├── grpcserver.pem (H3C 自签 demo)
    │   │   ├── ssl\certs\ca-certificates.crt (163 CA)
    │   │   ├── usbconfig\usbip.conf                          ← USB/IP 透传白名单
    │   │   ├── qoeconfig\ (collect_top_ten_data.sh / hdmi0/1 / get_mac_info)
    │   │   ├── fontconfig\, mlkit_barcode_models\, signed.bin, af.bin
    │   ├── lib\arm64-v8a\ (111 个 .so)
    │   ├── res\xml\network_security_config.xml
    │   ├── res\values\strings.xml (560 个字符串)
    │   ├── smali\s\h\e\l\l\ (3 个 stub: C/N/S)
    │   ├── original\META-INF\ (CPA.RSA / CPA.SF / MANIFEST.MF)
    │   └── unknown\ (Log4j / firebase / multidex 元配置)
    └── jadx_out\
        ├── sources\com\cmss\cloudcomputer\R.java
        ├── sources\s\h\e\l\l\{C,N,S}.java
        ├── sources\kotlin\coroutines\jvm\internal\DebugProbesKt.java
        └── resources\
```

---

## 11. 结论

`PCAS_App` v3.6.2 是中国移动云电脑 Android arm64 客户端：

1. **业务面**：完整覆盖云电脑客户端全场景（个人/政企/学习空间/池化/独享/GPU/UOS Linux 桌面），含 80 个 CEM Web API + 108 个 VDP gRPC RPC + RustDesk 全协议栈。
2. **技术栈**：Flutter UI + 爱加密 SecLLVM VMP 加固 + H3C VDI 2.0 SDK（VDP/SPICE）+ 中兴 ZTE mSPICE/RAP/QoE + 内嵌 RustDesk plugin。
3. **关键安全问题**：
   - 内嵌 RSA-1024 私钥（业务层"加密"无效）
   - 生产 APK 内含 `pcas-test-back.cloudtrust.com.cn` / 东莞 H3C 内部 admin / 10.253 内网 IP / 测试 OSS 等敏感信息
   - 信任用户级 CA + 允许明文 + 无 SPKI pinning → mitm 易接入
   - OpenSSL 三版本碎片化共存（含已停维护的 1.1）
   - 业务残留 DES 弱加密
4. **加固成熟度评估**：约 6/10。整壳保护到位，但应用层加密与传输安全工程实践不足，且测试/内部信息泄露超出可接受范围。

> **本报告所有结论仅基于公开可下载 APK 的离线静态分析**。所有"加固建议"面向 PCAS_App 自身改进；如需进一步动态行为确认，请在自有授权测试环境内进行（限速 ≤ 1 req/s、仅 GET/HEAD、不绕过认证）。
