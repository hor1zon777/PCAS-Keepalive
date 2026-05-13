# cem double stream 逆向进度

> blutter 已跑通，从 libapp.so 反编出 encoder/decoder/heart_beat_client/connection_request_client 的完整 Dart 源码。

## blutter 编译解决记录

| 步骤 | 方法 |
|---|---|
| 缺 ninja | `pip install ninja` |
| 缺 ICU + Capstone | `python scripts/init_env_win.py`（自动下载） |
| 缺 MSVC Build Tools | 用 `CC=clang-cl.exe CXX=clang-cl.exe RC=llvm-rc.exe CMAKE_LINKER=lld-link.exe` 强制 clang-cl + lld-link 工具链替代 MSVC |
| Dart SDK clone | blutter.py 自动 |
| 反编 | 成功，输出 195 MB asm 反编源码 + Frida script 模板 |

成功后的命令：
```powershell
CC='clang-cl.exe' CXX='clang-cl.exe' RC='llvm-rc.exe' CMAKE_LINKER='lld-link.exe' `
  python blutter.py `
  'E:\Desktop\foldder\Code\Claude\ydy\pcas_out\apktool_out\lib\arm64-v8a' `
  'E:\Desktop\foldder\Code\Claude\ydy\blutter_out'
```

## 从反编源码确认的协议细节

### encoder.dart::DoubleStreamEncoder::encode()

```dart
class DoubleStreamEncoder {
  Uint8List field_7;  // 构造时 AllocateUint8Array + _slowSetRange(0,1,src,0)
  Uint8List field_b;  // 构造时 AllocateUint8Array + _slowSetRange(0,1,src,0)

  Future<Uint8List> encode(DoubleStreamClientCommand cmd) async {
    var b = BytesBuilder();
    b.add(unsignedInt2bytes(0x2468ACF0));        // ← 4 字节 magic
    b.add(this.field_7);                          // ← 2 字节（构造时初始化）
    b.add(this.field_b);                          // ← 2 字节
    b.add(cmd.getCommand());                      // ← 4 字节 cmd_id (BE uint32)
    var data = await cmd.getData();
    var encrypted = await cemRsaEncode(jsonEncode(data));
    var utf8 = Utf8Encoder.convert(encrypted);
    var bd = ByteData(8);
    bd.setUint32(0, utf8.length, Endian.big);    // ← 8 字节（前 4 = utf8 长度 BE）
    b.add(bd.buffer.asUint8List());
    b.add(utf8);                                  // ← 加密 payload
    return b.toBytes();
  }
}
```

### decoder.dart::DoubleStreamDecoder::decode()

```dart
class DoubleStreamDecoder {
  Future<(int, Map<String, dynamic>)> decode(Iterable<int> input) async {
    var bytes = input.toList();
    var hdr = ByteData.sublistView(bytes.sublist(0, 8));
    var cmd_id = hdr.getInt32(0, Endian.big);
    var second = hdr.getInt32(4, Endian.big);    // length 或 seq
    var payload = bytes.skip(8).toList();
    var encrypted = Utf8Codec.decode(payload);
    var json = await cemRsaDecode(encrypted);
    return (cmd_id, jsonDecode(json) as Map<String, dynamic>);
  }
}
```

⚠️ 注意：客户端发送的帧（encoder）有 20 字节 header，服务端推送的帧（decoder）只有 8 字节 header。

### Command 子类

```dart
class ConnectionRequestClientCommand implements DoubleStreamClientCommand {
  String field_7;  // accessTicket（构造时传入）

  @override
  Future<Map<String, dynamic>> getData() async => {
    "ticket": this.field_7,
    "deviceId": await getDeviceUid(),
  };

  @override
  Uint8List getCommand() => Uint8List.fromList([0, 0, 0, 6]);  // cmd_id = 6
}

class HeartBeatClientCommand implements DoubleStreamClientCommand {
  @override
  Future<Map<String, dynamic>> getData() async => {
    "timeStamp": DateTime.now().microsecondsSinceEpoch ~/ 1000,
  };

  @override
  Uint8List getCommand() => Uint8List.fromList([0, 0, 0, 2]);  // cmd_id = 2
}
```

## Python 实现状态

`pcas/cem_stream.py` 已按上述规格实现：

| 函数 | 状态 |
|---|---|
| `encode_frame(cmd_id, data)` | ✓ — 20 字节 header + RSA 加密 utf8 payload |
| `decode_frame(reader)` | ✓ — 8 字节 header + utf8 RSA 解密 |
| `CemStreamClient.connect(ticket, device_uid)` | ✓ — 握手发送 |
| `CemStreamClient.run()` | ✓ — 心跳 + 接收推送循环 |

实测连接 `ecloud.10086.cn:31015`：
- TCP 握手 ✓
- 发送 192 字节 ConnectionRequest 帧 ✓
- 服务端立即 FIN 关闭 ✗

握手帧 header hex：`2468acf0 0000 0000 00000006 000000ac 00000000`

## 还有的小差异（需要抓包对照）

1. **`field_7` / `field_b` 的具体值**：构造函数中 `_slowSetRange(target, 0, 1, growable, 0)` 把 source 的第 1 个元素拷贝到 target。源 growable 看似初始化为 0，但也可能是 2（看 `r0 = 2; StoreField: arr->field_f = r0`）。当前实现假设是 `\x00\x00`。
2. **ConnectionRequest 字段是否完整**：getData 反编只看到 `ticket` 和 `deviceId`。但可能还有其他被 PP 池常量引用的字段我们漏看了。
3. **getDeviceUid() 的真实返回值**：Dart 端调用 `device_info_plus` 包，可能返回 Android device ID 而不是任意 hex 字符串。但既然官方客户端是 Windows 端，这里调用 `getDeviceUid` 可能返回 Windows 机器码（MAC / 主板序列号等格式）。我们生成的 `KA<14-hex>` 格式可能格式不对。

## 下一步：用 mitmproxy 抓首包对照

PCAS_App Windows 客户端没装抓包应该最容易做：

```powershell
# 装 mitmproxy
pip install mitmproxy

# 启动 transparent proxy（监听 31015 转发）
mitmdump --mode reverse:tcp://ecloud.10086.cn:31015 --listen-host 0.0.0.0 --listen-port 31015 -w cem.dump

# 修改 hosts 把 ecloud.10086.cn → 127.0.0.1，让官方客户端连过来
# 启动官方 PCAS_App，会自动尝试连 ecloud.10086.cn:31015
# mitmdump 会记录所有字节到 cem.dump
```

把 cem.dump 第一个 client → server 流的前 200 字节十六进制贴出来，我直接对照 encode_frame() 修正差异。

