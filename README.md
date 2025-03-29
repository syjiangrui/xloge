# XLogE - XLog 日志文件解码器

XLogE 是一个用 Rust 编写的工具，用于解析和解码 XLog 格式的日志文件。这些日志文件通常经过各种编码和压缩方式处理，XLogE 支持多种编码和压缩格式的解码。

## 功能特性

- 支持多种编码和压缩格式：
  - XOR 编码
  - Raw Deflate 压缩
  - Zstd 压缩
  - 分块格式
- 自动检测日志条目结构
- 处理序列号间隔和数据损坏
- 批量处理整个目录中的 `.xlog` 文件
- 详细的日志输出和错误处理

## 支持的日志格式

XLogE 支持多种日志格式类型：

| 魔术字节 | 描述 |
|---------|------|
| 0x03 | XOR 编码 |
| 0x04 | XOR + Raw Deflate 压缩 |
| 0x05 | 分块 + XOR + Raw Deflate 压缩 |
| 0x06 | 无压缩 |
| 0x07 | ECDH/TEA + Raw Deflate 压缩 (部分支持) |
| 0x08 | 无压缩无加密 |
| 0x09 | 仅 Raw Deflate 压缩 |
| 0x0A | ECDH/TEA + Zstd 压缩 (部分支持) |
| 0x0B | 仅 Zstd 压缩 |
| 0x0C | ECDH/TEA + Zstd 压缩 (异步) (部分支持) |
| 0x0D | 仅 Zstd 压缩 (异步) |

## 安装

### 从源码编译

1. 确保已安装 Rust 和 Cargo（[rustup.rs](https://rustup.rs/)）
2. 克隆此仓库：
   ```
   git clone https://github.com/your-username/xloge.git
   cd xloge
   ```
3. 编译发布版本：
   ```
   cargo build --release
   ```
4. 可执行文件将位于 `target/release/xloge`

### 依赖项

XLogE 依赖以下 Rust crate：
- byteorder
- clap
- flate2
- glob
- log
- env_logger
- thiserror
- zstd

## 使用方法

XLogE 提供了简单的命令行接口：

```
xloge [输入文件/目录] [输出文件]
```

### 示例

1. 解码单个文件（自动生成输出文件名）：
   ```
   xloge example.xlog
   ```
   这将创建 `example.log`

2. 解码单个文件并指定输出路径：
   ```
   xloge example.xlog output.log
   ```

3. 解码当前目录中的所有 .xlog 文件：
   ```
   xloge
   ```

4. 解码指定目录中的所有 .xlog 文件：
   ```
   xloge /path/to/logs/
   ```

## 日志级别

可以通过设置 `RUST_LOG` 环境变量控制日志级别：

```
RUST_LOG=debug xloge example.xlog
```

可用的日志级别：error、warn、info、debug、trace

## 错误处理

XLogE 设计为即使在遇到损坏的数据时也能继续操作。当检测到错误时，程序会：
1. 记录错误到日志输出
2. 在输出文件中插入错误标记
3. 尝试找到下一个有效日志条目并继续处理

## 许可证

[待定] - 请添加合适的许可证信息
