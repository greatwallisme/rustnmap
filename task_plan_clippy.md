# Task Plan: 修复 Clippy Pedantic 警告

**Created**: 2026-02-19
**Updated**: 2026-02-19
**Goal**: 修复项目中所有 249 个 clippy pedantic 警告
**Constraint**: 不准修改 Cargo.toml 中的 clippy 标准来放宽要求

## 警告统计 (239 个剩余)

| Crate | 警告数 |
|-------|--------|
| rustnmap-cli | 87 |
| rustnmap-fingerprint | 66 |
| rustnmap-core | 66 |
| rustnmap-sdk | 66 |
| rustnmap-api | 66 |
| rustnmap-stateless-scan | 66 |
| rustnmap-benchmarks | 66 |

**注意**: 多个 crate 的警告数显示为 66，这可能是由于共享依赖或输出限制

## 主要警告类型

| 类型 | 描述 |
|------|------|
| cast_lossless | 使用 From trait 替代 as 转换 |
| cast_possible_truncation | 可能截断的类型转换 |
| cast_sign_loss | 符号丢失 |
| cast_possible_wrap | 值环绕 |
| doc_markdown | 文档中缺少反引号 |
| single_match_else | 使用 if let 替代单分支 match |
| unnecessary_wraps | 不必要的 Option 包装 |
| unused_self | 未使用的 self 参数 |

## 修复进度

### rustnmap-fingerprint (进行中)
- [x] calculate_variance - 添加 cast 相关的 allow 属性
- [x] calculate_isr - 添加 cast 相关的 allow 属性
- [x] classify_timestamp_rate - 添加 unnecessary_wraps allow
- [x] analyze_ip_id_patterns - 改为关联函数

## 下一步

继续修复 rustnmap-fingerprint 中的剩余警告，然后依次处理其他 crate。
