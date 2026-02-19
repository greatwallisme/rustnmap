# Task Plan: 修复测试和 Clippy 警告

**Created**: 2026-02-18
**Last Updated**: 2026-02-19
**Goal**: 修复项目中所有失败的测试和 clippy pedantic 警告，保持零警告标准

## Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 1. 诊断问题 | COMPLETE | 运行测试和 clippy 获取所有错误和警告 |
| 2. 修复测试 | COMPLETE | 所有测试通过 (700+ 测试，2 个需要 root 权限的测试除外) |
| 3. 修复 Clippy | COMPLETE | 修复所有基本和 pedantic 警告 |
| 4. 验证结果 | COMPLETE | 零警告零错误验证通过 |

## 错误记录

### 测试失败
✅ 所有测试通过 (700+ 测试)
- 2 个失败测试需要 root 权限 (raw socket 测试)

### Clippy 警告修复进度

**最终状态**: ✅ 零警告零错误

**基本 clippy**: 0 警告
**pedantic clippy**: 0 警告

**本次修复的问题**：
- ✅ 编译错误: 不必要的 .await 调用 (cli.rs)
- ✅ `strict_comparison_of_floats` - 浮点数严格比较 (database.rs)
- ✅ `long_literal_without_separators` - 数字字面量分隔符 (tls_certificate_test.rs)
- ✅ `default_trait_access` - 使用 Type::default() (database_updater_test.rs, tls_certificate_test.rs)
- ✅ `used_underscore_binding` - 移除 underscore 前缀绑定 (database_updater_test.rs)
- ✅ `match_same_arms` - 合并相同 match 分支 (service_detection_integration_tests.rs)
- ✅ `unused_async` - 移除未使用的 async (cli.rs: write_all_formats, output_results)
- ✅ `unnecessary_wraps` - 移除不必要的 Result 返回 (cli.rs: handle_generate_profile_command)
- ✅ `cast_possible_truncation` / `cast_sign_loss` - 类型转换安全修复 (os_detection*.rs)
- ✅ `manual_abs_diff` - 使用 abs_diff() 方法 (os_detection*.rs)
- ✅ `match_wild_err_arm` - 使用 Err(ref e) 代替 Err(_) (cli.rs)
- ✅ `single_match_else` - 使用 if let 代替 match (service_detection_integration_tests.rs)

## 关键决策

- ✅ 不允许修改 Cargo.toml 放宽 clippy 标准
- ✅ 所有修复都是代码改进，不是简单 suppress 警告
- ✅ 保持测试代码同样符合 clippy 标准
