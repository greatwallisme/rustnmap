# Clippy Lint Fix Patterns

Quick reference for fixing common clippy lints. Organized by category.

---

## Error Handling

| Lint | Before | After |
|------|--------|-------|
| `unwrap_used` | `map.get("k").unwrap()` | `map.get("k")?` or `map.get("k").copied().unwrap_or_else(\|\| unreachable!("reason"))` |
| `expect_used` | `.expect("msg")` | `?` or proper error handling |
| `question_mark` | `match opt { Some(v) => v, None => return Err(e) }` | `let Some(v) = opt else { return Err(e) };` |
| `manual_let_else` | `if let Some(v) = opt { } else { return }` | `let Some(v) = opt else { return };` |
| `map_err` | `.map_err(\|e\| MyError::from(e))` | `.map_err(MyError::from)` |
| `or_fun_call` | `opt.unwrap_or(Vec::new())` | `opt.unwrap_or_default()` |
| `unwrap_or_default` | `opt.unwrap_or_else(Default::default)` | `opt.unwrap_or_default()` |

---

## Iterators & Collections

| Lint | Before | After |
|------|--------|-------|
| `needless_collect` | `iter.collect::<Vec<_>>().is_empty()` | `iter.next().is_none()` |
| `needless_collect` | `v.iter().collect::<Vec<_>>().len()` | `v.iter().count()` |
| `manual_filter_map` | `.filter(\|x\| x.is_some()).map(\|x\| x.unwrap())` | `.flatten()` |
| `manual_filter_map` | `.filter(\|x\| pred(x)).map(\|x\| f(x))` | `.filter_map(\|x\| pred(x).then(\|\| f(x)))` |
| `filter_map_identity` | `.filter_map(\|x\| x)` | `.flatten()` |
| `unnecessary_fold` | `.fold(0, \|a, x\| a + x)` | `.sum()` |
| `unnecessary_fold` | `.fold(false, \|a, x\| a \|\| f(x))` | `.any(f)` |
| `vec_init_then_push` | `let mut v = Vec::new(); v.push(a); v.push(b);` | `vec![a, b]` |
| `map_unwrap_or` | `opt.map(f).unwrap_or(v)` | `opt.map_or(v, f)` |
| `range_zip_with_len` | `(0..vec.len()).for_each(\|i\| ...)` | `vec.iter().enumerate().for_each(\|(i, x)\| ...)` |
| `iter_nth` | `iter.nth(0)` | `iter.next()` |
| `iter_skip_next` | `iter.skip(n).next()` | `iter.nth(n)` |
| `iter_cloned_collect` | `vec.iter().cloned().collect::<Vec<_>>()` | `vec.to_vec()` |
| `cloned_instead_of_copied` | `iter.cloned()` | `iter.copied()` (for Copy types) |
| `from_iter_instead_of_collect` | `Vec::from_iter(iter)` | `iter.collect::<Vec<_>>()` |

---

## Types & Conversions

| Lint | Before | After |
|------|--------|-------|
| `cast_possible_truncation` | `x as u8` (from larger int) | `u8::try_from(x)?` |
| `cast_sign_loss` | `x as u32` (from signed) | `x.try_into()?` or explicit handling |
| `cast_lossless` | `x as i64` (i32→i64) | `i64::from(x)` |
| `cast_ptr_alignment` | `ptr as *const T` | Use proper alignment checks |
| `as_conversions` | `x as f64` (int to float) | `f64::from(x)` (if safe) |
| `clone_on_ref_ptr` | `arc.clone()` | `Arc::clone(&arc)` |
| `clone_on_copy` | `x.clone()` (Copy type) | `x` |
| `redundant_clone` | `s.clone()` (s unused after) | `s` |
| `unnecessary_to_owned` | `s.to_owned()` (only needs AsRef) | Use `&str` instead |
| `ptr_arg` | `fn f(s: &String)` | `fn f(s: &str)` |
| `borrow_deref_ref` | `&*x` | `x.borrow()` or `&x` |

---

## Strings & Formatting

| Lint | Before | After |
|------|--------|-------|
| `useless_format` | `format!("hello")` | `"hello".to_owned()` |
| `to_string_in_format_args` | `format!("{}", x.to_string())` | `format!("{x}")` |
| `inefficient_to_string` | `s.to_string()` on &str | `s.to_owned()` |
| `format_in_format_args` | `format!("...{}", format!("..."))` | Inline the inner format |
| `string_add` | `s1 + &s2` | `format!("{s1}{s2}")` |
| `str_to_string` | `"text".to_string()` | `"text".to_owned()` |
| `into_bytes_on_ref` | `s.as_bytes().to_vec()` | `s.as_bytes().into()` |

---

## Structs & Enums

| Lint | Before | After |
|------|--------|-------|
| `struct_excessive_bools` | `struct { a: bool, b: bool, c: bool, d: bool }` | Use bitflags or enum |
| `match_wildcard_for_single_variants` | `match e { A => {}, _ => {} }` (enum has 2 variants) | `match e { A => {}, B => {} }` |
| `wildcard_enum_match_arm` | `match e { A => {}, _ => {} }` | List all variants explicitly |
| `single_match` | `match opt { Some(v) => {}, None => {} }` | `if let Some(v) = opt {}` |
| `single_match_else` | `match opt { Some(v) => {}, None => { return } }` | `let Some(v) = opt else { return };` |
| `manual_is_ascii_check` | `('a'..='z').contains(&c)` | `c.is_ascii_lowercase()` |
| `is_digit_ascii_radix` | `c.is_digit(10)` | `c.is_ascii_digit()` |
| `match_like_matches_macro` | `match e { A => true, _ => false }` | `matches!(e, A)` |
| `match_bool` | `match b { true => x, false => y }` | `if b { x } else { y }` |
| `unnecessary_wraps` | `fn f() -> Option<T> { Some(val) }` | `fn f() -> T { val }` |

---

## Performance

| Lint | Before | After |
|------|--------|-------|
| `large_stack_arrays` | `let arr = [0u8; 65536];` | `let vec = vec![0u8; 65536];` |
| `box_collection` | `Box<Vec<T>>` | `Vec<T>` |
| `boxed_local` | `Box::new(small_value)` | `small_value` directly |
| `slow_vector_initialization` | `vec![0; n]` when n is small | Array if known at compile time |
| `inefficient_to_string` | `s.to_string()` on &str | `s.to_owned()` |
| `to_owned_instead_of_clone` | `rc.to_owned()` on Rc | `rc.clone()` |
| `explicit_iter_loop` | `for x in v.iter()` | `for x in &v` |
| `explicit_into_iter_loop` | `for x in v.into_iter()` | `for x in v` |

---

## Documentation & API

| Lint | Before | After |
|------|--------|-------|
| `missing_errors_doc` | `pub fn f() -> Result<T, E>` | Add `# Errors` section |
| `missing_panics_doc` | Function with `assert!`/`panic!` | Add `# Panics` section |
| `must_use_candidate` | Pure function returning value | Add `#[must_use]` |
| `return_self_not_must_use` | Builder pattern method | Add `#[must_use]` |
| `missing_safety_doc` | `pub unsafe fn ...` | Add `# Safety` section |
| `unnecessary_safety_doc` | Safe function with `# Safety` | Remove safety doc |
| `doc_markdown` | Backticks for code in docs | Use proper markdown |
| `missing_docs_in_private_items` | Private items without docs | Add docs or `#[allow]` if internal |

---

## Code Quality

| Lint | Before | After |
|------|--------|-------|
| `too_many_arguments` | `fn f(a, b, c, d, e, f, g, h)` | Group into struct |
| `fn_params_excessive_bools` | Multiple bool parameters | Use flags enum or struct |
| `type_complexity` | Complex return type | Use type alias |
| `cognitive_complexity` | Deeply nested function | Extract functions |
| `too_many_lines` | Long function | Split into smaller functions |
| `panic` | `panic!("msg")` | Proper error handling |
| `todo` | `todo!()` | Implement or proper error |
| `unimplemented` | `unimplemented!()` | Implement or proper error |
| `dbg_macro` | `dbg!(x)` | Proper logging or remove |
| `print_stdout` | `println!()` in library | Use logging crate |
| `expect_fun_call` | `s.expect(&format!("..."))` | `s.unwrap_or_else(\|\| panic!("..."))` |

---

## Pedantic Lints (Selectively Applied)

| Lint | Before | After |
|------|--------|-------|
| `needless_lifetimes` | `fn f<'a>(x: &'a str) -> &'a str` | `fn f(x: &str) -> &str` |
| `elidable_lifetime_names` | `<'data>` | `<'a>` |
| `implicit_hasher` | `HashMap<K, V>` in public API | `HashMap<K, V, S>` |
| `semicolon_if_nothing_returned` | `expr` | `expr;` |
| `shadow_unrelated` | Reuse variable name | Use different name |
| `shadow_same` | `let x = x;` | Remove or rename |

---

## Restriction Lints (Carefully Evaluated)

These may not fit all projects. Judge based on crate type:

| Lint | Recommendation |
|------|----------------|
| `indexing_slicing` | Use `.get()` instead of `[]` - good for libraries |
| `panic` | Avoid panic in libraries, may relax for binaries |
| `unwrap_used` | Already covered - always fix or justify |
| `expect_used` | Same as unwrap_used |
| `exhaustive_structs` | Use `#[non_exhaustive]` for public API structs |
| `implicit_return` | Usually skip - against Rust idioms |
| `shadow_reuse` | Usually skip - acceptable in Rust |
| `float_arithmetic` | Only for crypto/numerical domains |
| `as_conversions` | Use `from()`/`try_from()` where possible |

---

## Cargo Lints

Fix in `Cargo.toml`:

| Lint | Fix |
|------|-----|
| `cargo_common_metadata` | Add description, license, repository |
| `multiple_crate_versions` | Check dependency tree |
| `wildcard_dependencies` | Use specific versions |
| `redundant_feature_names` | Remove redundant feature prefixes |

Required fields:
```toml
[package]
name = "..."
version = "..."
edition = "2021"
rust-version = "1.70"
description = "..."
license = "MIT OR Apache-2.0"
repository = "https://github.com/..."
readme = "README.md"
keywords = ["..."]      # Max 5
categories = ["..."]    # See crates.io/category_slugs
```

---

## Auto-Fix Lints

Some lints can be auto-fixed:

```bash
# Auto-fix applicable lints
cargo clippy --fix --workspace --all-targets --all-features

# Check what would be fixed (dry run)
cargo clippy --fix --workspace --all-targets --all-features --allow-dirty --allow-staged
```

**Always verify auto-fixes didn't break anything.**

---

## Common Patterns Decision Tree

```
Clippy warning about error handling?
├── unwrap_used / expect_used
│   ├── Can propagate error? → Use ?
│   ├── Is it truly impossible? → unwrap_or_else(|| unreachable!("reason"))
│   └── Otherwise → Return Result or Option
├── question_mark
│   └── Use let-else: let Some(x) = opt else { return ... };
└── map_err with closure
    └── Use method reference: .map_err(MyError::from)

Clippy warning about iteration?
├── Collect then iterate → Use iterator directly
├── filter + map with is_some/unwrap → flatten()
├── filter + map with condition → filter_map()
├── fold for sum/product → Use sum()/product()
└── manual loop with index → Use enumerate()

Clippy warning about types?
├── as conversion for widening → Use from()
├── as conversion for narrowing → Use try_from() with error handling
├── clone on Arc/Rc → Use Arc::clone(&arc)
├── clone on Copy type → Just use the value
└── &String parameter → Use &str
```
