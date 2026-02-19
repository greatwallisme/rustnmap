# Rustc Error Fix Patterns

Common Rust compiler errors (E0XXX) and their fixes.

---

## Borrow Checker Errors

### E0382 - Use of Moved Value

```rust
// ERROR
fn process(s: String) {
    consume(s);
    println!("{}", s); // ERROR: value used here after move
}

// FIX 1: Pass reference instead
fn process(s: &str) {
    consume(s);
    println!("{s}");
}

// FIX 2: Clone if ownership needed
fn process(s: String) {
    consume(s.clone());
    println!("{s}");
}

// FIX 3: Return value and reassign
fn process(mut s: String) -> String {
    s.push_str(" modified");
    s
}
```

### E0499 - Multiple Mutable Borrows

```rust
// ERROR
fn bad(slice: &mut [i32]) {
    let a = &mut slice[0];
    let b = &mut slice[1]; // ERROR: cannot borrow `*slice` as mutable more than once
    *a += *b;
}

// FIX 1: Use split methods
fn good(slice: &mut [i32]) {
    if let Some((first, rest)) = slice.split_first_mut() {
        *first += rest.iter().sum::<i32>();
    }
}

// FIX 2: Reborrow after use
fn also_good(slice: &mut [i32]) {
    let a = slice[0];
    let b = &mut slice[1]; // OK, a is Copy, not a borrow
    *b += a;
}
```

### E0502 - Borrow Conflict (Mutable + Immutable)

```rust
// ERROR
let mut v = vec![1, 2, 3];
let first = &v[0];
v.push(4); // ERROR: cannot borrow `v` as mutable because it is also borrowed as immutable

// FIX 1: Shorten borrow lifetime
let mut v = vec![1, 2, 3];
let first = v[0]; // Copy, not borrow
v.push(4);

// FIX 2: Scope the immutable borrow
let mut v = vec![1, 2, 3];
{
    let first = &v[0];
    println!("{first}");
}
v.push(4);

// FIX 3: Clone if needed
let mut v = vec![String::from("a")];
let first = v[0].clone();
v.push(String::from("b"));
```

### E0505 - Cannot Move Out of Borrowed Content

```rust
// ERROR
struct Container { data: String }
fn bad(c: &Container) -> String {
    c.data // ERROR: cannot move out of `c.data` which is behind a shared reference
}

// FIX: Clone or return reference
fn good(c: &Container) -> String {
    c.data.clone()
}

fn also_good(c: &Container) -> &str {
    &c.data
}
```

### E0507 - Cannot Move Out of Shared Reference

```rust
// ERROR
let v: &Vec<String> = &vec!["a".to_string()];
let s: String = v[0]; // ERROR: cannot move out of index of `&Vec<String>`

// FIX: Clone or use as_ref
let s: String = v[0].clone();
// or
let s: &str = &v[0];
```

---

## Lifetime Errors

### E0716 - Temporary Value Dropped While Borrowed

```rust
// ERROR
let s = String::from("hello").as_str(); // ERROR: temporary value dropped while borrowed

// FIX: Extend lifetime
let owned = String::from("hello");
let s = owned.as_str();
```

### E0597 - Value Does Not Live Long Enough

```rust
// ERROR
let r: &i32;
{
    let x = 5;
    r = &x; // ERROR: `x` does not live long enough
}
println!("{}", r);

// FIX: Owned value
let r: i32;
{
    let x = 5;
    r = x; // Copy, not borrow
}
println!("{}", r);
```

### E0621 - Explicit Lifetime Required

```rust
// ERROR
fn first(x: &str, y: &str) -> &str { // ERROR: explicit lifetime required
    if x.len() > y.len() { x } else { y }
}

// FIX: Add lifetime annotation
fn first<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}
```

---

## Trait Errors

### E0277 - Trait Bound Not Satisfied

```rust
// ERROR
fn print_all<T>(items: Vec<T>) {
    for item in &items {
        println!("{}", item); // ERROR: `T` doesn't implement `Display`
    }
}

// FIX: Add trait bound
use std::fmt::Display;
fn print_all<T: Display>(items: &[T]) {
    for item in items {
        println!("{item}");
    }
}

// Or use where clause for complex bounds
fn process<T>(items: &[T])
where
    T: Display + Clone,
{
    // ...
}
```

### E0308 - Mismatched Types

```rust
// ERROR
let x: u32 = -1; // ERROR: expected u32, found i32

// FIX: Try conversion with error handling
let x: u32 = (-1i32).try_into().expect("value must be non-negative");
// or
let x: u32 = (-1i32).try_into()?;

// ERROR
let s: String = "hello"; // ERROR: expected struct `String`, found `&str`

// FIX: Convert
let s: String = "hello".to_owned();
```

### E0369 - Binary Operation Cannot Be Applied

```rust
// ERROR
let a = String::from("hello");
let b = String::from(" world");
let c = a + b; // ERROR: expected &str, found String

// FIX: Borrow or use format!
let c = a + &b;
// or
let c = format!("{a}{b}");
```

---

## Ownership Errors

### E0384 - Cannot Assign Twice to Immutable Variable

```rust
// ERROR
let x = 5;
x = 6; // ERROR: cannot assign twice to immutable variable

// FIX: Use mut
let mut x = 5;
x = 6;
```

### E0594 - Cannot Borrow as Mutable More Than Once

```rust
// ERROR
let mut s = String::from("hello");
let r1 = &mut s;
let r2 = &mut s; // ERROR: cannot borrow `s` as mutable more than once

// FIX: Sequential borrows
let mut s = String::from("hello");
{
    let r1 = &mut s;
    r1.push_str(" world");
}
let r2 = &mut s;
```

---

## Pattern Matching Errors

### E0004 - Non-Exhaustive Patterns

```rust
// ERROR
enum Color { Red, Green, Blue }
match Color::Red {
    Color::Red => println!("red"),
    Color::Green => println!("green"),
} // ERROR: missing `Blue`

// FIX: Exhaustive match or wildcard
match Color::Red {
    Color::Red => println!("red"),
    Color::Green => println!("green"),
    Color::Blue => println!("blue"),
}
// or
match Color::Red {
    Color::Red => println!("red"),
    _ => println!("other"),
}
```

### E0308 - Arms Have Incompatible Types

```rust
// ERROR
let x = match true {
    true => 1,
    false => "no", // ERROR: expected integer, found &str
};

// FIX: Same type in all arms
let x = match true {
    true => 1,
    false => 0,
};
```

---

## Async/Await Errors

### E0728 - Await Only Allowed in Async

```rust
// ERROR
fn fetch() -> String {
    let data = reqwest::get("url").await; // ERROR: `await` is only allowed inside `async` functions
}

// FIX: Make function async
async fn fetch() -> String {
    let data = reqwest::get("url").await;
    // ...
}
```

### E0277 - Future Not Awaited

```rust
// WARNING (often escalated to error in strict mode)
async fn do_something() {}

fn main() {
    do_something(); // WARNING: unused implementer of `Future`
}

// FIX: Await or spawn
async fn main() {
    do_something().await;
}
// or
fn main() {
    tokio::spawn(do_something());
}
```

---

## Module and Visibility Errors

### E0433 - Failed to Resolve Use

```rust
// ERROR
use crate::nonexistent::Module; // ERROR: unresolved import

// FIX: Check path and visibility
use crate::actual::Module; // Correct path
// or make module public
pub mod actual { pub struct Module; }
```

### E0603 - Module is Private

```rust
// ERROR - in consuming code
use crate::internal::Secret; // ERROR: module `internal` is private

// FIX: Make public or re-export
pub use crate::internal::Secret;
```

---

## Generic Errors

### E0207 - Type Parameter Not Used

```rust
// ERROR
struct Wrapper<T> { value: i32 } // ERROR: type parameter `T` is never used

// FIX: Use T or remove
struct Wrapper<T> { value: T }
// or
struct Wrapper { value: i32 }
```

### E0392 - Parameter is Never Used

```rust
// ERROR
struct Phantom<T>(i32); // ERROR: parameter `T` is never used

// FIX: Use PhantomData
use std::marker::PhantomData;
struct Phantom<T>(i32, PhantomData<T>);
```

---

## FFI Errors

### E0133 - Use of Extern Static

```rust
// ERROR
extern "C" {
    static GLOBAL: i32;
}
let x = GLOBAL; // ERROR: use of extern static is unsafe

// FIX: Wrap in unsafe
unsafe {
    let x = GLOBAL;
}
```

### E0308: Mismatched Types in FFI

```rust
// ERROR
extern "C" {
    fn c_function(x: i32); // Wrong type
}

// FIX: Match C types exactly
extern "C" {
    fn c_function(x: libc::c_int);
}
```

---

## Common Fixes Summary

| Error | Common Cause | Fix Pattern |
|-------|-------------|-------------|
| E0382 | Value moved | Use `&T`, clone, or redesign ownership |
| E0499 | Multiple mut borrows | Use split methods, sequential scopes |
| E0502 | Mut + immut conflict | Shorten borrow, copy instead of borrow |
| E0716 | Temporary lifetime | Extend with let binding |
| E0277 | Missing trait bound | Add `<T: Trait>` or `where T: Trait` |
| E0308 | Type mismatch | Convert with `into()`, `try_into()`, or explicit constructors |
| E0004 | Incomplete match | Add missing arms or `_` wildcard |

---

## Error Decision Tree

```
Borrow checker error?
├── E0382 (use after move)
│   ├── Need both values? → Clone
│   ├── Only need to read? → Pass &T
│   └── Transfer ownership? → Redesign API
├── E0499 (multiple mut)
│   ├── Different parts of slice? → split_first_mut, split_at_mut
│   └── Sequential access? → Use blocks to limit borrow scope
└── E0502 (mut + immut)
    ├── Can Copy? → Copy value, don't borrow
    └── Cannot Copy? → Shorten immutable borrow lifetime

Type error?
├── E0277 (missing trait)
│   └── Add trait bound or implement trait
├── E0308 (mismatched)
│   ├── Narrowing? → try_into() with error handling
│   ├── Widening? → from() or into()
│   └── String/&str? → to_owned(), as_str()
└── E0369 (binary op)
    └── Borrow or use format!

Lifetime error?
├── E0716 (temporary dropped)
│   └── Bind to let variable
└── E0597 (not long enough)
    └── Use owned value instead of reference
```
