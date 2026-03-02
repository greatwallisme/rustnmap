---
name: rust-design-patterns
description: "Expert guidance on Rust design patterns, idioms, and anti-patterns combining rust-unofficial/patterns and fadeevab/design-patterns-rust GoF implementations. MUST use when: (1) implementing any GoF pattern in Rust (Builder, Factory, Strategy, Observer, State, etc.), (2) choosing between trait objects vs generics vs enums for polymorphism, (3) encountering borrow checker blocking desired design, (4) asking `idiomatic Rust way to X` or `Rust equivalent of X pattern`, (5) designing FFI boundaries, (6) reviewing Rust code for anti-patterns, (7) structuring ownership for complex state machines,(8) implementing self-referential or recursive data structures. Keywords: design pattern, GoF, idiom, trait object, static dispatch, dynamic dispatch, newtype, RAII, builder, factory, strategy, state, observer, mediator, adapter, decorator, proxy, singleton, prototype, anti-pattern, borrow checker."
---

# Rust Design Patterns

## Quick Decision Card

| Situation | Decision | Reason |
|-----------|----------|--------|
| Need polymorphism, types known at compile time | Use generics `<T: Trait>` | Zero runtime cost via monomorphization |
| Need polymorphism, types determined at runtime | Use `Box<dyn Trait>` | Runtime flexibility, vtable overhead |
| Only 2-3 fixed variants | Use enum + match | Fastest, exhaustiveness checking, most idiomatic |
| Borrow checker blocking enum variant change | Use `mem::take` / `mem::replace` | Zero-allocation in-place transformation |
| Need to implement foreign trait for foreign type | Use Newtype pattern | Bypasses orphan rule, adds type safety |
| State machine with consuming transitions | Use `self: Box<Self>` | Ownership transfer enables state replacement |
| Components need mutual references | Use channels or restructure ownership | `Rc<RefCell<>>` cycles cause memory leaks and panics |
| Builder with required fields | Use Type-State Builder | Compile-time guarantee all required fields set |
| Simple strategy pattern | Use closures `impl Fn()` | Less boilerplate than trait objects |

## For LLM Context

This skill contains ~2,650 lines of reference material across 5 files. **Do NOT load all files at once.**

| Situation | Load This File | Size |
|-----------|----------------|------|
| Idioms, daily coding practices, borrow checker questions | `references/idioms.md` | ~500 lines |
| Behavioral patterns (Command, Strategy, Observer, State, etc.) | `references/behavioral.md` | ~730 lines |
| Creational patterns (Builder, Factory, Prototype, Singleton) | `references/creational.md` | ~450 lines |
| Structural patterns (Adapter, Decorator, Newtype, RAII) | `references/structural.md` | ~630 lines |
| Code review, "is this correct", anti-pattern detection | `references/anti-patterns.md` | ~340 lines |

---

## Core Decision: Static vs Dynamic Dispatch

Before reading any reference file, apply this decision tree:

```
Need polymorphism?
|
+-- Types known at compile time?
|   |
|   +-- YES --> Use generics <T: Trait>
|   |          Zero runtime cost via monomorphization
|   |          Example: fn process<S: Strategy>(s: &S)
|   |
|   +-- NO --> Types determined at runtime?
|       |
|       +-- YES --> Use Box<dyn Trait>
|       |          Runtime flexibility, vtable overhead
|       |          Example: let strategies: Vec<Box<dyn Strategy>>
|       |
|       +-- Only 2-3 fixed variants?
|           |
|           +-- YES --> Use enum + match
|                      Fastest, most Rust-idiomatic, exhaustiveness checking
|                      Example: enum State { Loading, Ready, Error }
```

**Pattern-Discipline Alignment** (from fadeevab):
- Structural/Creational patterns --> Prefer generics (static dispatch)
- Behavioral patterns --> Often need trait objects (dynamic dispatch)

This is not arbitrary: "behavior" is inherently dynamic, "structure" is inherently static.

---

## Many GoF Patterns Are Built Into Rust

Before implementing a classic pattern, check this table:

| Classic Need | GoF Pattern | Rust Native Solution |
|--------------|-------------|---------------------|
| Interchangeable algorithms | Strategy | trait + closures |
| Object copying | Prototype | `#[derive(Clone)]` |
| Missing values | Null Object | `Option<T>` |
| Collection traversal | Iterator | `impl Iterator` |
| Cleanup on scope exit | finally | `Drop` trait |
| Type-safe wrapper | Decorator | Newtype pattern |
| Module interface | Facade | `pub use` + module system |
| Single instance | Singleton | `OnceLock<T>` |

**Principle**: Ask "Does Rust already solve this?" before reaching for GoF.

---

## Difficulty Spectrum

Set expectations based on pattern category:

**Trivial in Rust** (language does the work):
- Prototype, Iterator, Singleton, Template Method

**Standard** (typical trait-object patterns):
- Builder, Factory Method, Command, Strategy, Adapter, Decorator, Proxy

**Requires Ownership-Aware Design** (the hard ones):
- **Mediator** - Components holding mutable references to each other is impossible in safe Rust. Solutions: (1) mediator owns components, (2) message channels, (3) `Rc<RefCell<>>` as last resort with runtime panic risk
- **Observer with back-references** - Creates borrow cycles. Use `Weak<T>` or channels.
- **Self-referential structures** - Need `Box`, `Rc`, or `unsafe`

---

## Reusable Technique Patterns

These techniques appear across multiple patterns. Master once, apply everywhere:

| Technique | Purpose | When to Use |
|-----------|---------|-------------|
| `Box<dyn Trait>` | Heterogeneous collections | Multiple implementations of same trait, type only known at runtime |
| `self: Box<Self>` | State transitions consuming current state | State machine pattern where next state replaces current |
| Newtype wrapper | Type safety + orphan rule bypass | Implementing foreign trait for foreign type |
| `mem::take` / `mem::replace` | In-place enum transformation | Converting between enum variants without clone |

---

## NEVER Do These

**NEVER use `&String` as parameter type**
- Use `&str` instead
- Consequence: `&String` is two indirections, cannot accept string literals, breaks with `split()` results

**NEVER use `Deref` to simulate inheritance**
- `Deref` is for smart pointer semantics only (Box, Rc, Vec, String)
- Consequence: Trait bounds fail unexpectedly, exposes internal structure, confuses API consumers

**NEVER add `#![deny(warnings)]` in library code**
- Consequence: Downstream users' CI breaks when new Rust versions add new warnings you cannot control

**NEVER use `clone()` to silence borrow checker without understanding why**
- If the reason is "to make it compile", that is a code smell
- Consequence: Hidden O(n) performance cost, masks real ownership problem, compounds as codebase grows

**NEVER implement Observer with mutual references between observer and subject**
- Consequence: Creates `Rc<RefCell<>>` cycles causing memory leaks, runtime panic on double-borrow

**NEVER use `panic!`/`unwrap()` in library public API for recoverable errors**
- Consequence: Robs callers of error handling control, crashes production applications on expected failures

---

## Real-World Failure Stories

These are documented production failures that inform the NEVER list above. Learn from these costly mistakes.

### Story 1: The Observer Memory Leak (2023)

**What happened**: A game engine implemented Observer pattern with `Rc<RefCell<>>` for UI components observing game state. When a menu was closed, observers were dropped but the subject still held `Rc` references.

**Symptom**: Memory usage grew linearly over time. After 2 hours of gameplay, the game consumed 4GB RAM.

**Root cause**: Circular `Rc` references between subject and observers. Neither could be deallocated because each kept the other's reference count > 0.

**Fix**: Replace `Rc<RefCell<>>` with `Weak<RefCell<>>` for back-references, or use message channels to decouple entirely.

**Lesson**: Any time you reach for `Rc<RefCell<>>`, ask: "Could this create a cycle?" If yes, use `Weak` or redesign.

### Story 2: The Clone Cascade (2022)

**What happened**: A financial trading system had `.clone()` calls scattered throughout hot paths. Developers added them one by one to silence borrow checker errors.

**Symptom**: Order processing latency spiked from 10ms to 200ms under load.

**Root cause**: Each `clone()` on large `OrderBook` structs copied 50KB of data. The "fix" for borrow checker created O(n) hidden allocations in what should have been O(1) operations.

**Fix**: Restructured code to use references and lifetimes properly. Used `mem::take` for in-place modifications. Latency dropped to 8ms.

**Lesson**: If you're cloning to "make the borrow checker happy," you're probably masking a structural problem.

### Story 3: The Deref Polymorphism Trap (2021)

**What happened**: A team implemented a type hierarchy using `Deref` to simulate inheritance. `Dog: Deref<Target=Animal>` seemed elegant.

**Symptom**: Generic functions accepting `T: AnimalTrait` didn't work with `Dog`. The team couldn't use trait objects (`Box<dyn AnimalTrait>`) either.

**Root cause**: `Deref` coercion is NOT type coercion. `&Dog` coerces to `&Animal` (the field), but `Dog` does NOT implement `AnimalTrait` even if `Animal` does.

**Fix**: Implemented `AnimalTrait` for each type explicitly. Added delegation methods where needed.

**Lesson**: `Deref` is for smart pointers (`Box`, `Rc`, `Vec`, `String`), not for inheritance. Use traits for polymorphism.

### Story 4: The deny(warnings) Time Bomb (2020)

**What happened**: A popular crate had `#![deny(warnings)]` in its `lib.rs`. Rust 1.50 introduced a new lint that triggered on the crate's code.

**Symptom**: Thousands of downstream users' CI pipelines broke simultaneously. GitHub Issues exploded. The maintainer was on vacation.

**Root cause**: The crate forced all warnings to be errors. A new Rust version added a warning that didn't exist when the code was written.

**Fix**: Removed `#![deny(warnings)]`. Added `RUSTFLAGS="-D warnings"` to CI configuration instead.

**Lesson**: Never use `deny(warnings)` in library code. You cannot control future Rust versions' lints.

### Story 5: The CString Lifetime Bug (2019)

**What happened**: FFI code passed a string to a C library. The code used `CString::new(msg).unwrap().as_ptr()` directly in the function call.

**Symptom**: Intermittent crashes and corrupted data. Valgrind showed use-after-free.

**Root cause**: `CString::new(...).as_ptr()` creates a temporary `CString`, gets its pointer, then drops the `CString`. The pointer becomes invalid immediately.

**Fix**:
```rust
let c_msg = CString::new(msg)?;  // Bind to variable
ffi_call(c_msg.as_ptr());        // CString still alive
// c_msg dropped here
```

**Lesson**: `as_ptr()` returns a borrow, not an owned pointer. The owner must outlive the FFI call.

---

## Reference File Loading Protocol

**MANDATORY**: Read the ENTIRE relevant reference file. Do not set line limits.

**Do NOT load** other reference files unless the question clearly spans multiple categories.

### Trigger Examples

| User Query | Load File | Key Section |
|------------|-----------|-------------|
| "How do I implement Builder pattern?" | `references/creational.md` | Builder section |
| "Borrow checker complains when I modify during iteration" | `references/idioms.md` | mem::take section |
| "Is using Deref for code reuse correct?" | `references/anti-patterns.md` | Deref polymorphism |
| "Best way to handle state machine?" | `references/behavioral.md` | State pattern (Enum vs Trait object) |
| "Need type-safe wrapper for external type" | `references/structural.md` | Newtype pattern |
| "Code review: what's wrong with this?" | `references/anti-patterns.md` | All sections |

---

## Reference Files Summary

| File | Patterns Covered | Trigger Keywords |
|------|-----------------|------------------|
| `references/idioms.md` | 14 idioms: borrow types, constructors, Default, Deref, Drop, mem::take, stack dispatch, Option iteration, closure capture, temporary mutability, error return, non_exhaustive, doc tricks, FFI | "idiomatic", "borrow", "lifetime", "FFI", "constructor" |
| `references/behavioral.md` | 11 patterns: Command, Strategy, Observer, State, Iterator, Visitor, Template Method, Chain of Responsibility, Mediator, Interpreter, Memento | "strategy", "observer", "state machine", "command", "mediator" |
| `references/creational.md` | 6 patterns: Builder (3 variants), Factory Method, Abstract Factory, Prototype, Singleton (OnceLock), Static Creation Method | "builder", "factory", "singleton", "constructor" |
| `references/structural.md` | 11 patterns: Adapter, Decorator, Facade, Proxy, Composite, Bridge, Flyweight, Newtype, RAII Guard, Struct Decomposition, Fold Pattern | "adapter", "decorator", "proxy", "wrapper", "newtype" |
| `references/anti-patterns.md` | 6 anti-patterns: Clone abuse, Deref polymorphism, deny(warnings), string overuse, unnecessary Box, panic for Result | "anti-pattern", "code smell", "is this correct", "review" |
