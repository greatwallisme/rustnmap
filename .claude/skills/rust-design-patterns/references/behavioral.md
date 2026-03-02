# Behavioral Design Patterns

Source: fadeevab/design-patterns-rust + rust-unofficial/patterns, comprehensive compilation

## Table of Contents
1. [Command](#command)
2. [Strategy](#strategy)
3. [Observer](#observer)
4. [State](#state)
5. [Iterator](#iterator)
6. [Visitor](#visitor)
7. [Template Method](#template-method)
8. [Chain of Responsibility](#chain-of-responsibility)
9. [Mediator](#mediator)
10. [Interpreter](#interpreter)
11. [Memento](#memento)

---

## Command

**Intent**: Encapsulate operations as objects, supporting undo/redo, operation queues, and logging.

### Approach A: Trait Objects (Supports Undo)

```rust
pub trait Command {
    fn execute(&self);
    fn undo(&self);
    fn name(&self) -> &str;
}

pub struct CommandHistory {
    history: Vec<Box<dyn Command>>,
}

impl CommandHistory {
    pub fn execute(&mut self, cmd: Box<dyn Command>) {
        cmd.execute();
        self.history.push(cmd);
    }

    pub fn undo(&mut self) {
        if let Some(cmd) = self.history.pop() {
            println!("Undoing: {}", cmd.name());
            cmd.undo();
        }
    }
}

// Concrete command
pub struct CreateTableCommand { table_name: String }
impl Command for CreateTableCommand {
    fn execute(&self) { println!("CREATE TABLE {}", self.table_name); }
    fn undo(&self) { println!("DROP TABLE {}", self.table_name); }
    fn name(&self) -> &str { "CreateTable" }
}
```

### Approach B: Function Pointers/Closures (Simpler when no undo needed)

```rust
type CommandFn = Box<dyn Fn() + Send>;

struct Scheduler {
    queue: Vec<CommandFn>,
}

impl Scheduler {
    fn schedule(&mut self, cmd: impl Fn() + Send + 'static) {
        self.queue.push(Box::new(cmd));
    }

    fn run_all(&mut self) {
        for cmd in self.queue.drain(..) { cmd(); }
    }
}
```

**Selection criteria**: Need undo/redo -> Trait object approach. Just execute -> Closure approach is simpler.

---

## Strategy

**Intent**: Define a family of algorithms, making them interchangeable at runtime.

**Rust-specific note**: Strategy is the most over-engineered GoF pattern. Rust's traits and closures can often directly replace it.

### Approach A: Trait Objects (Runtime Strategy Selection)

```rust
pub trait SortStrategy {
    fn sort(&self, data: &mut Vec<i32>);
    fn name(&self) -> &str;
}

pub struct Sorter {
    strategy: Box<dyn SortStrategy>,
}

impl Sorter {
    pub fn new(strategy: Box<dyn SortStrategy>) -> Self { Self { strategy } }
    pub fn sort(&self, data: &mut Vec<i32>) { self.strategy.sort(data); }
    pub fn set_strategy(&mut self, strategy: Box<dyn SortStrategy>) {
        self.strategy = strategy;
    }
}

struct QuickSort;
impl SortStrategy for QuickSort {
    fn sort(&self, data: &mut Vec<i32>) { data.sort_unstable(); }
    fn name(&self) -> &str { "quicksort" }
}
```

### Approach B: Generic Parameter (Compile-time, Zero Cost)

```rust
pub fn process<S: SortStrategy>(data: &mut Vec<i32>, strategy: &S) {
    strategy.sort(data);
}
// Compiler generates specialized code for each S, no vtable overhead
```

### Approach C: Closures (Simplest, for Simple Strategies)

```rust
pub fn transform(data: &[i32], strategy: impl Fn(i32) -> i32) -> Vec<i32> {
    data.iter().map(|&x| strategy(x)).collect()
}

// Usage:
let doubled = transform(&data, |x| x * 2);
let squared = transform(&data, |x| x * x);
```

**Decision rules**:
- Strategy has multiple methods/carries state -> Trait objects
- Strategy determined at compile time -> Generics (zero cost)
- Strategy is a single function -> Use closure `Fn(...)` directly

---

## Observer

**Intent**: When one object's state changes, automatically notify all observers that depend on it.

### Approach A: Trait Object Observer List

```rust
pub trait Observer {
    fn on_event(&self, event: &Event);
}

pub struct EventBus {
    observers: Vec<Box<dyn Observer>>,
}

impl EventBus {
    pub fn subscribe(&mut self, observer: Box<dyn Observer>) {
        self.observers.push(observer);
    }

    pub fn publish(&self, event: &Event) {
        for observer in &self.observers {
            observer.on_event(event);
        }
    }
}
```

### Approach B: Message Channels (Recommended for Multi-threaded/Async)

```rust
use std::sync::mpsc;

#[derive(Clone)]
pub struct EventBus {
    sender: mpsc::Sender<Event>,
}

impl EventBus {
    pub fn new() -> (Self, mpsc::Receiver<Event>) {
        let (tx, rx) = mpsc::channel();
        (Self { sender: tx }, rx)
    }

    pub fn emit(&self, event: Event) {
        let _ = self.sender.send(event);
    }
}

// Observer consumes in separate thread
thread::spawn(move || {
    for event in receiver {
        handle(event);
    }
});
```

### Warning: Common Pitfall - Borrow Cycles

```rust
// WRONG: Leads to borrow cycles or Rc<RefCell<>> nightmares
struct Button { listeners: Vec<Rc<RefCell<dyn Listener>>> }
struct Form { button: Button }
impl Listener for Form { ... }
// Form holds Button, Button holds reference to Form -> circular reference

// CORRECT: Use Weak<T> to break the cycle
struct Button { listeners: Vec<Weak<dyn Listener>> }
```

**Architecture advice**: If observers need back-references to subjects, prioritize redesigning ownership, or use channels for decoupling.

---

## State

**Intent**: Object behavior changes based on internal state.

### Approach A: Enum (Recommended, for Simple/Medium State Machines)

Rust enums are the natural way to implement state machines - type-safe with zero runtime overhead:

```rust
enum PlayerState {
    Stopped,
    Playing { track: String, position: Duration },
    Paused { track: String, position: Duration },
}

struct MusicPlayer {
    state: PlayerState,
}

impl MusicPlayer {
    fn play(&mut self, track: String) {
        self.state = match mem::replace(&mut self.state, PlayerState::Stopped) {
            PlayerState::Stopped => PlayerState::Playing {
                track,
                position: Duration::ZERO,
            },
            PlayerState::Paused { track: t, position } => PlayerState::Playing {
                track: t,
                position,
            },
            playing @ PlayerState::Playing { .. } => playing,  // Already playing, no-op
        };
    }

    fn pause(&mut self) {
        self.state = match mem::replace(&mut self.state, PlayerState::Stopped) {
            PlayerState::Playing { track, position } => PlayerState::Paused { track, position },
            other => other,
        };
    }

    fn is_playing(&self) -> bool {
        matches!(self.state, PlayerState::Playing { .. })
    }
}
```

### Approach B: Trait Objects (OOP Style, for States with Very Different Behaviors)

Key technique: `self: Box<Self>` consumes current state, returns new state (ownership transfer simulates state transition):

```rust
pub trait TrafficState {
    fn next(self: Box<Self>) -> Box<dyn TrafficState>;
    fn display(&self) -> &str;
    fn duration(&self) -> Duration;
}

struct RedLight;
struct YellowLight;
struct GreenLight;

impl TrafficState for RedLight {
    fn next(self: Box<Self>) -> Box<dyn TrafficState> { Box::new(GreenLight) }
    fn display(&self) -> &str { "STOP" }
    fn duration(&self) -> Duration { Duration::from_secs(30) }
}

impl TrafficState for GreenLight {
    fn next(self: Box<Self>) -> Box<dyn TrafficState> { Box::new(YellowLight) }
    fn display(&self) -> &str { "GO" }
    fn duration(&self) -> Duration { Duration::from_secs(25) }
}

pub struct TrafficLight {
    state: Box<dyn TrafficState>,
}

impl TrafficLight {
    pub fn transition(&mut self) {
        let old = mem::replace(&mut self.state, Box::new(RedLight));
        self.state = old.next();
    }
}
```

**Selection criteria**:
- Fixed number of states, moderate behavioral differences -> Enum (faster, simpler, compile-time exhaustiveness checking)
- States need many independent methods, or states themselves carry complex logic -> Trait objects
- Very complex state machine (10+ states, many transition rules) -> Consider `sm`/`rustfsm` crates

---

## Iterator

**Intent**: Sequentially access elements of an aggregate object without exposing its internal representation.

**Rust-specific note**: This pattern is built into the language. Implementing the `Iterator` trait IS implementing the Iterator pattern.

```rust
struct Fibonacci {
    curr: u64,
    next: u64,
}

impl Fibonacci {
    fn new() -> Self { Self { curr: 0, next: 1 } }
}

impl Iterator for Fibonacci {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        let result = self.curr;
        (self.curr, self.next) = (self.next, self.curr + self.next);
        Some(result)  // Fibonacci sequence is infinite, never returns None
    }
}

// After implementing Iterator, automatically get all adapter methods:
let sum_of_first_10: u64 = Fibonacci::new().take(10).sum();
let evens: Vec<u64> = Fibonacci::new().take(20).filter(|&x| x % 2 == 0).collect();
```

**Best practices for custom iterators**:
- Infinite sequences -> Always return `Some`, caller uses `.take(n)` to truncate
- Finite sequences -> Return `None` when exhausted
- Consider implementing `DoubleEndedIterator` (supports traversal from both ends) and `ExactSizeIterator` (known length)
- If iteration needs references to original collection, pay attention to lifetime annotations when `Item = &T`

---

## Visitor

**Intent**: Define new operations on elements without modifying element classes.

**Use cases**: Stable data structure + frequently changing operations (e.g., AST processing, document format conversion).

```rust
// Stable data structure
pub enum Expr {
    Number(f64),
    BinaryOp { op: Op, left: Box<Expr>, right: Box<Expr> },
    Variable(String),
}

pub enum Op { Add, Sub, Mul, Div }

// Visitor trait: one visit method per node type
pub trait ExprVisitor {
    type Output;
    fn visit_number(&self, n: f64) -> Self::Output;
    fn visit_binary_op(&self, op: &Op, left: &Expr, right: &Expr) -> Self::Output;
    fn visit_variable(&self, name: &str) -> Self::Output;
}

impl Expr {
    pub fn accept<V: ExprVisitor>(&self, visitor: &V) -> V::Output {
        match self {
            Expr::Number(n) => visitor.visit_number(*n),
            Expr::BinaryOp { op, left, right } => visitor.visit_binary_op(op, left, right),
            Expr::Variable(name) => visitor.visit_variable(name),
        }
    }
}

// Concrete visitor 1: Evaluator
pub struct Evaluator<'a> {
    variables: &'a HashMap<String, f64>,
}

impl<'a> ExprVisitor for Evaluator<'a> {
    type Output = Result<f64, EvalError>;

    fn visit_number(&self, n: f64) -> Self::Output { Ok(n) }

    fn visit_binary_op(&self, op: &Op, left: &Expr, right: &Expr) -> Self::Output {
        let l = left.accept(self)?;
        let r = right.accept(self)?;
        match op {
            Op::Add => Ok(l + r),
            Op::Sub => Ok(l - r),
            Op::Mul => Ok(l * r),
            Op::Div => if r == 0.0 { Err(EvalError::DivByZero) } else { Ok(l / r) },
        }
    }

    fn visit_variable(&self, name: &str) -> Self::Output {
        self.variables.get(name).copied().ok_or(EvalError::UnboundVariable(name.to_string()))
    }
}

// Concrete visitor 2: Pretty printer (add new operations without modifying Expr)
pub struct PrettyPrinter;
impl ExprVisitor for PrettyPrinter {
    type Output = String;
    fn visit_number(&self, n: f64) -> String { n.to_string() }
    fn visit_binary_op(&self, op: &Op, left: &Expr, right: &Expr) -> String {
        format!("({} {} {})", left.accept(self), op.symbol(), right.accept(self))
    }
    fn visit_variable(&self, name: &str) -> String { name.to_string() }
}
```

---

## Template Method

**Intent**: Define algorithm skeleton in base class, defer some steps to subclasses.

**Rust implementation**: Trait default methods = skeleton algorithm. Implementers only override steps needing customization.

```rust
pub trait DataProcessor {
    // Required steps (no default implementation)
    fn read_data(&self) -> Vec<u8>;
    fn write_data(&self, data: Vec<u8>);

    // Optional override steps (default implementation)
    fn validate(&self, data: &[u8]) -> bool { !data.is_empty() }
    fn transform(&self, data: Vec<u8>) -> Vec<u8> { data }  // Default: return as-is

    // Template method: algorithm skeleton, final (trait can't prevent override, but convention says don't)
    fn process(&self) -> Result<(), ProcessError> {
        let data = self.read_data();
        if !self.validate(&data) {
            return Err(ProcessError::InvalidData);
        }
        let processed = self.transform(data);
        self.write_data(processed);
        Ok(())
    }
}

struct CsvProcessor { path: String }
impl DataProcessor for CsvProcessor {
    fn read_data(&self) -> Vec<u8> { std::fs::read(&self.path).unwrap_or_default() }
    fn write_data(&self, data: Vec<u8>) { std::fs::write(&self.path, data).unwrap(); }
    fn transform(&self, data: Vec<u8>) -> Vec<u8> {
        // Custom transformation: UTF-8 -> process CSV
        normalize_csv(data)
    }
}
```

---

## Chain of Responsibility

**Intent**: Request passes along a chain of handlers until one handles it.

```rust
pub trait Handler {
    fn handle(&self, request: &Request) -> Option<Response>;
}

pub struct Chain {
    handlers: Vec<Box<dyn Handler>>,
}

impl Chain {
    pub fn add(mut self, handler: impl Handler + 'static) -> Self {
        self.handlers.push(Box::new(handler));
        self
    }

    pub fn handle(&self, request: &Request) -> Option<Response> {
        self.handlers.iter().find_map(|h| h.handle(request))
    }
}

// Concrete handlers
struct CacheHandler { cache: HashMap<String, Response> }
struct AuthHandler { token: String }
struct ApiHandler;

impl Handler for CacheHandler {
    fn handle(&self, req: &Request) -> Option<Response> {
        self.cache.get(&req.url).cloned()  // Return if hit, otherwise pass
    }
}

impl Handler for AuthHandler {
    fn handle(&self, req: &Request) -> Option<Response> {
        if req.token != self.token {
            Some(Response::unauthorized())  // Intercept unauthorized requests
        } else {
            None  // Authorization passed, continue
        }
    }
}

// Build chain
let chain = Chain::default()
    .add(CacheHandler::new())
    .add(AuthHandler::new(token))
    .add(ApiHandler);
```

---

## Mediator

**HARDEST GoF PATTERN TO IMPLEMENT IN RUST**

**Root problem**: Classic Mediator requires components to hold mutable references to the mediator, while the mediator holds mutable references to all components - this directly violates Rust's borrowing rules in safe code.

### Approach A: Mediator Owns Components (Recommended)

Redesign ownership: mediator owns components, components don't hold references to mediator:

```rust
struct Mediator {
    component_a: ComponentA,
    component_b: ComponentB,
    component_c: ComponentC,
}

enum Event { ATriggered(String), BTriggered(u32) }

impl Mediator {
    fn notify(&mut self, event: Event) {
        match event {
            Event::ATriggered(data) => {
                let result = self.component_b.process(&data);
                self.component_c.display(result);
            }
            Event::BTriggered(value) => {
                self.component_a.update(value);
            }
        }
    }
}

impl ComponentA {
    fn do_something(&self) -> Event {
        // Produce event, but don't directly call other components
        Event::ATriggered("data".to_string())
    }
}
```

### Approach B: Message Channels (For Async/Threaded Scenarios)

```rust
use std::sync::mpsc;

#[derive(Clone)]
struct Mediator {
    sender: mpsc::Sender<Event>,
}

// Each component holds a cloned Sender
struct ComponentA { mediator: Mediator }
impl ComponentA {
    fn trigger(&self) {
        self.mediator.sender.send(Event::ATriggered).unwrap();
    }
}

// Mediator logic runs on receive side
fn run_mediator(receiver: mpsc::Receiver<Event>, mut b: ComponentB, mut c: ComponentC) {
    for event in receiver {
        match event {
            Event::ATriggered => { b.react(); c.update(); }
            // ...
        }
    }
}
```

### Approach C: `Rc<RefCell<>>` Shared Mutability (For Single-threaded, Accept Runtime Borrow Checking)

```rust
use std::rc::{Rc, Weak};
use std::cell::RefCell;

struct Mediator {
    components: Vec<Weak<RefCell<dyn Component>>>,
}

impl Mediator {
    fn notify(&self, event: &Event) {
        for weak in &self.components {
            if let Some(comp) = weak.upgrade() {
                comp.borrow_mut().react(event);
            }
        }
    }
}

struct ConcreteComponent {
    mediator: Weak<RefCell<Mediator>>,
}
```

**Architecture advice**: Prioritize Approach A (ownership restructuring). If not feasible, consider channels. `Rc<RefCell<>>` as last resort - it has runtime panic risk.

---

## Interpreter

**Intent**: Define grammar representation for a language, and implement an interpreter for that grammar.

**Rust advantage**: Enums naturally express recursive syntax structures (AST).

```rust
#[derive(Debug, Clone)]
pub enum Expr {
    Integer(i64),
    Boolean(bool),
    Variable(String),
    BinaryOp { op: BinOp, lhs: Box<Expr>, rhs: Box<Expr> },
    If { condition: Box<Expr>, then_expr: Box<Expr>, else_expr: Box<Expr> },
    Let { name: String, value: Box<Expr>, body: Box<Expr> },
}

#[derive(Debug, Clone)]
pub enum BinOp { Add, Sub, Mul, Eq, Lt }

#[derive(Debug, Clone)]
pub enum Value { Int(i64), Bool(bool) }

type Env = HashMap<String, Value>;

pub fn eval(expr: &Expr, env: &Env) -> Result<Value, EvalError> {
    match expr {
        Expr::Integer(n) => Ok(Value::Int(*n)),
        Expr::Boolean(b) => Ok(Value::Bool(*b)),
        Expr::Variable(name) => env.get(name).cloned().ok_or(EvalError::UnboundVar(name.clone())),
        Expr::BinaryOp { op, lhs, rhs } => {
            let l = eval(lhs, env)?;
            let r = eval(rhs, env)?;
            apply_binop(op, l, r)
        }
        Expr::If { condition, then_expr, else_expr } => {
            match eval(condition, env)? {
                Value::Bool(true) => eval(then_expr, env),
                Value::Bool(false) => eval(else_expr, env),
                _ => Err(EvalError::TypeMismatch),
            }
        }
        Expr::Let { name, value, body } => {
            let v = eval(value, env)?;
            let mut new_env = env.clone();
            new_env.insert(name.clone(), v);
            eval(body, &new_env)
        }
    }
}
```

---

## Memento

**Intent**: Capture object's internal state without breaking encapsulation, for later restoration.

```rust
// Simple version: Clone IS Memento
#[derive(Clone)]
pub struct EditorState {
    content: String,
    cursor: (usize, usize),
    selection: Option<(usize, usize)>,
}

pub struct Editor {
    state: EditorState,
    history: Vec<EditorState>,
    future: Vec<EditorState>,  // Supports redo
}

impl Editor {
    pub fn execute(&mut self, action: EditAction) {
        self.future.clear();
        let snapshot = self.state.clone();
        action.apply(&mut self.state);
        self.history.push(snapshot);
    }

    pub fn undo(&mut self) {
        if let Some(prev) = self.history.pop() {
            let current = std::mem::replace(&mut self.state, prev);
            self.future.push(current);
        }
    }

    pub fn redo(&mut self) {
        if let Some(next) = self.future.pop() {
            let current = std::mem::replace(&mut self.state, next);
            self.history.push(current);
        }
    }
}

// Complex state: serialize to snapshot with serde
#[cfg(feature = "persistence")]
impl Editor {
    pub fn save_to_disk(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&self.state)
    }
    pub fn restore_from_disk(&mut self, data: &[u8]) -> Result<(), serde_json::Error> {
        self.state = serde_json::from_slice(data)?;
        Ok(())
    }
}
```
