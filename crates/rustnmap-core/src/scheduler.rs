//! Task scheduler for concurrent scan execution.
//!
//! This module provides the [`TaskScheduler`] which manages the concurrent
//! execution of scan tasks with configurable parallelism limits and priorities.

use std::cmp::Ordering as CmpOrdering;
use std::collections::BinaryHeap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::task::JoinHandle;
use tracing::{debug, error, trace};

use crate::error::{CoreError, Result};

/// Unique task identifier.
pub type TaskId = u64;

/// Task priority level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum TaskPriority {
    /// Critical priority - executes immediately.
    Critical = 0,
    /// High priority - executes before normal tasks.
    High = 1,
    /// Normal priority - default for most scan tasks.
    #[default]
    Normal = 2,
    /// Low priority - executes when resources are available.
    Low = 3,
    /// Background priority - executes last.
    Background = 4,
}

/// A scheduled task with priority and metadata.
pub struct ScheduledTask<F, Fut>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    /// Unique task identifier.
    id: TaskId,
    /// Task name for debugging.
    name: String,
    /// Task priority.
    priority: TaskPriority,
    /// The task function.
    task: Option<F>,
}

impl<F, Fut> ScheduledTask<F, Fut>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    /// Creates a new scheduled task.
    #[must_use]
    pub fn new(name: impl Into<String>, priority: TaskPriority, task: F) -> Self {
        static TASK_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
        let id = TASK_ID_COUNTER.fetch_add(1, Ordering::Relaxed);

        Self {
            id,
            name: name.into(),
            priority,
            task: Some(task),
        }
    }

    /// Returns the task identifier.
    #[must_use]
    pub const fn id(&self) -> TaskId {
        self.id
    }

    /// Returns the task name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the task priority.
    #[must_use]
    pub const fn priority(&self) -> TaskPriority {
        self.priority
    }
}

// Manual implementation of Debug to avoid F: Debug bound
impl<F, Fut> std::fmt::Debug for ScheduledTask<F, Fut>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScheduledTask")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("priority", &self.priority)
            .finish_non_exhaustive()
    }
}

// Wrapper for priority queue ordering
#[expect(
    dead_code,
    reason = "Priority queue wrapper for future priority-based scheduling"
)]
struct PrioritizedTask {
    /// Task identifier.
    id: TaskId,
    /// Task priority (lower = higher priority).
    priority: TaskPriority,
    /// Sequence number for stable ordering within same priority.
    sequence: u64,
}

impl PartialEq for PrioritizedTask {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.sequence == other.sequence
    }
}

impl Eq for PrioritizedTask {}

impl PartialOrd for PrioritizedTask {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedTask {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        // Reverse ordering for min-heap behavior (lower priority value = higher priority)
        other
            .priority
            .cmp(&self.priority)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

/// Task scheduler for managing concurrent scan execution.
#[derive(Debug)]
pub struct TaskScheduler {
    /// Maximum number of concurrent tasks.
    max_concurrent: usize,
    /// Current number of active tasks.
    active_count: AtomicUsize,
    /// Total tasks submitted.
    total_submitted: AtomicU64,
    /// Total tasks completed.
    total_completed: AtomicU64,
    /// Total tasks failed.
    total_failed: AtomicU64,
    /// Semaphore for limiting concurrency.
    semaphore: Arc<Semaphore>,
    /// Task queue sender.
    task_tx: mpsc::Sender<TaskMessage>,
    /// Task queue receiver (wrapped in Mutex for async access).
    task_rx: Mutex<mpsc::Receiver<TaskMessage>>,
    /// Shutdown signal sender.
    #[expect(
        dead_code,
        reason = "Shutdown signal for graceful scheduler termination"
    )]
    shutdown_tx: Option<mpsc::Sender<()>>,
}

/// Internal task message type.
enum TaskMessage {
    /// Execute a task.
    Execute {
        /// Task identifier.
        id: TaskId,
        /// Task name.
        name: String,
        /// The task future.
        future: Pin<Box<dyn Future<Output = Result<()>> + Send>>,
    },
    /// Shutdown the scheduler.
    Shutdown,
}

impl TaskScheduler {
    /// Creates a new task scheduler with the given concurrency limit.
    #[must_use]
    pub fn new(max_concurrent: usize) -> Self {
        let (task_tx, task_rx) = mpsc::channel(1024);
        let semaphore = Arc::new(Semaphore::new(max_concurrent));

        Self {
            max_concurrent,
            active_count: AtomicUsize::new(0),
            total_submitted: AtomicU64::new(0),
            total_completed: AtomicU64::new(0),
            total_failed: AtomicU64::new(0),
            semaphore,
            task_tx,
            task_rx: Mutex::new(task_rx),
            shutdown_tx: None,
        }
    }

    /// Schedules a task for execution.
    ///
    /// # Errors
    ///
    /// Returns an error if the task cannot be scheduled due to queue full
    /// or scheduler shutdown.
    ///
    /// # Panics
    ///
    /// Panics if the task has already been taken (should not happen with proper usage).
    pub async fn schedule<F, Fut>(&self, task: ScheduledTask<F, Fut>) -> Result<()>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let task_id = task.id;
        let task_name = task.name.clone();

        trace!(task_id, task_name = %task_name, "Scheduling task");

        self.total_submitted.fetch_add(1, Ordering::Relaxed);

        // Create the task future
        let task_fn = task.task.expect("task should not be None");
        let future = Box::pin(task_fn());

        // Send to execution queue
        self.task_tx
            .send(TaskMessage::Execute {
                id: task_id,
                name: task_name,
                future,
            })
            .await
            .map_err(|_e| CoreError::scheduler("failed to send task to queue"))?;

        Ok(())
    }

    /// Runs the scheduler until all tasks complete.
    ///
    /// # Errors
    ///
    /// Returns an error if task execution fails.
    pub async fn run(&self) -> Result<()> {
        let mut rx = self.task_rx.lock().await;
        let semaphore = Arc::clone(&self.semaphore);

        let mut handles: Vec<JoinHandle<Result<()>>> = Vec::new();

        while let Some(message) = rx.recv().await {
            match message {
                TaskMessage::Execute { id, name, future } => {
                    let permit = Arc::clone(&semaphore)
                        .acquire_owned()
                        .await
                        .map_err(|_e| CoreError::scheduler("semaphore closed"))?;

                    self.active_count.fetch_add(1, Ordering::Relaxed);

                    let handle = tokio::spawn(async move {
                        let _permit = permit; // Hold permit until task completes
                        trace!(task_id = id, task_name = %name, "Executing task");

                        let result = future.await;

                        if result.is_err() {
                            error!(task_id = id, task_name = %name, "Task failed");
                        } else {
                            trace!(task_id = id, task_name = %name, "Task completed");
                        }

                        result
                    });

                    handles.push(handle);
                }
                TaskMessage::Shutdown => {
                    debug!("Scheduler received shutdown signal");
                    break;
                }
            }
        }

        // Wait for all active tasks to complete
        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {
                    self.total_completed.fetch_add(1, Ordering::Relaxed);
                }
                Ok(Err(_)) | Err(_) => {
                    self.total_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
            self.active_count.fetch_sub(1, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Waits for all scheduled tasks to complete.
    ///
    /// # Errors
    ///
    /// Returns an error if the scheduler encounters an error.
    pub async fn wait_for_completion(&self) -> Result<()> {
        // Signal shutdown
        let _ = self.task_tx.send(TaskMessage::Shutdown).await;

        // Run until completion
        self.run().await
    }

    /// Shuts down the scheduler gracefully.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    pub async fn shutdown(&self) -> Result<()> {
        debug!("Initiating scheduler shutdown");
        self.task_tx
            .send(TaskMessage::Shutdown)
            .await
            .map_err(|_e| CoreError::scheduler("failed to send shutdown signal"))?;
        Ok(())
    }

    /// Returns the number of currently active tasks.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active_count.load(Ordering::Relaxed)
    }

    /// Returns the total number of tasks submitted.
    #[must_use]
    pub fn total_submitted(&self) -> u64 {
        self.total_submitted.load(Ordering::Relaxed)
    }

    /// Returns the total number of tasks completed.
    #[must_use]
    pub fn total_completed(&self) -> u64 {
        self.total_completed.load(Ordering::Relaxed)
    }

    /// Returns the total number of tasks that failed.
    #[must_use]
    pub fn total_failed(&self) -> u64 {
        self.total_failed.load(Ordering::Relaxed)
    }

    /// Returns the maximum number of concurrent tasks.
    #[must_use]
    pub const fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }
}

impl Default for TaskScheduler {
    fn default() -> Self {
        Self::new(num_cpus::get())
    }
}

/// Priority-based task queue.
#[derive(Debug)]
pub struct PriorityTaskQueue<T> {
    /// Internal heap storage.
    heap: Mutex<BinaryHeap<PrioritizedTaskItem<T>>>,
    /// Sequence counter for stable ordering.
    sequence: AtomicU64,
}

/// Item in the priority queue.
#[derive(Debug)]
struct PrioritizedTaskItem<T> {
    /// Priority (lower = higher priority).
    priority: TaskPriority,
    /// Sequence number for FIFO within same priority.
    sequence: u64,
    /// The actual task data.
    item: T,
}

impl<T> PartialEq for PrioritizedTaskItem<T> {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.sequence == other.sequence
    }
}

impl<T> Eq for PrioritizedTaskItem<T> {}

impl<T> PartialOrd for PrioritizedTaskItem<T> {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for PrioritizedTaskItem<T> {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        // Reverse ordering for min-heap (lower priority value = higher priority)
        other
            .priority
            .cmp(&self.priority)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

impl<T> PriorityTaskQueue<T> {
    /// Creates a new empty priority task queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            heap: Mutex::new(BinaryHeap::new()),
            sequence: AtomicU64::new(0),
        }
    }

    /// Pushes an item onto the queue with the given priority.
    pub async fn push(&self, priority: TaskPriority, item: T) {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let task_item = PrioritizedTaskItem {
            priority,
            sequence,
            item,
        };
        self.heap.lock().await.push(task_item);
    }

    /// Pops the highest priority item from the queue.
    pub async fn pop(&self) -> Option<T> {
        self.heap.lock().await.pop().map(|item| item.item)
    }

    /// Returns true if the queue is empty.
    pub async fn is_empty(&self) -> bool {
        self.heap.lock().await.is_empty()
    }

    /// Returns the number of items in the queue.
    pub async fn len(&self) -> usize {
        self.heap.lock().await.len()
    }
}

impl<T> Default for PriorityTaskQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn test_task_priority_ordering() {
        assert!(TaskPriority::Critical < TaskPriority::High);
        assert!(TaskPriority::High < TaskPriority::Normal);
        assert!(TaskPriority::Normal < TaskPriority::Low);
        assert!(TaskPriority::Low < TaskPriority::Background);
    }

    #[test]
    fn test_scheduled_task_creation() {
        let task = ScheduledTask::new("test_task", TaskPriority::Normal, || async { Ok(()) });
        assert_eq!(task.name(), "test_task");
        assert_eq!(task.priority(), TaskPriority::Normal);
        assert!(task.id() > 0);
    }

    #[tokio::test]
    async fn test_task_scheduler_creation() {
        let scheduler = TaskScheduler::new(4);
        assert_eq!(scheduler.max_concurrent(), 4);
        assert_eq!(scheduler.active_count(), 0);
        assert_eq!(scheduler.total_submitted(), 0);
    }

    #[tokio::test]
    async fn test_task_scheduler_schedule() {
        let scheduler = TaskScheduler::new(2);
        let executed = Arc::new(AtomicBool::new(false));
        let executed_clone = Arc::clone(&executed);

        let task = ScheduledTask::new("test_task", TaskPriority::Normal, move || {
            let flag = Arc::clone(&executed_clone);
            async move {
                flag.store(true, Ordering::Relaxed);
                Ok(())
            }
        });

        scheduler.schedule(task).await.unwrap();
        assert_eq!(scheduler.total_submitted(), 1);
    }

    #[tokio::test]
    async fn test_priority_task_queue() {
        let queue = PriorityTaskQueue::new();

        queue.push(TaskPriority::Low, "low").await;
        queue.push(TaskPriority::High, "high").await;
        queue.push(TaskPriority::Normal, "normal").await;

        assert_eq!(queue.len().await, 3);

        // Should pop in priority order: high, normal, low
        assert_eq!(queue.pop().await, Some("high"));
        assert_eq!(queue.pop().await, Some("normal"));
        assert_eq!(queue.pop().await, Some("low"));
        assert_eq!(queue.pop().await, None);
    }

    #[tokio::test]
    async fn test_priority_queue_fifo_within_priority() {
        let queue = PriorityTaskQueue::new();

        queue.push(TaskPriority::Normal, "first").await;
        queue.push(TaskPriority::Normal, "second").await;
        queue.push(TaskPriority::Normal, "third").await;

        // Should maintain FIFO order within same priority
        assert_eq!(queue.pop().await, Some("first"));
        assert_eq!(queue.pop().await, Some("second"));
        assert_eq!(queue.pop().await, Some("third"));
    }

    #[test]
    fn test_scheduler_error_display() {
        use crate::error::SchedulerError;
        assert_eq!(SchedulerError::QueueFull.to_string(), "task queue is full");
        assert_eq!(SchedulerError::Cancelled.to_string(), "task was cancelled");
    }
}
