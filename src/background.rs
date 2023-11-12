use dashmap::DashMap;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time;

pub struct Scheduler {
    tasks: Arc<DashMap<String, (JoinHandle<()>, oneshot::Sender<()>)>>,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    // Create a new Scheduler.
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(DashMap::new()),
        }
    }

    // Schedule a task with a delay.
    pub fn schedule<T, F, Fut>(
        &self,
        task_id: String,
        delay: Option<time::Duration>,
        arg: T,
        task_fn: F,
    ) where
        T: Send + 'static,
        F: FnOnce(T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        if self.tasks.contains_key(&task_id) {
            log::warn!("Task '{}' is already scheduled.", task_id);
            return;
        }

        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let task_id_copy = task_id.clone();
        let handle = tokio::spawn(async move {
            if let Some(delay_duration) = delay {
                time::sleep(delay_duration).await;
            }

            // Execute the task function with the provided argument.
            let fut = task_fn(arg);
            tokio::pin!(fut);

            // Listen for cancellation or completion of the task.
            tokio::select! {
                _ = fut => {
                    log::warn!("Task '{}' completed.", task_id);
                }
                _ = cancel_rx => {
                    log::warn!("Task '{}' was cancelled.", task_id);
                }
            }
        });

        self.tasks.insert(task_id_copy, (handle, cancel_tx));
    }

    // Check if a task exists.
    pub fn exists(&self, task_id: &str) -> bool {
        self.tasks.contains_key(task_id)
    }

    // Cancel a scheduled task.
    pub fn cancel(&self, task_id: &str) {
        if let Some((_, (_, cancel))) = self.tasks.remove(task_id) {
            let _ = cancel.send(());
            log::warn!("Task '{}' has been cancelled.", task_id);
        }
    }

    // Stop all tasks.
    pub fn stop_all(&self) {
        for entry in self.tasks.iter() {
            if let Some((_, (_, cancel))) = self.tasks.remove(entry.key()) {
                let _ = cancel.send(());
                log::warn!("Task '{}' has been cancelled.", entry.key());
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicU32;
    use std::sync::atomic::Ordering::Relaxed;
    use std::time::Duration;
    use crate::background::Scheduler;

    #[tokio::test]
    async fn test_schedule() {
        let task_counter = Arc::new(AtomicU32::new(0));
        let task_counter_copy = task_counter.clone();

        let scheduler = Scheduler::new();

        scheduler.schedule(
            "task1".to_string(),
            Some(Duration::from_millis(3)),
            42, // The argument we want to pass to the task.
            |_num: i32| async move {
                task_counter_copy.fetch_add(1, Relaxed);
            },
        );

        tokio::time::sleep(Duration::from_millis(5)).await;
        scheduler.cancel("task1");

        // Example to stop all tasks
        tokio::time::sleep(Duration::from_secs(1)).await;
        scheduler.stop_all();
        assert!(task_counter.load(Relaxed) > 0);
    }
}
