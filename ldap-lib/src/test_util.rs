#[cfg(test)]
pub mod util {
    use std::time;

    /// Wait until interval has passed, and then still wait a while longer to ensure that any task that is 
    /// scheduling its work at this interval has done its thing.
    pub async fn await_concurrent_task_progress(interval: time::Duration) {
        tokio::time::sleep(interval + time::Duration::from_millis(10)).await;
    }
    
    pub async fn async_noop() {}
}
