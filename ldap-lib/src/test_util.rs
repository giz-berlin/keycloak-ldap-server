#[cfg(test)]
pub mod test_constants {
    pub const DEFAULT_BASE_DISTINGUISHED_NAME: &str = "dc=base_dsn";
    pub const DEFAULT_ORGANIZATION_NAME: &str = "organization";
    pub const DEFAULT_CLIENT_ID: &str = "default_client";
    pub const DEFAULT_CLIENT_PASSWORD: &str = "default_client_password";
    pub const DEFAULT_USER_ID: &str = "s0m3-us3r";
    pub const ANOTHER_USER_ID: &str = "4n0th3r-us3r";
    pub const DEFAULT_GROUP_ID: &str = "d3f4ult_gr0up";
    pub const ANOTHER_GROUP_ID: &str = "4n0th3r-gr0up";
    pub const DEFAULT_NUM_USERS_TO_FETCH: i32 = 5;
}

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
