pub trait Target: Sized {
    /// The configuration struct to use for a specific [Target].
    /// Must derive from [serde::de::DeserializeOwned] because it will be deserialized from a
    /// TOML configuration file.
    type Config: serde::de::DeserializeOwned + std::fmt::Debug;
}
