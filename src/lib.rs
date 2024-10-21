pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

#[macro_use]
extern crate napi_derive;

use napi::bindgen_prelude::*;
use quiche::{self, Config, ConnectionId};

#[napi]
pub fn create_connection() -> String {
    // Example: Add any `quiche`-specific logic here
    "Connection created successfully".to_string()
}

