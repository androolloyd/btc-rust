//! Error types for the Electrum server.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ElectrumError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("method not found: {0}")]
    MethodNotFound(String),

    #[error("invalid params: {0}")]
    InvalidParams(String),

    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    #[test]
    fn test_io_error_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test io");
        let err = ElectrumError::Io(io_err);
        let msg = format!("{}", err);
        assert!(msg.contains("IO error"));
        assert!(msg.contains("test io"));
    }

    #[test]
    fn test_json_error_display() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err = ElectrumError::Json(json_err);
        let msg = format!("{}", err);
        assert!(msg.contains("JSON serialization error"));
    }

    #[test]
    fn test_invalid_request_display() {
        let err = ElectrumError::InvalidRequest("bad request".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("invalid request"));
        assert!(msg.contains("bad request"));
    }

    #[test]
    fn test_method_not_found_display() {
        let err = ElectrumError::MethodNotFound("unknown.method".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("method not found"));
        assert!(msg.contains("unknown.method"));
    }

    #[test]
    fn test_invalid_params_display() {
        let err = ElectrumError::InvalidParams("wrong type".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("invalid params"));
        assert!(msg.contains("wrong type"));
    }

    #[test]
    fn test_internal_error_display() {
        let err = ElectrumError::Internal("something broke".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("internal error"));
        assert!(msg.contains("something broke"));
    }

    #[test]
    fn test_io_error_from_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: ElectrumError = io_err.into();
        assert!(matches!(err, ElectrumError::Io(_)));
    }

    #[test]
    fn test_json_error_from_conversion() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();
        let err: ElectrumError = json_err.into();
        assert!(matches!(err, ElectrumError::Json(_)));
    }

    #[test]
    fn test_error_debug_format() {
        let err = ElectrumError::Internal("debug test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("Internal"));
        assert!(debug.contains("debug test"));
    }

    #[test]
    fn test_error_is_std_error() {
        let err = ElectrumError::Internal("test".to_string());
        // Verify it implements std::error::Error via Display
        let _: &dyn std::error::Error = &err;
        let display = format!("{}", err);
        assert!(!display.is_empty());
    }
}
