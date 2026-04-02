use std::fmt;

/// Launcher error types with user-facing messages.
pub enum Error {
    /// No Python 3.11+ found on PATH.
    NoPython,
    /// Virtual environment creation failed.
    VenvCreate(String),
    /// pip install failed.
    PipInstall(String),
    /// HTTP request failed (PyPI, GitHub).
    Network(String),
    /// manifest.json read/write failed.
    Manifest(String),
    /// Self-update failed.
    SelfUpdate(String),
    /// exec() failed.
    Exec(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoPython => write!(
                f,
                "Python 3.11+ required but not found.\n\
                 Searched: python3.14, python3.13, python3.12, python3.11, python3, python\n\n\
                 Install Python:\n\
                 \x20 macOS:  brew install python@3.13\n\
                 \x20 Ubuntu: sudo apt install python3.13\n\
                 \x20 Windows: winget install Python.Python.3.13"
            ),
            Error::VenvCreate(detail) => write!(
                f,
                "Failed to create virtual environment.\n{detail}\n\n\
                 Try: rm -rf ~/.huitzo/venv && huitzo"
            ),
            Error::PipInstall(detail) => write!(
                f,
                "Package installation failed.\n{detail}\n\n\
                 Check your internet connection and try: huitzo --launcher-bootstrap"
            ),
            Error::Network(detail) => write!(f, "Network error: {detail}"),
            Error::Manifest(detail) => write!(f, "Manifest error: {detail}"),
            Error::SelfUpdate(detail) => write!(
                f,
                "Self-update failed: {detail}\n\n\
                 Update manually: https://github.com/Huitzo-Inc/huitzo-launcher/releases"
            ),
            Error::Exec(detail) => write!(f, "Failed to exec into Python CLI: {detail}"),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Exit codes following sysexits.h conventions.
pub fn exit_code(err: &Error) -> i32 {
    match err {
        Error::NoPython => 78,      // EX_CONFIG
        Error::VenvCreate(_) => 73, // EX_CANTCREAT
        Error::PipInstall(_) => 69, // EX_UNAVAILABLE
        Error::Network(_) => 69,    // EX_UNAVAILABLE
        Error::Manifest(_) => 66,   // EX_NOINPUT
        Error::SelfUpdate(_) => 1,
        Error::Exec(_) => 126, // Command found but not executable
    }
}
