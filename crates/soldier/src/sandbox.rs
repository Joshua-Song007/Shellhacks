//! FR-R-2, NFR-5: the evolved cure runs in a `wasmi` sandbox with zero host
//! imports. Rather than parsing a compiled gene's import section after the
//! fact, this enforces the boundary structurally: the `Linker` given to
//! every instantiation offers nothing, so any import the module declares
//! simply fails to resolve and instantiation errors out. A gene cannot get
//! a host capability that was never wired up.

use std::fmt;

use wasmi::{Engine, Instance, Linker, Module, Store};

#[derive(Debug)]
pub struct SandboxError(String);

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sandbox: {}", self.0)
    }
}

impl std::error::Error for SandboxError {}

pub struct Sandbox {
    engine: Engine,
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Sandbox {
    pub fn new() -> Self {
        Self { engine: Engine::default() }
    }

    /// Instantiates `wasm_bytes` with a linker that supplies zero host
    /// imports (FR-R-2). If the module imports anything at all, this
    /// returns `Err` instead of running it.
    pub fn instantiate(&self, wasm_bytes: &[u8]) -> Result<(Store<()>, Instance), SandboxError> {
        let module = Module::new(&self.engine, wasm_bytes).map_err(|e| SandboxError(e.to_string()))?;
        let linker = Linker::<()>::new(&self.engine);
        let mut store = Store::new(&self.engine, ());
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| SandboxError(e.to_string()))?
            .start(&mut store)
            .map_err(|e| SandboxError(e.to_string()))?;
        Ok((store, instance))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_module_with_zero_imports_instantiates() {
        let wasm = wat::parse_str("(module)").unwrap();
        assert!(Sandbox::new().instantiate(&wasm).is_ok());
    }

    #[test]
    fn a_module_declaring_any_import_is_rejected() {
        let wasm = wat::parse_str(r#"(module (import "env" "f" (func)))"#).unwrap();
        let err = Sandbox::new().instantiate(&wasm).unwrap_err();
        assert!(err.to_string().contains("sandbox:"));
    }
}
