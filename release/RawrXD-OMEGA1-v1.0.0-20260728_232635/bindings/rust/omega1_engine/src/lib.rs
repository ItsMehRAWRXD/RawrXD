// ═════════════════════════════════════════════════════════════════════════════
// OMEGA-1 Engine Rust FFI Bindings
// Safe Rust wrapper for IAT slots 64-75
// ═════════════════════════════════════════════════════════════════════════════

use std::ffi::{CStr, CString, c_void, c_char, c_uint};
use std::ptr::{null_mut, NonNull};
use std::mem::MaybeUninit;
use thiserror::Error;

// ═════════════════════════════════════════════════════════════════════════════
// Error Types
// ═════════════════════════════════════════════════════════════════════════════

#[derive(Error, Debug)]
pub enum Omega1Error {
    #[error("Initialization failed")]
    InitializationFailed,
    
    #[error("Not initialized")]
    NotInitialized,
    
    #[error("Operation failed: {0}")]
    OperationFailed(String),
    
    #[error("Invalid string")]
    InvalidString,
    
    #[error("Module not found: {0}")]
    ModuleNotFound(String),
}

pub type Result<T> = std::result::Result<T, Omega1Error>;

// ═════════════════════════════════════════════════════════════════════════════
// FFI Declarations
// ═════════════════════════════════════════════════════════════════════════════

#[repr(C)]
pub struct Omega1Context {
    _private: [u8; 0], // Opaque type
}

pub type Omega1Handle = *mut Omega1Context;
pub type HpsModule = *mut c_void;

extern "C" {
    // Slot 64: Initialize
    fn Omega1_Initialize(ppContext: *mut Omega1Handle, flags: c_uint) -> bool;
    
    // Slot 65: Shutdown
    fn Omega1_Shutdown(pContext: Omega1Handle);
    
    // Slot 66: GetModuleCount
    fn Omega1_GetModuleCount(pContext: Omega1Handle) -> c_uint;
    
    // Slot 67: IsMutant
    fn Omega1_IsMutant(pContext: Omega1Handle) -> bool;
    
    // Slot 68: GetMutationCount
    fn Omega1_GetMutationCount(pContext: Omega1Handle) -> c_uint;
    
    // Slot 69: ExecuteReflective
    fn Omega1_ExecuteReflective(
        pContext: Omega1Handle,
        payload: *const c_char,
        payloadSize: c_uint,
        output: *mut c_char,
        outputSize: c_uint,
    ) -> bool;
    
    // Slot 70: ValidateIntegrity
    fn Omega1_ValidateIntegrity(pContext: Omega1Handle, pChecksum: *mut c_uint) -> bool;
    
    // Slot 71: TriggerMutation
    fn Omega1_TriggerMutation(pContext: Omega1Handle, mutationType: c_uint) -> bool;
    
    // Slot 72: GetManifestJson
    fn Omega1_GetManifestJson(
        pContext: Omega1Handle,
        buffer: *mut c_char,
        bufferSize: c_uint,
    ) -> bool;
    
    // Slot 73: ExecutePowerShell
    fn Omega1_ExecutePowerShell(
        pContext: Omega1Handle,
        command: *const c_char,
        output: *mut c_char,
        outputSize: c_uint,
    ) -> bool;
    
    // Slot 74: LoadModule
    fn Omega1_LoadModule(pContext: Omega1Handle, moduleName: *const c_char) -> HpsModule;
    
    // Slot 75: InvokeModule
    fn Omega1_InvokeModule(
        pContext: Omega1Handle,
        hModule: HpsModule,
        function: *const c_char,
        output: *mut c_char,
        outputSize: c_uint,
    ) -> bool;
    
    // C API
    fn Omega1_CreateContext() -> Omega1Handle;
    fn Omega1_DestroyContext(pContext: Omega1Handle);
    fn Omega1_GetVersion(buffer: *mut c_char, bufferSize: c_uint) -> c_uint;
    fn Omega1_GetStatus(pContext: Omega1Handle) -> c_uint;
}

// ═════════════════════════════════════════════════════════════════════════════
// Safe Rust Wrapper
// ═════════════════════════════════════════════════════════════════════════════

pub struct Omega1Engine {
    handle: Option<NonNull<Omega1Context>>,
}

impl Omega1Engine {
    /// Create a new uninitialized engine
    pub fn new() -> Self {
        Self { handle: None }
    }
    
    /// Initialize with flags
    pub fn initialize(&mut self, flags: u32) -> Result<()> {
        if self.handle.is_some() {
            return Err(Omega1Error::OperationFailed("Already initialized".to_string()));
        }
        
        let mut handle: Omega1Handle = null_mut();
        let result = unsafe { Omega1_Initialize(&mut handle, flags) };
        
        if result && !handle.is_null() {
            self.handle = NonNull::new(handle);
            Ok(())
        } else {
            Err(Omega1Error::InitializationFailed)
        }
    }
    
    /// Initialize using simple C API
    pub fn initialize_simple(&mut self) -> Result<()> {
        if self.handle.is_some() {
            return Err(Omega1Error::OperationFailed("Already initialized".to_string()));
        }
        
        let handle = unsafe { Omega1_CreateContext() };
        
        if !handle.is_null() {
            self.handle = NonNull::new(handle);
            Ok(())
        } else {
            Err(Omega1Error::InitializationFailed)
        }
    }
    
    fn handle(&self) -> Result<Omega1Handle> {
        self.handle
            .map(|h| h.as_ptr())
            .ok_or(Omega1Error::NotInitialized)
    }
    
    // ═════════════════════════════════════════════════════════════════
    // Properties
    // ═════════════════════════════════════════════════════════════════
    
    pub fn module_count(&self) -> Result<u32> {
        let handle = self.handle()?;
        Ok(unsafe { Omega1_GetModuleCount(handle) })
    }
    
    pub fn is_mutant(&self) -> Result<bool> {
        let handle = self.handle()?;
        Ok(unsafe { Omega1_IsMutant(handle) })
    }
    
    pub fn mutation_count(&self) -> Result<u32> {
        let handle = self.handle()?;
        Ok(unsafe { Omega1_GetMutationCount(handle) })
    }
    
    pub fn status(&self) -> Result<u32> {
        let handle = self.handle()?;
        Ok(unsafe { Omega1_GetStatus(handle) })
    }
    
    pub fn version() -> Result<String> {
        let mut buffer = vec![0u8; 256];
        let len = unsafe {
            Omega1_GetVersion(
                buffer.as_mut_ptr() as *mut c_char,
                buffer.len() as c_uint,
            )
        };
        
        if len > 0 {
            let c_str = unsafe { CStr::from_ptr(buffer.as_ptr() as *const c_char) };
            Ok(c_str.to_string_lossy().into_owned())
        } else {
            Err(Omega1Error::OperationFailed("Failed to get version".to_string()))
        }
    }
    
    // ═════════════════════════════════════════════════════════════════
    // Methods
    // ═════════════════════════════════════════════════════════════════
    
    pub fn execute_reflective(&self, payload: &str) -> Result<String> {
        let handle = self.handle()?;
        let payload_c = CString::new(payload).map_err(|_| Omega1Error::InvalidString)?;
        let mut output = vec![0u8; 4096];
        
        let result = unsafe {
            Omega1_ExecuteReflective(
                handle,
                payload_c.as_ptr(),
                payload.len() as c_uint,
                output.as_mut_ptr() as *mut c_char,
                output.len() as c_uint,
            )
        };
        
        if result {
            let c_str = unsafe { CStr::from_ptr(output.as_ptr() as *const c_char) };
            Ok(c_str.to_string_lossy().into_owned())
        } else {
            Err(Omega1Error::OperationFailed("ExecuteReflective failed".to_string()))
        }
    }
    
    pub fn validate_integrity(&self) -> Result<u32> {
        let handle = self.handle()?;
        let mut checksum: c_uint = 0;
        
        let result = unsafe { Omega1_ValidateIntegrity(handle, &mut checksum) };
        
        if result {
            Ok(checksum)
        } else {
            Err(Omega1Error::OperationFailed("ValidateIntegrity failed".to_string()))
        }
    }
    
    pub fn trigger_mutation(&self, mutation_type: MutationType) -> Result<()> {
        let handle = self.handle()?;
        
        let result = unsafe { Omega1_TriggerMutation(handle, mutation_type as c_uint) };
        
        if result {
            Ok(())
        } else {
            Err(Omega1Error::OperationFailed("TriggerMutation failed".to_string()))
        }
    }
    
    pub fn get_manifest_json(&self) -> Result<String> {
        let handle = self.handle()?;
        let mut buffer = vec![0u8; 8192];
        
        let result = unsafe {
            Omega1_GetManifestJson(
                handle,
                buffer.as_mut_ptr() as *mut c_char,
                buffer.len() as c_uint,
            )
        };
        
        if result {
            let c_str = unsafe { CStr::from_ptr(buffer.as_ptr() as *const c_char) };
            Ok(c_str.to_string_lossy().into_owned())
        } else {
            Err(Omega1Error::OperationFailed("GetManifestJson failed".to_string()))
        }
    }
    
    pub fn execute_powershell(&self, command: &str) -> Result<String> {
        let handle = self.handle()?;
        let command_c = CString::new(command).map_err(|_| Omega1Error::InvalidString)?;
        let mut output = vec![0u8; 4096];
        
        let result = unsafe {
            Omega1_ExecutePowerShell(
                handle,
                command_c.as_ptr(),
                output.as_mut_ptr() as *mut c_char,
                output.len() as c_uint,
            )
        };
        
        if result {
            let c_str = unsafe { CStr::from_ptr(output.as_ptr() as *const c_char) };
            Ok(c_str.to_string_lossy().into_owned())
        } else {
            Err(Omega1Error::OperationFailed("ExecutePowerShell failed".to_string()))
        }
    }
    
    pub fn load_module(&self, module_name: &str) -> Result<HpsModule> {
        let handle = self.handle()?;
        let name_c = CString::new(module_name).map_err(|_| Omega1Error::InvalidString)?;
        
        let module = unsafe { Omega1_LoadModule(handle, name_c.as_ptr()) };
        
        if module.is_null() {
            Err(Omega1Error::ModuleNotFound(module_name.to_string()))
        } else {
            Ok(module)
        }
    }
    
    pub fn invoke_module(&self, module: HpsModule, function: &str) -> Result<String> {
        let handle = self.handle()?;
        let func_c = CString::new(function).map_err(|_| Omega1Error::InvalidString)?;
        let mut output = vec![0u8; 4096];
        
        let result = unsafe {
            Omega1_InvokeModule(
                handle,
                module,
                func_c.as_ptr(),
                output.as_mut_ptr() as *mut c_char,
                output.len() as c_uint,
            )
        };
        
        if result {
            let c_str = unsafe { CStr::from_ptr(output.as_ptr() as *const c_char) };
            Ok(c_str.to_string_lossy().into_owned())
        } else {
            Err(Omega1Error::OperationFailed(format!("InvokeModule failed: {}", function)))
        }
    }
}

impl Default for Omega1Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Omega1Engine {
    fn drop(&mut self) {
        if let Some(handle) = self.handle {
            unsafe {
                Omega1_Shutdown(handle.as_ptr());
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Types
// ═════════════════════════════════════════════════════════════════════════════

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationType {
    None = 0,
    Hotpatch = 1,
    Reflective = 2,
    Genesis = 3,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Omega1Status {
    Ok = 0,
    Error = 1,
    NotInitialized = 2,
    Mutation = 3,
}

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Omega1Flags: u32 {
        const NONE = 0x00000000;
        const VERBOSE = 0x00000001;
        const STRICT = 0x00000002;
        const MUTANT = 0x00000004;
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_version() {
        let version = Omega1Engine::version().unwrap();
        assert!(!version.is_empty());
    }
    
    #[test]
    fn test_initialize_simple() {
        let mut engine = Omega1Engine::new();
        engine.initialize_simple().unwrap();
        assert!(engine.module_count().is_ok());
    }
}
