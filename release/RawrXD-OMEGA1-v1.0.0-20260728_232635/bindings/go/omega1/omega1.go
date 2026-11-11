// ═════════════════════════════════════════════════════════════════════════════
// OMEGA-1 Engine Go cgo Bindings
// Cloud-native tooling interface for IAT slots 64-75
// ═════════════════════════════════════════════════════════════════════════════

package omega1

/*
#cgo LDFLAGS: -LOmega1Engine.dll
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

// FFI Declarations
typedef void* Omega1Handle;
typedef void* HpsModule;

extern bool Omega1_Initialize(Omega1Handle* ppContext, uint32_t flags);
extern void Omega1_Shutdown(Omega1Handle pContext);
extern uint32_t Omega1_GetModuleCount(Omega1Handle pContext);
extern bool Omega1_IsMutant(Omega1Handle pContext);
extern uint32_t Omega1_GetMutationCount(Omega1Handle pContext);
extern bool Omega1_ExecuteReflective(Omega1Handle pContext, const char* payload, uint32_t payloadSize, char* output, uint32_t outputSize);
extern bool Omega1_ValidateIntegrity(Omega1Handle pContext, uint32_t* pChecksum);
extern bool Omega1_TriggerMutation(Omega1Handle pContext, uint32_t mutationType);
extern bool Omega1_GetManifestJson(Omega1Handle pContext, char* buffer, uint32_t bufferSize);
extern bool Omega1_ExecutePowerShell(Omega1Handle pContext, const char* command, char* output, uint32_t outputSize);
extern HpsModule Omega1_LoadModule(Omega1Handle pContext, const char* moduleName);
extern bool Omega1_InvokeModule(Omega1Handle pContext, HpsModule hModule, const char* function, char* output, uint32_t outputSize);
extern Omega1Handle Omega1_CreateContext(void);
extern void Omega1_DestroyContext(Omega1Handle pContext);
extern uint32_t Omega1_GetVersion(char* buffer, uint32_t bufferSize);
extern uint32_t Omega1_GetStatus(Omega1Handle pContext);
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// ═════════════════════════════════════════════════════════════════════════════
// Types
// ═════════════════════════════════════════════════════════════════════════════

type MutationType uint32

const (
	MutationNone       MutationType = 0
	MutationHotpatch   MutationType = 1
	MutationReflective MutationType = 2
	MutationGenesis    MutationType = 3
)

type Status uint32

const (
	StatusOK            Status = 0
	StatusError         Status = 1
	StatusNotInit       Status = 2
	StatusMutation      Status = 3
)

type Flags uint32

const (
	FlagNone    Flags = 0x00000000
	FlagVerbose Flags = 0x00000001
	FlagStrict  Flags = 0x00000002
	FlagMutant  Flags = 0x00000004
)

// Omega1Engine wraps the OMEGA-1 engine context
type Omega1Engine struct {
	handle C.Omega1Handle
}

// ModuleHandle represents a loaded PowerShell module
type ModuleHandle struct {
	handle C.HpsModule
}

// ═════════════════════════════════════════════════════════════════════════════
// Engine Lifecycle
// ═════════════════════════════════════════════════════════════════════════════

// New creates a new uninitialized engine
func New() *Omega1Engine {
	return &Omega1Engine{}
}

// Initialize initializes the engine with flags
func (e *Omega1Engine) Initialize(flags Flags) error {
	if e.handle != nil {
		return fmt.Errorf("already initialized")
	}

	var handle C.Omega1Handle
	result := C.Omega1_Initialize(&handle, C.uint32_t(flags))

	if !result || handle == nil {
		return fmt.Errorf("Omega1_Initialize failed")
	}

	e.handle = handle
	return nil
}

// InitializeSimple initializes using the simple C API
func (e *Omega1Engine) InitializeSimple() error {
	if e.handle != nil {
		return fmt.Errorf("already initialized")
	}

	handle := C.Omega1_CreateContext()
	if handle == nil {
		return fmt.Errorf("Omega1_CreateContext failed")
	}

	e.handle = handle
	return nil
}

// Shutdown releases the engine
func (e *Omega1Engine) Shutdown() {
	if e.handle != nil {
		C.Omega1_Shutdown(e.handle)
		e.handle = nil
	}
}

// ensureInitialized checks if engine is initialized
func (e *Omega1Engine) ensureInitialized() error {
	if e.handle == nil {
		return fmt.Errorf("engine not initialized")
	}
	return nil
}

// ═════════════════════════════════════════════════════════════════════════════
// Properties
// ═════════════════════════════════════════════════════════════════════════════

// ModuleCount returns the number of loaded modules
func (e *Omega1Engine) ModuleCount() (uint32, error) {
	if err := e.ensureInitialized(); err != nil {
		return 0, err
	}
	return uint32(C.Omega1_GetModuleCount(e.handle)), nil
}

// IsMutant returns true if this is a mutant instance
func (e *Omega1Engine) IsMutant() (bool, error) {
	if err := e.ensureInitialized(); err != nil {
		return false, err
	}
	return bool(C.Omega1_IsMutant(e.handle)), nil
}

// MutationCount returns the mutation count
func (e *Omega1Engine) MutationCount() (uint32, error) {
	if err := e.ensureInitialized(); err != nil {
		return 0, err
	}
	return uint32(C.Omega1_GetMutationCount(e.handle)), nil
}

// Status returns the engine status
func (e *Omega1Engine) Status() (Status, error) {
	if err := e.ensureInitialized(); err != nil {
		return StatusNotInit, err
	}
	return Status(C.Omega1_GetStatus(e.handle)), nil
}

// Version returns the OMEGA-1 version string
func Version() (string, error) {
	buffer := make([]byte, 256)
	length := C.Omega1_GetVersion((*C.char)(unsafe.Pointer(&buffer[0])), 256)
	
	if length == 0 {
		return "", fmt.Errorf("Omega1_GetVersion failed")
	}
	
	return string(buffer[:length]), nil
}

// ═════════════════════════════════════════════════════════════════════════════
// Methods
// ═════════════════════════════════════════════════════════════════════════════

// ExecuteReflective executes a reflective payload
func (e *Omega1Engine) ExecuteReflective(payload string) (string, error) {
	if err := e.ensureInitialized(); err != nil {
		return "", err
	}

	payloadC := C.CString(payload)
	defer C.free(unsafe.Pointer(payloadC))

	output := make([]byte, 4096)
	result := C.Omega1_ExecuteReflective(
		e.handle,
		payloadC,
		C.uint32_t(len(payload)),
		(*C.char)(unsafe.Pointer(&output[0])),
		4096,
	)

	if !result {
		return "", fmt.Errorf("ExecuteReflective failed")
	}

	return string(output), nil
}

// ValidateIntegrity validates engine integrity
func (e *Omega1Engine) ValidateIntegrity() (uint32, error) {
	if err := e.ensureInitialized(); err != nil {
		return 0, err
	}

	var checksum C.uint32_t
	result := C.Omega1_ValidateIntegrity(e.handle, &checksum)

	if !result {
		return 0, fmt.Errorf("ValidateIntegrity failed")
	}

	return uint32(checksum), nil
}

// TriggerMutation triggers a mutation
func (e *Omega1Engine) TriggerMutation(mutationType MutationType) error {
	if err := e.ensureInitialized(); err != nil {
		return err
	}

	result := C.Omega1_TriggerMutation(e.handle, C.uint32_t(mutationType))
	if !result {
		return fmt.Errorf("TriggerMutation failed")
	}

	return nil
}

// GetManifestJSON returns the manifest as JSON
func (e *Omega1Engine) GetManifestJSON() (string, error) {
	if err := e.ensureInitialized(); err != nil {
		return "", err
	}

	buffer := make([]byte, 8192)
	result := C.Omega1_GetManifestJson(
		e.handle,
		(*C.char)(unsafe.Pointer(&buffer[0])),
		8192,
	)

	if !result {
		return "", fmt.Errorf("GetManifestJson failed")
	}

	return string(buffer), nil
}

// ExecutePowerShell executes a PowerShell command
func (e *Omega1Engine) ExecutePowerShell(command string) (string, error) {
	if err := e.ensureInitialized(); err != nil {
		return "", err
	}

	commandC := C.CString(command)
	defer C.free(unsafe.Pointer(commandC))

	output := make([]byte, 4096)
	result := C.Omega1_ExecutePowerShell(
		e.handle,
		commandC,
		(*C.char)(unsafe.Pointer(&output[0])),
		4096,
	)

	if !result {
		return "", fmt.Errorf("ExecutePowerShell failed")
	}

	return string(output), nil
}

// LoadModule loads a PowerShell module
func (e *Omega1Engine) LoadModule(moduleName string) (*ModuleHandle, error) {
	if err := e.ensureInitialized(); err != nil {
		return nil, err
	}

	nameC := C.CString(moduleName)
	defer C.free(unsafe.Pointer(nameC))

	handle := C.Omega1_LoadModule(e.handle, nameC)
	if handle == nil {
		return nil, fmt.Errorf("module not found: %s", moduleName)
	}

	return &ModuleHandle{handle: handle}, nil
}

// InvokeModule invokes a function from a loaded module
func (e *Omega1Engine) InvokeModule(module *ModuleHandle, function string) (string, error) {
	if err := e.ensureInitialized(); err != nil {
		return "", err
	}

	funcC := C.CString(function)
	defer C.free(unsafe.Pointer(funcC))

	output := make([]byte, 4096)
	result := C.Omega1_InvokeModule(
		e.handle,
		module.handle,
		funcC,
		(*C.char)(unsafe.Pointer(&output[0])),
		4096,
	)

	if !result {
		return "", fmt.Errorf("InvokeModule failed: %s", function)
	}

	return string(output), nil
}

// ═════════════════════════════════════════════════════════════════════════════
// Convenience Functions
// ═════════════════════════════════════════════════════════════════════════════

// QuickPowerShell executes a PowerShell command with a temporary engine
func QuickPowerShell(command string) (string, error) {
	engine := New()
	if err := engine.InitializeSimple(); err != nil {
		return "", err
	}
	defer engine.Shutdown()

	return engine.ExecutePowerShell(command)
}

// GetManifest returns the manifest with a temporary engine
func GetManifest() (string, error) {
	engine := New()
	if err := engine.InitializeSimple(); err != nil {
		return "", err
	}
	defer engine.Shutdown()

	return engine.GetManifestJSON()
}
