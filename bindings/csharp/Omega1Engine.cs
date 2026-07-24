// ═════════════════════════════════════════════════════════════════════════════
// OMEGA-1 Engine C# Wrapper
// Managed interop for IAT slots 64-75
// ═════════════════════════════════════════════════════════════════════════════

using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;

namespace RawrXD.Omega1
{
    /// <summary>
    /// OMEGA-1 Engine flags
    /// </summary>
    [Flags]
    public enum Omega1Flags : uint
    {
        None = 0x00000000,
        Verbose = 0x00000001,
        Strict = 0x00000002,
        Mutant = 0x00000004
    }

    /// <summary>
    /// OMEGA-1 mutation types
    /// </summary>
    public enum MutationType : uint
    {
        None = 0,
        Hotpatch = 1,
        Reflective = 2,
        Genesis = 3
    }

    /// <summary>
    /// OMEGA-1 status codes
    /// </summary>
    public enum Omega1Status : uint
    {
        Ok = 0,
        Error = 1,
        NotInitialized = 2,
        Mutation = 3
    }

    /// <summary>
    /// Module information structure
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct Omega1ModuleInfo
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Name;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string Version;

        public uint SlotIndex;

        [MarshalAs(UnmanagedType.Bool)]
        public bool Loaded;
    }

    /// <summary>
    /// OMEGA-1 Engine context handle
    /// </summary>
    public sealed class Omega1Context : IDisposable
    {
        private IntPtr _handle;
        private bool _disposed;

        public IntPtr Handle => _handle;

        internal Omega1Context(IntPtr handle)
        {
            _handle = handle;
        }

        public void Dispose()
        {
            if (!_disposed && _handle != IntPtr.Zero)
            {
                NativeMethods.Omega1_Shutdown(_handle);
                _handle = IntPtr.Zero;
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }

        ~Omega1Context()
        {
            Dispose();
        }
    }

    /// <summary>
    /// Native P/Invoke methods for OMEGA-1 IAT slots 64-75
    /// </summary>
    internal static class NativeMethods
    {
        private const string DllName = "Omega1Engine.dll";

        // Slot 64: Initialize
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Omega1_Initialize(out IntPtr ppContext, uint flags);

        // Slot 65: Shutdown
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Omega1_Shutdown(IntPtr pContext);

        // Slot 66: GetModuleCount
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint Omega1_GetModuleCount(IntPtr pContext);

        // Slot 67: IsMutant
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Omega1_IsMutant(IntPtr pContext);

        // Slot 68: GetMutationCount
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint Omega1_GetMutationCount(IntPtr pContext);

        // Slot 69: ExecuteReflective
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Omega1_ExecuteReflective(
            IntPtr pContext,
            [MarshalAs(UnmanagedType.LPStr)] string payload,
            uint payloadSize,
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder output,
            uint outputSize);

        // Slot 70: ValidateIntegrity
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Omega1_ValidateIntegrity(IntPtr pContext, out uint pChecksum);

        // Slot 71: TriggerMutation
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Omega1_TriggerMutation(IntPtr pContext, uint mutationType);

        // Slot 72: GetManifestJson
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Omega1_GetManifestJson(
            IntPtr pContext,
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder buffer,
            uint bufferSize);

        // Slot 73: ExecutePowerShell
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Omega1_ExecutePowerShell(
            IntPtr pContext,
            [MarshalAs(UnmanagedType.LPStr)] string command,
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder output,
            uint outputSize);

        // Slot 74: LoadModule
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr Omega1_LoadModule(
            IntPtr pContext,
            [MarshalAs(UnmanagedType.LPStr)] string moduleName);

        // Slot 75: InvokeModule
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Omega1_InvokeModule(
            IntPtr pContext,
            IntPtr hModule,
            [MarshalAs(UnmanagedType.LPStr)] string function,
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder output,
            uint outputSize);

        // C API: CreateContext
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr Omega1_CreateContext();

        // C API: DestroyContext
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Omega1_DestroyContext(IntPtr pContext);

        // C API: GetVersion
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint Omega1_GetVersion(
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder buffer,
            uint bufferSize);

        // C API: GetStatus
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint Omega1_GetStatus(IntPtr pContext);
    }

    /// <summary>
    /// High-level OMEGA-1 Engine wrapper
    /// </summary>
    public sealed class Omega1Engine : IDisposable
    {
        private Omega1Context _context;
        private bool _disposed;

        public bool IsInitialized => _context?.Handle != IntPtr.Zero && !_disposed;

        /// <summary>
        /// Initialize the OMEGA-1 engine
        /// </summary>
        public void Initialize(Omega1Flags flags = Omega1Flags.None)
        {
            if (IsInitialized)
                throw new InvalidOperationException("Omega1Engine is already initialized");

            IntPtr handle;
            if (!NativeMethods.Omega1_Initialize(out handle, (uint)flags))
                throw new InvalidOperationException("Failed to initialize OMEGA-1 engine");

            _context = new Omega1Context(handle);
        }

        /// <summary>
        /// Initialize using C API (simpler path)
        /// </summary>
        public void InitializeSimple()
        {
            if (IsInitialized)
                throw new InvalidOperationException("Omega1Engine is already initialized");

            var handle = NativeMethods.Omega1_CreateContext();
            if (handle == IntPtr.Zero)
                throw new InvalidOperationException("Failed to create OMEGA-1 context");

            _context = new Omega1Context(handle);
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _context?.Dispose();
                _context = null;
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }

        ~Omega1Engine()
        {
            Dispose();
        }

        // ═════════════════════════════════════════════════════════════════
        // Properties
        // ═════════════════════════════════════════════════════════════════

        public uint ModuleCount => NativeMethods.Omega1_GetModuleCount(_context.Handle);

        public bool IsMutant => NativeMethods.Omega1_IsMutant(_context.Handle);

        public uint MutationCount => NativeMethods.Omega1_GetMutationCount(_context.Handle);

        public Omega1Status Status => (Omega1Status)NativeMethods.Omega1_GetStatus(_context.Handle);

        public static string Version
        {
            get
            {
                var sb = new StringBuilder(256);
                NativeMethods.Omega1_GetVersion(sb, (uint)sb.Capacity);
                return sb.ToString();
            }
        }

        // ═════════════════════════════════════════════════════════════════
        // Methods
        // ═════════════════════════════════════════════════════════════════

        /// <summary>
        /// Execute a reflective payload
        /// </summary>
        public string ExecuteReflective(string payload)
        {
            EnsureInitialized();
            var output = new StringBuilder(4096);
            if (!NativeMethods.Omega1_ExecuteReflective(_context.Handle, payload, (uint)payload.Length, output, (uint)output.Capacity))
                throw new InvalidOperationException("ExecuteReflective failed");
            return output.ToString();
        }

        /// <summary>
        /// Validate engine integrity
        /// </summary>
        public uint ValidateIntegrity()
        {
            EnsureInitialized();
            uint checksum;
            if (!NativeMethods.Omega1_ValidateIntegrity(_context.Handle, out checksum))
                throw new InvalidOperationException("ValidateIntegrity failed");
            return checksum;
        }

        /// <summary>
        /// Trigger a mutation
        /// </summary>
        public void TriggerMutation(MutationType type)
        {
            EnsureInitialized();
            if (!NativeMethods.Omega1_TriggerMutation(_context.Handle, (uint)type))
                throw new InvalidOperationException("TriggerMutation failed");
        }

        /// <summary>
        /// Get manifest as JSON string
        /// </summary>
        public string GetManifestJson()
        {
            EnsureInitialized();
            var sb = new StringBuilder(8192);
            if (!NativeMethods.Omega1_GetManifestJson(_context.Handle, sb, (uint)sb.Capacity))
                throw new InvalidOperationException("GetManifestJson failed");
            return sb.ToString();
        }

        /// <summary>
        /// Execute PowerShell command
        /// </summary>
        public string ExecutePowerShell(string command)
        {
            EnsureInitialized();
            var output = new StringBuilder(4096);
            if (!NativeMethods.Omega1_ExecutePowerShell(_context.Handle, command, output, (uint)output.Capacity))
                throw new InvalidOperationException("ExecutePowerShell failed");
            return output.ToString();
        }

        /// <summary>
        /// Load a PowerShell module
        /// </summary>
        public IntPtr LoadModule(string moduleName)
        {
            EnsureInitialized();
            var handle = NativeMethods.Omega1_LoadModule(_context.Handle, moduleName);
            if (handle == IntPtr.Zero)
                throw new InvalidOperationException($"Failed to load module: {moduleName}");
            return handle;
        }

        /// <summary>
        /// Invoke a function from a loaded module
        /// </summary>
        public string InvokeModule(IntPtr moduleHandle, string functionName)
        {
            EnsureInitialized();
            var output = new StringBuilder(4096);
            if (!NativeMethods.Omega1_InvokeModule(_context.Handle, moduleHandle, functionName, output, (uint)output.Capacity))
                throw new InvalidOperationException($"InvokeModule failed: {functionName}");
            return output.ToString();
        }

        private void EnsureInitialized()
        {
            if (!IsInitialized)
                throw new InvalidOperationException("Omega1Engine is not initialized");
        }
    }

    /// <summary>
    /// Extension methods for easier usage
    /// </summary>
    public static class Omega1Extensions
    {
        public static bool IsOk(this Omega1Status status) => status == Omega1Status.Ok;
        public static bool IsError(this Omega1Status status) => status == Omega1Status.Error;
    }
}
