use core_foundation_sys::base::{kCFAllocatorDefault, CFAllocatorRef, CFTypeRef};
use core_foundation_sys::string::{CFStringCreateWithCString, CFStringRef};
use ctor::ctor;
use libc::{c_char, c_void};
use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::Mutex;

// --- IOKit and CoreFoundation constants and types ---
type IOOptionBits = u32;
// io_registry_entry_t is an opaque pointer type in IOKit/
// In C it's typedef mach_port_t io_object_t; typedef io_object_t io_registry_entry_t;
// mach_port_t is a natural_t which is an unsigned int.
// Using *mut c_void for simplicity as it's treated as an opaque handle here.
type IORegistryEntryT = *mut c_void;

// kIOPlatformUUIDKey as a CFStringRef (static or created on demand)
const IO_PLATFORM_UUID_KEY_STR: &str = "IOPlatformUUID";

// The UUID to spoof
const SPOOFED_UUID_STR: &str = "DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF";

// --- fishhook FFI ---
#[repr(C)]
struct Rebinding {
    name: *const c_char,
    replacement: *mut c_void,
    replaced: *mut *mut c_void,
}

extern "C" {
    fn rebind_symbols(rebindings: *mut Rebinding, rebindings_nel: usize) -> i32;
    fn CFStringGetCString(
        theString: CFStringRef,
        buffer: *mut c_char,
        bufferSize: i32,
        encoding: u32,
    ) -> bool;
    fn CFRetain(cf: CFTypeRef) -> CFTypeRef;
    // fn CFRelease(cf: CFTypeRef); // Not strictly needed for this example if only returning retained objects

    // IORegistryEntryCreateCFProperty is part of IOKit.framework
    // Its signature is:
    // CFTypeRef IORegistryEntryCreateCFProperty(
    //     io_registry_entry_t entry,
    //     CFStringRef key,
    //     CFAllocatorRef allocator,
    //     IOOptionBits options
    // );
}

// --- Original function pointer ---
type FnIORegistryEntryCreateCFProperty = extern "C" fn(
    entry: IORegistryEntryT,
    key: CFStringRef,
    allocator: CFAllocatorRef,
    options: IOOptionBits,
) -> CFTypeRef;

// This will hold the original function pointer after fishhook retrieves it.
static mut ORIGINAL_IOREGISTRYENTRYCREATECFPROPERTY: Option<FnIORegistryEntryCreateCFProperty> =
    None;

// Wrapper type for CFStringRef to mark it as Send + Sync
// This is safe because we are treating the CFString as immutable after creation,
// and CF Retain/Release are thread-safe.
#[derive(Clone, Copy)] // Add Copy if CFStringRef is Copy, which raw pointers are.
struct MySafeCFStringRef(CFStringRef);
unsafe impl Send for MySafeCFStringRef {}
unsafe impl Sync for MySafeCFStringRef {}

// Lazy static for holding our spoofed UUID CFString to avoid recreating it every time.
// CFStringRef is a pointer, so it can be stored in a static Mutex.
static SPOOFED_UUID_CFSTRING: Mutex<Option<MySafeCFStringRef>> = Mutex::new(None);

fn get_spoofed_uuid_cfstring() -> CFStringRef {
    let mut locked_spoofed_uuid = SPOOFED_UUID_CFSTRING.lock().unwrap();
    if let Some(cf_string_wrapper) = &*locked_spoofed_uuid {
        // The string is already created and stored with a +1 retain count.
        // For each time we return it from the hook, we need to provide a new +1 retain count.
        return unsafe { CFRetain(cf_string_wrapper.0 as CFTypeRef) } as CFStringRef;
    }

    let c_str = CString::new(SPOOFED_UUID_STR).unwrap();
    let new_cf_string = unsafe {
        CFStringCreateWithCString(
            kCFAllocatorDefault, // Default allocator
            c_str.as_ptr(),
            core_foundation_sys::string::kCFStringEncodingUTF8, // Standard UTF8 encoding
        )
    };
    // CFStringCreateWithCString returns a CFString with a retain count of +1.
    // We store this +1 reference in our static.
    *locked_spoofed_uuid = Some(MySafeCFStringRef(new_cf_string));
    // For the *first* call that populates the cache, we also need to return a +1 reference.
    // Since new_cf_string is already +1, we can CFRetain it again for the immediate return.
    (unsafe { CFRetain(new_cf_string as CFTypeRef) }) as CFStringRef
}

// --- Replacement function ---
#[no_mangle]
pub extern "C" fn replaced_IORegistryEntryCreateCFProperty(
    entry: IORegistryEntryT,
    key: CFStringRef,
    allocator: CFAllocatorRef,
    options: IOOptionBits,
) -> CFTypeRef {
    if key.is_null() {
        return unsafe {
            ORIGINAL_IOREGISTRYENTRYCREATECFPROPERTY.unwrap()(entry, key, allocator, options)
        };
    }

    let mut buffer: [c_char; 256] = [0; 256]; // Buffer for C-string
    let cf_encoding_utf8 = 0x08000100; // kCFStringEncodingUTF8

    let got_c_str = unsafe {
        CFStringGetCString(
            key,
            buffer.as_mut_ptr(),
            buffer.len() as i32,
            cf_encoding_utf8,
        )
    };

    if got_c_str {
        let rust_key_str = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_string_lossy();
        if rust_key_str == IO_PLATFORM_UUID_KEY_STR {
            // Return the spoofed UUID. get_spoofed_uuid_cfstring() handles retain counts.
            return get_spoofed_uuid_cfstring() as CFTypeRef;
        }
    }

    // If key doesn't match or conversion fails, call the original function.
    unsafe { ORIGINAL_IOREGISTRYENTRYCREATECFPROPERTY.unwrap()(entry, key, allocator, options) }
}

// --- Dylib constructor ---
#[ctor]
fn init() {
    unsafe {
        let func_name_cstr = CString::new("IORegistryEntryCreateCFProperty").unwrap();

        // This variable will be filled by fishhook with the original function's address.
        static mut ORIGINAL_FUNC_PTR_RAW: *mut c_void = ptr::null_mut();

        let mut rebindings = [Rebinding {
            name: func_name_cstr.as_ptr(),
            replacement: replaced_IORegistryEntryCreateCFProperty as *mut c_void,
            replaced: &raw mut ORIGINAL_FUNC_PTR_RAW,
        }];

        if rebind_symbols(rebindings.as_mut_ptr(), 1) == 0 {
            if ORIGINAL_FUNC_PTR_RAW.is_null() {
                eprintln!("[uuid_spoofer] Error: fishhook succeeded but did not return original function pointer.");
                return;
            }
            ORIGINAL_IOREGISTRYENTRYCREATECFPROPERTY =
                Some(std::mem::transmute(ORIGINAL_FUNC_PTR_RAW));
            // For debugging, one might print:
            // println!("[uuid_spoofer] Successfully hooked IORegistryEntryCreateCFProperty. Original @ {:?}", ORIGINAL_FUNC_PTR_RAW);
        } else {
            eprintln!("[uuid_spoofer] Error: Failed to hook IORegistryEntryCreateCFProperty using fishhook.");
        }
    }
}

/*
Build Instructions:
1. Ensure you have Rust installed (https://rustup.rs/).
2. Make sure you have a C compiler (like Clang, typically available with Xcode Command Line Tools on macOS).
   `xcode-select --install` if needed.
3. Navigate to the `uuid_spoofer` directory (which should be your project root).
4. Run `cargo build` (for debug) or `cargo build --release` (for release).
   This will produce the dylib in `target/debug/libuuid_spoofer.dylib` or `target/release/libuuid_spoofer.dylib`.

Loading with Frida:
1. Install Frida: `pip3 install frida-tools` (use pip3 for Python 3).
2. Identify your target application's process ID (PID) or bundle identifier.
   - List running apps: `frida-ps -Ua` (for iOS devices or macOS apps if Frida server is running locally for all apps).
   - Or find PID manually (e.g., Activity Monitor).
3. Use Frida to inject the dylib:
   - Attach to PID: `frida -p <PID> -l /path/to/your/libuuid_spoofer.dylib`
   - Spawn an application: `frida -f <BUNDLE_IDENTIFIER_OR_PATH> -l /path/to/your/libuuid_spoofer.dylib --no-pause`
     Example for TextEdit on macOS:
     `frida -f /System/Applications/TextEdit.app -l ./target/release/libuuid_spoofer.dylib --no-pause`
     (Run from your project's root directory where `target` is a subdirectory)

Loading with insert_dylib:
(This permanently modifies the target binary to load your dylib at launch)
1. Copy your `libuuid_spoofer.dylib` into the target application bundle, for example, into its `Contents/Frameworks/` directory.
   If the Frameworks directory doesn't exist, you can create it.
2. Use `insert_dylib` (you might need to build it from the `example-project/insert_dylib` submodule or download a pre-built binary):
   `path/to/insert_dylib @executable_path/../Frameworks/libuuid_spoofer.dylib /Applications/TargetApp.app/Contents/MacOS/TargetAppBinary --inplace`
   Replace paths accordingly. The `@executable_path/...` tells the loader where to find your dylib relative to the main executable.

Testing:
- Any application that reads the IOPlatformUUID should show the spoofed value *after* the dylib is injected into its process.
- A simple way to check the system's perceived UUID is often via `system_profiler SPHardwareDataType | grep "Platform UUID"`.
  However, to see the *effect* of your dylib, you need to inject it into `system_profiler` or a process it queries. This can be tricky for command-line tools.
- A more reliable test is to write a small Swift or Objective-C program that calls `IORegistryEntryCreateCFProperty` directly (or uses a higher-level API that calls it) and prints the UUID. Then, run this test program with your dylib injected.

Example Swift test code (save as `testuuid.swift`):
```swift
import Foundation
import IOKit

func getIOPlatformUUID() -> String? {
    var masterPort: mach_port_t = 0
    var iterator: io_iterator_t = 0
    var kernelClass: CFString = "IOPlatformExpertDevice" as CFString
    var platformExpert: io_registry_entry_t = 0
    var uuidCfString: Unmanaged<CFString>?

    if IOMasterPort(mach_port_null, &masterPort) != KERN_SUCCESS {
        print("Error: Couldn't get master port")
        return nil
    }

    let matchingDict = IOServiceMatching(CFStringGetCStringPtr(kernelClass, CFStringBuiltInEncodings.UTF8.rawValue))
    if IOServiceGetMatchingServices(masterPort, matchingDict, &iterator) != KERN_SUCCESS {
        print("Error: Couldn't get matching services")
        return nil
    }

    platformExpert = IOIteratorNext(iterator)
    IOObjectRelease(iterator)

    if platformExpert == 0 {
        print("Error: Couldn't find platform expert")
        return nil
    }

    uuidCfString = IORegistryEntryCreateCFProperty(
        platformExpert,
        "IOPlatformUUID" as CFString,
        kCFAllocatorDefault,
        0
    ). τότεUnmanagedRetainedValue() as? Unmanaged<CFString>

    IOObjectRelease(platformExpert)

    if let uuid = uuidCfString?.takeRetainedValue() {
        return uuid as String
    }
    return nil
}

if let uuid = getIOPlatformUUID() {
    print("IOPlatformUUID: \(uuid)")
} else {
    print("Failed to get IOPlatformUUID")
}
```
Compile: `swiftc testuuid.swift -o testuuid`
Run without dylib: `./testuuid`
Run with dylib using Frida: `frida -f ./testuuid -l ./target/release/libuuid_spoofer.dylib --no-pause`

Compatibility:
- Target macOS: 11.0+
- Architectures: arm64 (Apple Silicon) and x86_64 (Intel).
  `cargo build` will build for your current machine's architecture.
  To build for a specific architecture: `cargo build --target aarch64-apple-darwin` or `cargo build --target x86_64-apple-darwin`.
  To create a universal binary (fat binary) containing both architectures, build for each target and then use the `lipo` command:
  `lipo -create target/aarch64-apple-darwin/release/libuuid_spoofer.dylib target/x86_64-apple-darwin/release/libuuid_spoofer.dylib -output target/release/libuuid_spoofer_universal.dylib`
*/
