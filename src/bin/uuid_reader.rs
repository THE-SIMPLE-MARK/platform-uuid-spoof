use core_foundation_sys::base::{kCFAllocatorDefault, CFAllocatorRef, CFTypeRef};
use core_foundation_sys::string::{kCFStringEncodingUTF8, CFStringGetCStringPtr, CFStringRef};

use libc::{c_char, c_void};
use std::ffi::CStr;

// --- IOKit FFI types and functions ---
type IOOptionBits = u32;
type IORegistryEntryT = *mut c_void; // Or mach_port_t which is u32
type IOMasterPortT = u32; // mach_port_t
type IOServiceMatchingCFDictRef = CFTypeRef; // Actually CFDictionaryRef
type IOIteratorT = u32; // io_iterator_t

const KERN_SUCCESS: i32 = 0;
const MACH_PORT_NULL: u32 = 0; // Or 0 as *mut c_void if using that for mach_port_t

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IOMasterPort(bootstrapPort: IOMasterPortT, masterPort: *mut IOMasterPortT) -> i32; // kern_return_t

    fn IOServiceMatching(name: *const c_char) -> IOServiceMatchingCFDictRef;
    fn IOServiceGetMatchingServices(
        masterPort: IOMasterPortT,
        matching: IOServiceMatchingCFDictRef,
        existing: *mut IOIteratorT,
    ) -> i32; // kern_return_t

    fn IOIteratorNext(iterator: IOIteratorT) -> IORegistryEntryT; // io_object_t
    fn IOObjectRelease(object: u32) -> i32; // kern_return_t for io_object_t

    fn IORegistryEntryCreateCFProperty(
        entry: IORegistryEntryT,
        key: CFStringRef,
        allocator: CFAllocatorRef,
        options: IOOptionBits,
    ) -> CFTypeRef;

    // For CFStringCreateWithCString, already in core-foundation-sys but if we need it explicitly
    // fn CFStringCreateWithCString(alloc: CFAllocatorRef, cStr: *const c_char, encoding: u32) -> CFStringRef;
    // For CFRelease
    // fn CFRelease(cf: CFTypeRef);
}

// Helper function to create a CFStringRef from a Rust string literal.
// Note: core-foundation-sys provides CFStringCreateWithCString.
// Here we are using it to create the key.
fn cfstring_from_rust_str(s: &str) -> Option<CFStringRef> {
    let c_string = std::ffi::CString::new(s).ok()?;
    unsafe {
        Some(core_foundation_sys::string::CFStringCreateWithCString(
            kCFAllocatorDefault,
            c_string.as_ptr(),
            kCFStringEncodingUTF8,
        ))
    }
}

fn get_platform_uuid() -> Option<String> {
    unsafe {
        let mut master_port: IOMasterPortT = MACH_PORT_NULL;
        if IOMasterPort(MACH_PORT_NULL, &mut master_port) != KERN_SUCCESS {
            eprintln!("Error: Couldn't get master port");
            return None;
        }

        let matching_dictionary =
            IOServiceMatching("IOPlatformExpertDevice\0".as_ptr() as *const c_char);
        if matching_dictionary.is_null() {
            eprintln!("Error: IOServiceMatching failed");
            return None;
        }

        let mut iterator: IOIteratorT = 0;
        if IOServiceGetMatchingServices(master_port, matching_dictionary, &mut iterator)
            != KERN_SUCCESS
        {
            // IOServiceMatching returns a +1 CFObject.
            // According to Apple docs for the Obj-C equivalent (matchingDictionaryConsumed),
            // the dictionary is consumed by IOServiceGetMatchingServices and does not need to be released by the caller.
            eprintln!("Error: Couldn't get matching services");
            return None;
        }

        let platform_expert_device = IOIteratorNext(iterator);
        IOObjectRelease(iterator); // Release the iterator

        if platform_expert_device.is_null() {
            eprintln!("Error: Couldn't find platform expert device");
            return None;
        }

        let uuid_key_cfstring = cfstring_from_rust_str("IOPlatformUUID")?;

        let uuid_cfref = IORegistryEntryCreateCFProperty(
            platform_expert_device,
            uuid_key_cfstring,
            kCFAllocatorDefault,
            0,
        );

        // Release the key CFString as IORegistryEntryCreateCFProperty should not consume it.
        core_foundation_sys::base::CFRelease(uuid_key_cfstring as CFTypeRef);
        IOObjectRelease(platform_expert_device as u32); // Release the platform expert device

        if uuid_cfref.is_null() {
            eprintln!("Error: Failed to create CFProperty for UUID");
            return None;
        }

        // Convert CFStringRef to Rust String
        let result_string = {
            let c_str_ptr = CFStringGetCStringPtr(uuid_cfref as CFStringRef, kCFStringEncodingUTF8);
            if !c_str_ptr.is_null() {
                CStr::from_ptr(c_str_ptr).to_string_lossy().into_owned()
            } else {
                let length =
                    core_foundation_sys::string::CFStringGetLength(uuid_cfref as CFStringRef);
                let buffer_size = core_foundation_sys::string::CFStringGetMaximumSizeForEncoding(
                    length,
                    kCFStringEncodingUTF8,
                ) + 1;
                let mut buffer = vec![0u8; buffer_size as usize];
                if core_foundation_sys::string::CFStringGetCString(
                    uuid_cfref as CFStringRef,
                    buffer.as_mut_ptr() as *mut c_char,
                    buffer_size,
                    kCFStringEncodingUTF8,
                ) != 0
                {
                    // Find the NUL terminator for CStr::from_bytes_with_nul_unchecked, or use the whole buffer if somehow no NUL
                    let nul_pos = buffer
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(buffer.len() - 1);
                    CStr::from_bytes_with_nul_unchecked(&buffer[..nul_pos + 1])
                        .to_string_lossy()
                        .into_owned()
                } else {
                    eprintln!("Error: Failed to convert UUID CFString to Rust string via CFStringGetCString");
                    core_foundation_sys::base::CFRelease(uuid_cfref);
                    return None;
                }
            }
        };

        core_foundation_sys::base::CFRelease(uuid_cfref); // Release the UUID CFStringRef (it was created with +1)
        Some(result_string)
    }
}

fn main() {
    match get_platform_uuid() {
        Some(uuid) => println!("IOPlatformUUID: {}", uuid),
        None => println!("Failed to retrieve IOPlatformUUID."),
    }
}
