use std::path::PathBuf;

use crate::error::LicenseError;

#[derive(Debug, Clone)]
pub struct UsbDevice {
    pub serial: String,
    pub mount_path: PathBuf,
    pub name: String,
}

pub fn enumerate_usb_devices() -> Result<Vec<UsbDevice>, LicenseError> {
    platform_enumerate()
}

// ---- Windows ----

#[cfg(target_os = "windows")]
fn platform_enumerate() -> Result<Vec<UsbDevice>, LicenseError> {
    use std::ffi::c_void;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, GetDriveTypeW, GetLogicalDriveStringsW, GetVolumeInformationW,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::core::PCWSTR;

    const DRIVE_REMOVABLE: u32 = 2;
    const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D1400;

    #[repr(C)]
    struct StoragePropertyQuery {
        property_id: u32,
        query_type: u32,
        additional: [u8; 1],
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct StorageDeviceDescriptor {
        version: u32,
        size: u32,
        device_type: u8,
        device_type_modifier: u8,
        removable_media: u8,
        command_queueing: u8,
        vendor_id_offset: u32,
        product_id_offset: u32,
        product_revision_offset: u32,
        serial_number_offset: u32,
        bus_type: u32,
        raw_properties_length: u32,
        raw_device_properties: [u8; 1],
    }

    let mut drives_buf = [0u16; 512];
    let len = unsafe { GetLogicalDriveStringsW(Some(&mut drives_buf)) };
    if len == 0 {
        return Ok(Vec::new());
    }

    let mut devices = Vec::new();
    let mut offset = 0usize;

    while offset < len as usize {
        let end = drives_buf[offset..]
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(0);
        if end == 0 {
            break;
        }
        let drive_slice = &drives_buf[offset..offset + end + 1]; // include null
        offset += end + 1;

        let drive_type = unsafe { GetDriveTypeW(PCWSTR(drive_slice.as_ptr())) };
        if drive_type != DRIVE_REMOVABLE {
            continue;
        }

        let drive_letter = (drive_slice[0] as u8) as char;
        let device_path: Vec<u16> = format!("\\\\.\\{}:", drive_letter)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                PCWSTR(device_path.as_ptr()),
                0, // no read/write needed for property query
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                Default::default(),
                HANDLE::default(),
            )
        };

        let handle: HANDLE = match handle {
            Ok(h) => h,
            Err(_) => continue,
        };

        let query = StoragePropertyQuery {
            property_id: 0, // StorageDeviceProperty
            query_type: 0,  // PropertyStandardQuery
            additional: [0],
        };

        let mut buf = [0u8; 1024];
        let mut returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                Some(&query as *const _ as *const c_void),
                std::mem::size_of::<StoragePropertyQuery>() as u32,
                Some(buf.as_mut_ptr() as *mut c_void),
                buf.len() as u32,
                Some(&mut returned),
                None,
            )
        };

        let _ = unsafe { CloseHandle(handle) };

        if ok.is_err() || returned < std::mem::size_of::<StorageDeviceDescriptor>() as u32 {
            continue;
        }

        let desc = unsafe { &*(buf.as_ptr() as *const StorageDeviceDescriptor) };
        if desc.serial_number_offset == 0 || desc.serial_number_offset as usize >= buf.len() {
            continue;
        }

        let serial_start = desc.serial_number_offset as usize;
        let serial_end = buf[serial_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| serial_start + p)
            .unwrap_or(buf.len());
        let serial = String::from_utf8_lossy(&buf[serial_start..serial_end])
            .trim()
            .to_string();

        if serial.is_empty() {
            continue;
        }

        // Get volume label
        let mut vol_name = [0u16; 261];
        let vol_ok = unsafe {
            GetVolumeInformationW(
                PCWSTR(drive_slice.as_ptr()),
                Some(&mut vol_name),
                None,
                None,
                None,
                None,
            )
        };

        let name = if vol_ok.is_ok() {
            let end = vol_name.iter().position(|&c| c == 0).unwrap_or(vol_name.len());
            let label = String::from_utf16_lossy(&vol_name[..end]);
            if label.is_empty() {
                "USB Drive".to_string()
            } else {
                label
            }
        } else {
            "USB Drive".to_string()
        };

        let mount_path = format!("{}:\\", drive_letter);

        devices.push(UsbDevice {
            serial,
            mount_path: PathBuf::from(mount_path),
            name,
        });
    }

    Ok(devices)
}

// ---- Linux ----

#[cfg(target_os = "linux")]
fn platform_enumerate() -> Result<Vec<UsbDevice>, LicenseError> {
    use std::collections::HashMap;

    // Parse /proc/mounts -> device -> mountpoint
    let mounts_content = std::fs::read_to_string("/proc/mounts")
        .map_err(|e| LicenseError::UsbError(format!("Failed to read /proc/mounts: {}", e)))?;

    let mut mounts: HashMap<String, String> = HashMap::new();
    for line in mounts_content.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(dev), Some(mount)) = (parts.next(), parts.next()) {
            mounts.insert(dev.to_string(), mount.to_string());
        }
    }

    let mut devices = Vec::new();

    let block_dir = match std::fs::read_dir("/sys/block") {
        Ok(d) => d,
        Err(_) => return Ok(devices),
    };

    for entry in block_dir.flatten() {
        let block_name = entry.file_name().to_string_lossy().to_string();
        if !block_name.starts_with("sd") {
            continue;
        }

        // Check removable
        let removable_path = format!("/sys/block/{}/removable", block_name);
        let removable = std::fs::read_to_string(&removable_path)
            .unwrap_or_default()
            .trim()
            .to_string();
        if removable != "1" {
            continue;
        }

        // Walk sysfs upward to find USB serial
        let device_link = format!("/sys/block/{}/device", block_name);
        let real_path = match std::fs::canonicalize(&device_link) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let mut serial = String::new();
        let mut current = real_path.as_path();
        for _ in 0..6 {
            let serial_file = current.join("serial");
            if let Ok(s) = std::fs::read_to_string(&serial_file) {
                let s = s.trim().to_string();
                if !s.is_empty() {
                    serial = s;
                    break;
                }
            }
            match current.parent() {
                Some(p) => current = p,
                None => break,
            }
        }

        if serial.is_empty() {
            continue;
        }

        // Find mount point for this device or its partitions
        let dev_path = format!("/dev/{}", block_name);
        let mut mount_path = None;

        // Try partitions first (e.g. /dev/sdb1)
        for i in 1..=9 {
            let part = format!("{}{}",dev_path, i);
            if let Some(mp) = mounts.get(&part) {
                mount_path = Some(mp.clone());
                break;
            }
        }

        // Try whole device
        if mount_path.is_none() {
            if let Some(mp) = mounts.get(&dev_path) {
                mount_path = Some(mp.clone());
            }
        }

        let mount_path = match mount_path {
            Some(mp) => mp,
            None => continue, // not mounted
        };

        // Try to get model name
        let model_path = format!("/sys/block/{}/device/model", block_name);
        let name = std::fs::read_to_string(&model_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "USB Drive".to_string());

        devices.push(UsbDevice {
            serial,
            mount_path: PathBuf::from(mount_path),
            name,
        });
    }

    Ok(devices)
}

// ---- Unsupported platforms ----

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn platform_enumerate() -> Result<Vec<UsbDevice>, LicenseError> {
    Err(LicenseError::UsbError(
        "USB token enumeration not supported on this platform".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // requires physical USB device
    fn test_enumerate_usb() {
        let devices = enumerate_usb_devices().unwrap();
        println!("Found {} USB device(s):", devices.len());
        for dev in &devices {
            println!("  serial={}, mount={}, name={}", dev.serial, dev.mount_path.display(), dev.name);
        }
    }
}
