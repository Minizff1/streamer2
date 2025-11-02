from flask import *
import threading
import keyboard
from datetime import datetime

import sys
import time
import platform
import os
import hashlib
from time import sleep
from datetime import datetime
# from aob import *


from pymem import *
from pymem.memory import read_bytes, write_bytes
from pymem.pattern import pattern_scan_all
import os


def mkp(aob: str):
    if '??' in aob:
        if aob.startswith("??"):
            aob = f" {aob}"
            n = aob.replace(" ??", ".").replace(" ", "\\x")
            b = bytes(n.encode())
        else:
            n = aob.replace(" ??", ".").replace(" ", "\\x")
            b = bytes(f"\\x{n}".encode())
        del n
        return b
    else:
        m = aob.replace(" ", "\\x")
        c = bytes(f"\\x{m}".encode())
        del m
        return c
    


def HEADLOAD():
    try:

        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        return

    try:
        if proc:
            print("\033[31m[>]\033[0m Searching Entity...")
            
            global aimbot_addresses
            entity_pattern = mkp("FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 A5 43")
            aimbot_addresses = pattern_scan_all(proc.process_handle, entity_pattern, return_multiple=True)

            if aimbot_addresses:
                print("Addresses found")
                
            else:
                print("Failed")
    
    except:
        print("")
    finally:
        if proc:
            proc.close_process()
    return "Fitur Berhasil Di Load"
    


def HEADON():
    try:
        proc = Pymem("HD-Player")
    
        if proc:
            global original_value
            original_value = []
            for current_entity in aimbot_addresses:
                original_value.append((current_entity, read_bytes(proc.process_handle, current_entity + 0xA6, 4)))
                # Read the value at current_entity + 0x60
                # Read the value at current_entity + 0x2C
                value_bytes = read_bytes(proc.process_handle, current_entity +  0xAA, 4) 
                
                # Write the value to current_entity + 0x5C
                # Write the value to current_entity + 0x28
                write_bytes(proc.process_handle, current_entity + 0xA6, value_bytes, len(value_bytes))
    except pymem.exception.ProcessNotFound:
        print("")
        return
    finally:
        if proc:
            proc.close_process()
           
    return "AIMBOT HEAD ON"

def HEADOFF():
    try:
        # Open the process
        proc = Pymem("HD-Player")
        
        if original_value:
         
            for i in original_value:
                # Write the value to current_entity + 0x5C
                # Write the value to current_entity + 0x28
                write_bytes(proc.process_handle, i[0] + 0xA6, i[1], len(i[1]))
    except pymem.exception.ProcessNotFound:
        print("")
        return
    finally:
        if proc:
            proc.close_process()
    return "AIMBOT HEAD OFF"


def RIGHTSHOULDERON():
    try:
        # Open the process
        proc = Pymem("HD-Player")
    
        if proc:
            global original_value
            # Save the original value to variable, btw all the orginal values are same so we just save one
            original_value = []
            for current_entity in aimbot_addresses:
                original_value.append((current_entity, read_bytes(proc.process_handle, current_entity + 0xA6, 4)))
                # Read the value at current_entity + 0x60
                # Read the value at current_entity + 0x2C
                value_bytes = read_bytes(proc.process_handle, current_entity + 0xDA, 4)
                
                # Write the value to current_entity + 0x5C
                # Write the value to current_entity + 0x28
                write_bytes(proc.process_handle, current_entity + 0xA6, value_bytes, len(value_bytes))    
    except pymem.exception.ProcessNotFound:
        print("")
        return
    finally:
        if proc:
            proc.close_process()
           
    return "AIMBOT DRAG ON"

def RIGHTSHOULDEROFF():
    try:
        # Open the process
        proc = Pymem("HD-Player")
        
        if original_value: # check the original value is present or not
         
            for i in original_value:
                # Write the value to current_entity + 0x5C
                # Write the value to current_entity + 0x28
                write_bytes(proc.process_handle, i[0] + 0xA6, i[1], len(i[1]))
    except pymem.exception.ProcessNotFound:
        print("")
        return
    finally:
        if proc:
            proc.close_process()
    return "AIMBOT DRAG OFF"


def LEFTSHOULDERON():
    try:
        # Open the process
        proc = Pymem("HD-Player")
    
        if proc:
            global original_value
            # Save the original value to variable, btw all the orginal values are same so we just save one
            original_value = []
            for current_entity in aimbot_addresses:
                original_value.append((current_entity, read_bytes(proc.process_handle, current_entity + 0xA6, 4)))
                # Read the value at current_entity + 0x60
                # Read the value at current_entity + 0x2C
                value_bytes = read_bytes(proc.process_handle, current_entity + 0xD6, 4) 
                
                # Write the value to current_entity + 0x5C
                # Write the value to current_entity + 0x28
                write_bytes(proc.process_handle, current_entity + 0xA6, value_bytes, len(value_bytes))    
    except pymem.exception.ProcessNotFound:
        print("")
        return
    finally:
        if proc:
            proc.close_process()
           
    return "AIMBOT DRAG ON"

def LEFTSHOULDEROFF():
    try:
        # Open the process
        proc = Pymem("HD-Player")
        
        if original_value: # check the original value is present or not
         
            for i in original_value:
                # Write the value to current_entity + 0x5C
                # Write the value to current_entity + 0x28
                write_bytes(proc.process_handle, i[0] + 0xA6, i[1], len(i[1]))
    except pymem.exception.ProcessNotFound:
        print("")
        return
    finally:
        if proc:
            proc.close_process()
    return "AIMBOT DRAG OFF"

# def taskmanager():
#     process_name = "Taskmgr.exe"

#     try:
#         # Open the process
#         temp_dll_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'task.dll')

#         dll_path_bytes = bytes(temp_dll_path.encode('UTF-8'))

#         open_process = Pymem(process_name)

#         process.inject_dll(open_process.process_handle, dll_path_bytes)
#         print("Task Manager Injected DLL Successfully!") 

#     except pymem.exception.ProcessNotFound:
#         print("Task Manager not found!")
#     except Exception as e:
#         print(f"Error: {e}")

def RemoveRecoil():
    try:
       proc = Pymem("HD-Player")
    except:
        pass

    try:
       if proc:
        value = pattern_scan_all(proc.process_handle, mkp("7a 44 f0 48 2d e9 10 b0 8d e2 02 8b 2d ed 08 d0 4d e2 00 50 a0 e1 10 1a 08 ee 08 40 95 e5 00 00 54 e3"), return_multiple=True)
    except:
        pass
  
    

    if value :
      for addr in value :
        write_bytes(proc.process_handle, addr, bytes.fromhex("00 00"),2)


def AddRecoil():
    try:
       proc = Pymem("HD-Player")
    except:
        pass

    try:
       if proc:
        value = pattern_scan_all(proc.process_handle, mkp("00 00 f0 48 2d e9 10 b0 8d e2 02 8b 2d ed 08 d0 4d e2 00 50 a0 e1 10 1a 08 ee 08 40 95 e5 00 00 54 e3"), return_multiple=True)
    except:
        pass
  
    

    if value :
      for addr in value :
        write_bytes(proc.process_handle, addr, bytes.fromhex("7a 44"),2)


def box3d():
    process_name = "HD-Player"

    try:
        # Open the process
        temp_dll_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'BOX.dll')

        dll_path_bytes = bytes(temp_dll_path.encode('UTF-8'))

        open_process = Pymem(process_name)

        process_name.inject_dll(open_process.process_handle, dll_path_bytes)
        print("Chams Box Injected DLL Successfully!") 

    except pymem.exception.ProcessNotFound:
        print("Task Manager not found!")
    except Exception as e:
        print(f"Error: {e}")

def chamsmenu():
    process_name = "HD-Player.exe"

    try:
        # Open the process
        temp_dll_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'charms_menu.dll')

        dll_path_bytes = bytes(temp_dll_path.encode('UTF-8'))

        open_process = Pymem(process_name)

        process_name.inject_dll(open_process.process_handle, dll_path_bytes)
        print("Chams Blue Injected DLL Successfully!") 

    except pymem.exception.ProcessNotFound:
        print("Task Manager not found!")
    except Exception as e:
        print(f"Error: {e}")

def chams3d():
    process_name = "HD-Player.exe"

    try:
        # Open the process
        temp_dll_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'wallfixedchams.dll')

        dll_path_bytes = bytes(temp_dll_path.encode('UTF-8'))

        open_process = Pymem(process_name)

        process_name.inject_dll(open_process.process_handle, dll_path_bytes)
        print("Chams 3D Injected DLL Successfully!") 

    except pymem.exception.ProcessNotFound:
        print("Task Manager not found!")
    except Exception as e:
        print(f"Error: {e}")


def SNIPERSCOPELOAD():
    try:
        # Open the process
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        return

    try:
        if proc:
            print("\033[31m[>]\033[0m Searching Entity...")
            # Scan for entities
            global sniperScopeAddress
            sniperScopePattern = mkp("CC 3D 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F 33 33 13 40 00 00 B0 3F 00 00 80 3F 01")
            sniperScopeAddress = pattern_scan_all(proc.process_handle, sniperScopePattern, return_multiple=True)

            if sniperScopeAddress:
                print("")
                
            else:
                print("")
    
    except:
        print("")
    finally:
        if proc:
            proc.close_process()
    return "Fitur Berhasil Di Load"

def ACTIVATELOADEDSCOPE():
    try:
        # Open the process
        proc = Pymem("HD-Player")
    
        if proc:
            global original_Scope_value
            # Save the original value to variable, btw all the orginal values are same so we just save one
            original_Scope_value = []

            for addr in sniperScopeAddress:

                current_value = read_bytes(proc.process_handle, addr, 22)
                original_Scope_value.append(current_value)


                write_bytes(proc.process_handle, addr, bytes.fromhex("CC 3D 06 00 00 00 00 00 80 3F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 33 33 13 40 00 00 B0 3F 00 00 80 3F 01"),39)

    except pymem.exception.ProcessNotFound:
        print("")
        return
    finally:
        if proc:
            proc.close_process()
           
    return "AIMBOT HEAD ON"

def REMOVELOADEDSCOPE():
    try:
        # Open the process
        proc = Pymem("HD-Player")
        
        if original_Scope_value:  # Ensure the original values exist before proceeding
            for i, original_val in enumerate(original_Scope_value):
                # Write back the original value stored in `original_value` for each address
                write_bytes(proc.process_handle, sniperScopeAddress[i], original_val, 22)
                
    except pymem.exception.ProcessNotFound:
        print("")
        return
    finally:
        if proc:
            proc.close_process()
    return "AIMBOT HEAD OFF"



def SNIPERSWITCHLOAD():
    try:
        # Open the process
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        return

    try:
        if proc:
            print("\033[31m[>]\033[0m Searching Entity...")
            # Scan for entities
            global sniperSwitchAddress
            sniperSwitchPattern = mkp("B4 C8 D6 3F 00 00 80 3F 00 00 80 3F 0A D7 A3 3D 00 00 00 00 00 00 5C 43 00 00 90 42 00 00 B4 42 96 00 00 00 00 00 00 00 00 00 00 3F 00 00 80 3E 00 00 00 00 04 00 00 00 00 00 80 3F 00 00 20 41 00 00 34 42 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F 8F C2 35 3F 9A 99 99 3F 00 00 80 3F 00 00 00 00 00 00 80 3F 00 00 80 3F 00 00 80 3F 00 00 00 00 00 00 00 00 00 00 00 3F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F 00 00 80 3F")
            sniperSwitchAddress = pattern_scan_all(proc.process_handle, sniperSwitchPattern, return_multiple=True)

            if sniperSwitchAddress:
                print("")
                
            else:
                print("")
    
    except:
        print("")
    finally:
        if proc:
            proc.close_process()
    return "Fitur Berhasil Di Load"

def ACTIVATELOADEDSWITCH():
    try:
        # Open the process
        proc = Pymem("HD-Player")
    
        if proc:
            global original_Switch_value
            # Save the original value to variable, btw all the orginal values are same so we just save one
            original_Switch_value = []

            for addr in sniperSwitchAddress:

                current_value = read_bytes(proc.process_handle, addr, 22)
                original_Switch_value.append(current_value)


                write_bytes(proc.process_handle, addr, bytes.fromhex("B4 C8 D6 3F 00 00 80 3F 00 00 80 3F 0A D7 A3 3D 00 00 00 00 00 00 5C 43 00 00 90 42 00 00 B4 42 96 00 00 00 00 00 00 00 00 00 00 3C 00 00 80 3C 00 00 00 00 04 00 00 00 00 00 80 3F 00 00 20 41 00 00 34 42 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F 8F C2 35 3F 9A 99 99 3F 00 00 80 3F 00 00 00 00 00 00 80 3F 00 00 80 3F 00 00 80 3F 00 00 00 00 00 00 00 00 00 00 00 3F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F 00 00 80 3F"),148)

    except pymem.exception.ProcessNotFound:
        print("")
        return
    finally:
        if proc:
            proc.close_process()
           
    return "AIMBOT HEAD ON"

def REMOVELOADEDSWITCH():
    try:
        # Open the process
        proc = Pymem("HD-Player")
        
        if original_Switch_value:  # Ensure the original values exist before proceeding
            for i, original_val in enumerate(original_Switch_value):
                # Write back the original value stored in `original_value` for each address
                write_bytes(proc.process_handle, sniperSwitchAddress[i], original_val, 26)
                
    except pymem.exception.ProcessNotFound:
        print("")
        return
    finally:
        if proc:
            proc.close_process()
    return "AIMBOT HEAD OFF"


def clear():
    if platform.system() == 'Windows':
        os.system('cls & title Python Example')
    elif platform.system() == 'Linux':
        os.system('clear')
        sys.stdout.write("\x1b]0;Python Example\x07")
    # elif platform.system() == 'Darwin':
    #     os.system("clear && printf '\e[3J'")
    #     os.system('''echo - n - e "\033]0;Python Example\007"''')

def getchecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest

def _hex_normalize(s: str) -> str:
    # remove newlines/spaces and return continuous hex string
    return ''.join(s.split())

def WALLHACKLOAD():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        return "HD-Player not running"

    pattern_hex = """AE 47 81 3F AE 47 81 3F AE 47 81 3F AE 47 81 3F 00 1A B7 EE DC 3A 9F ED 30"""
    try:
        global wallhack_addresses
        print("\033[31m[>]\033[0m Searching wallhack patterns...")
        wall_pattern = mkp(pattern_hex)
        wallhack_addresses = pattern_scan_all(proc.process_handle, wall_pattern, return_multiple=True)
        if wallhack_addresses:
            print(f"Found {len(wallhack_addresses)} candidate(s).")
        else:
            print("No wallhack addresses found.")
    except Exception as e:
        print("WALLHACKLOAD error:", repr(e))
    finally:
        if proc:
            proc.close_process()
    return "WALLHACK pattern loaded"

def ACTIVATEWALLHACK():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        return "HD-Player not running"
    patch_hex = """00 00 EF C1 AE 47 81 3F AE 47 81 3F AE 47 81 3F 00 1A B7 EE DC 3A 9F ED 30"""
    try:
        global original_wall_bytes
        global wallhack_addresses
        original_wall_bytes = []
        if not wallhack_addresses:
            return "No wallhack addresses loaded. Run WALLHACKLOAD first."
        patch_hex_norm = _hex_normalize(patch_hex)
        try:
            patch_bytes = bytes.fromhex(patch_hex_norm)
        except Exception as e:
            return f"Invalid patch hex: {e}"
        patch_len = len(patch_bytes)
        if patch_len == 0:
            return "Patch hex is empty."
        for addr in wallhack_addresses:
            try:
                orig = read_bytes(proc.process_handle, addr, patch_len)
                original_wall_bytes.append(orig)
                write_bytes(proc.process_handle, addr, patch_bytes, patch_len)
            except Exception as e:
                print(f"Write/Read error at {hex(addr)}:", repr(e))
    except Exception as e:
        print("ACTIVATEWALLHACK error:", repr(e))
        return "Failed to enable wallhack"
    finally:
        if proc:
            proc.close_process()
    return "Wallhack enabled"

def REMOVEWALLHACK():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        return "HD-Player not running"
    try:
        global original_wall_bytes
        global wallhack_addresses
        if not original_wall_bytes or not wallhack_addresses:
            return "No original bytes saved. Nothing to restore."
        for i, orig in enumerate(original_wall_bytes):
            try:
                write_bytes(proc.process_handle, wallhack_addresses[i], orig, len(orig))
            except Exception as e:
                print(f"Restore error for addr {hex(wallhack_addresses[i])}:", repr(e))
    except Exception as e:
        print("REMOVEWALLHACK error:", repr(e))
        return "Failed to disable wallhack"
    finally:
        if proc:
            proc.close_process()
    return "Wallhack disabled"

def SPEEDHACKLOAD():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        return "HD-Player not running"

    try:
        global speedHackAddress
        print("\033[31m[>]\033[0m Searching speed addresses...")
        speedPattern = mkp("00 01 00 00 00 02 2B 07 3D")  # Example pattern
        speedHackAddress = pattern_scan_all(proc.process_handle, speedPattern, return_multiple=True)

        if speedHackAddress:
            print(f"Found {len(speedHackAddress)} addresses")
        else:
            print("No addresses found")
    finally:
        proc.close_process()

    return "Speed hack addresses loaded"


def ACTIVATELOADEDSPEED():
    try:
        proc = Pymem("HD-Player")
        global original_Speed_value
        original_Speed_value = []

        for addr in speedHackAddress:
            current_value = read_bytes(proc.process_handle, addr, 9)  # match pattern length
            original_Speed_value.append(current_value)

            # Overwrite with higher speed value
            write_bytes(proc.process_handle, addr, bytes.fromhex("00 01 00 00 00 92 E4 50 3D"), 9)

    except pymem.exception.ProcessNotFound:
        return "HD-Player not running"
    finally:
        proc.close_process()

    return "Speed hack enabled"


def REMOVESPEEDHACK():
    try:
        proc = Pymem("HD-Player")
        if original_Speed_value:
            for i, original_val in enumerate(original_Speed_value):
                write_bytes(proc.process_handle, speedHackAddress[i], original_val, 9)
    except pymem.exception.ProcessNotFound:
        return "HD-Player not running"
    finally:
        proc.close_process()

    return "Speed hack disabled"

# if sys.platform == "win32":
#     ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

# def taskmanagerloop():
#     while True:
#         taskmanager()
#         print("Taskmanager is running...")
#         time.sleep(2)  # Wait for 2 seconds

# def run_taskmanager():
#     # Running taskmanagerloop in a separate thread
#     task_thread = threading.Thread(target=taskmanagerloop)
#     task_thread.daemon = True  # Allows thread to exit when the main program exits
#     task_thread.start()

# === Internal Tab: OOP AimbotInternalPro ===

# Singleton for persistent state across requests
_aimbot_internal_singleton = None

def get_aimbot_internal():
    global _aimbot_internal_singleton
    if _aimbot_internal_singleton is None:
        _aimbot_internal_singleton = AimbotInternalPro()
    return _aimbot_internal_singleton

import pymem
from pymem import Pymem
import pymem.process

class AimbotInternalPro:
    def __init__(self):
        self.proc = None
        self.aimbot_addresses = []
        self.original_values = []
    
    def connect(self):
        try:
            self.proc = Pymem("HD-Player")
            return True
        except pymem.exception.ProcessNotFound:
            return False
    
    def disconnect(self):
        if self.proc:
            self.proc.close_process()
            self.proc = None
    
    def pattern_scan(self, pattern, return_multiple=True):
        if not self.proc:
            return None
        return pymem.pattern.pattern_scan_all(self.proc.process_handle, pattern, return_multiple=return_multiple)
    
    def read_memory(self, address, size):
        if not self.proc:
            return None
        return pymem.memory.read_bytes(self.proc.process_handle, address, size)
    
    def write_memory(self, address, value):
        if not self.proc:
            return False
        pymem.memory.write_bytes(self.proc.process_handle, address, value, len(value))
        return True
    
    def mkp(self, aob: str):
        if '??' in aob:
            if aob.startswith("??"):
                aob = f" {aob}"
                n = aob.replace(" ??", ".").replace(" ", "\\x")
                b = bytes(n.encode())
            else:
                n = aob.replace(" ??", ".").replace(" ", "\\x")
                b = bytes(f"\\x{n}".encode())
            del n
            return b
        else:
            m = aob.replace(" ", "\\x")
            c = bytes(f"\\x{m}".encode())
            del m
            return c
    
    def load_aimbot(self):
        if not self.connect():
            return "HD-Player not running"
        try:
            print("\033[31m[>]\033[0m Searching Entity...")
            entity_pattern = self.mkp("FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 A5 43")
            self.aimbot_addresses = self.pattern_scan(entity_pattern)
            if self.aimbot_addresses:
                print("Aimbot addresses found")
                return "Aimbot loaded successfully"
            else:
                print("No aimbot addresses found")
                return "Failed to load aimbot"
        except Exception as e:
            print(f"Error loading aimbot: {e}")
            return "Error loading aimbot"
        finally:
            self.disconnect()
    
    def head_aim_on(self):
        if not self.connect():
            return "HD-Player not running"
        try:
            self.original_values = []
            for current_entity in self.aimbot_addresses:
                self.original_values.append((current_entity, self.read_memory(current_entity + 0xA6, 4)))
                value_bytes = self.read_memory(current_entity + 0xAA, 4)
                self.write_memory(current_entity + 0xA6, value_bytes)
            return "HEAD AIM ON"
        except Exception as e:
            print(f"Error enabling head aim: {e}")
            return "Error enabling head aim"
        finally:
            self.disconnect()
    
    def head_aim_off(self):
        if not self.connect():
            return "HD-Player not running"
        try:
            if self.original_values:
                for addr, original_val in self.original_values:
                    self.write_memory(addr + 0xA6, original_val)
            return "HEAD AIM OFF"
        except Exception as e:
            print(f"Error disabling head aim: {e}")
            return "Error disabling head aim"
        finally:
            self.disconnect()
    
    def right_shoulder_aim_on(self):
        if not self.connect():
            return "HD-Player not running"
        try:
            self.original_values = []
            for current_entity in self.aimbot_addresses:
                self.original_values.append((current_entity, self.read_memory(current_entity + 0xA6, 4)))
                value_bytes = self.read_memory(current_entity + 0xDA, 4)
                self.write_memory(current_entity + 0xA6, value_bytes)
            return "RIGHT SHOULDER AIM ON"
        except Exception as e:
            print(f"Error enabling right shoulder aim: {e}")
            return "Error enabling right shoulder aim"
        finally:
            self.disconnect()
    
    def left_shoulder_aim_on(self):
        if not self.connect():
            return "HD-Player not running"
        try:
            self.original_values = []
            for current_entity in self.aimbot_addresses:
                self.original_values.append((current_entity, self.read_memory(current_entity + 0xA6, 4)))
                value_bytes = self.read_memory(current_entity + 0xD6, 4)
                self.write_memory(current_entity + 0xA6, value_bytes)
            return "LEFT SHOULDER AIM ON"
        except Exception as e:
            print(f"Error enabling left shoulder aim: {e}")
            return "Error enabling left shoulder aim"
        finally:
            self.disconnect()
    
    def shoulder_aim_off(self):
        return self.head_aim_off()  # Uses same restore mechanism as head aim