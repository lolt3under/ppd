import os
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from itertools import islice
import codecs

def format_line(offset, data, width=16, groupsize=2, uppercase=False):
    if not data:
        return ""
    
    # Format hex values with proper grouping
    hex_values = []
    for i in range(0, len(data), groupsize):
        group = data[i:i + groupsize]
        group_hex = ' '.join(f'{b:02X}' if uppercase else f'{b:02x}' for b in group)
        hex_values.append(group_hex)
    
    grouped_hex = ' '.join(hex_values)
    padding = ' ' * (width * 3 - len(grouped_hex))
    ascii_repr = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in data)
    
    return f"{offset:08x}: {grouped_hex}{padding} {ascii_repr}"

def read_file_chunk(file_path, offset, size):
    try:
        with open(file_path, 'rb') as f:
            f.seek(offset)
            return f.read(size)
    except (IOError, OSError) as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

def process_chunk(file_path, offset, size, width, groupsize, uppercase):
    chunk = read_file_chunk(file_path, offset, size)
    return [format_line(offset + i, chunk[i:i + width], width, groupsize, uppercase)
            for i in range(0, len(chunk), width)]

def autoskip(lines):
    result = []
    prev_null = False
    
    for line in lines:
        if not line:
            continue
        
        hex_part = line.split(":")[1].strip().split("  ")[0]
        is_null_line = all(byte == "00" for byte in hex_part.split())
        
        if is_null_line:
            if not prev_null:
                result.append('*')
                prev_null = True
        else:
            result.append(line)
            prev_null = False
    
    return result

def bits_mode(file_path, offset, size):
    chunk = read_file_chunk(file_path, offset, size)
    lines = []
    for i in range(0, len(chunk), 6):
        data = chunk[i:i + 6]
        binary_data = ' '.join(f'{byte:08b}' for byte in data)
        ascii_repr = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in data)
        padding = ' ' * (48 - len(binary_data))
        lines.append(f"{offset + i:08x}: {binary_data}{padding} {ascii_repr}")
    return lines

def revert_mode(input_lines):
    def clean_hex(line):
        try:
            hex_part = line.split(':', 1)[1]
            if '  ' in hex_part:
                hex_part = hex_part.split('  ')[0]
            return ''.join(hex_part.strip().split())
        except (IndexError, ValueError):
            return None

    for line in input_lines:
        line = line.strip()
        if not line or line.startswith('*'):
            continue
        
        hex_data = clean_hex(line)
        if hex_data:
            try:
                binary_data = bytes.fromhex(hex_data)
                sys.stdout.buffer.write(binary_data)
            except ValueError:
                continue

def to_c_include(data):
    if not data:
        return "unsigned char data[] = {};"
    
    hex_bytes = [f"0x{byte:02x}" for byte in data]
    chunks = [hex_bytes[i:i + 12] for i in range(0, len(hex_bytes), 12)]
    body = ',\n  '.join(', '.join(chunk) for chunk in chunks)
    return f"unsigned char data[] = {{\n  {body}\n}};"

def to_ebcdic(data):
    if isinstance(data, bytes):
        try:
            return codecs.encode(data.decode('ascii'), 'cp500')
        except UnicodeError:
            return data
    try:
        return codecs.encode(data, 'cp500')
    except UnicodeError:
        return data

def plain_format_line(offset, data, width=16):
    if not data:
        return ""
    hex_bytes = ' '.join(f'{byte:02x}' for byte in data)
    return f"{offset:08x}: {hex_bytes}"

def main():
    parser = argparse.ArgumentParser(description="A multi-threaded xxd replacement...Kinda")
    parser.add_argument('file', type=str, nargs='?', help="Input file to process.")
    parser.add_argument('outfile', type=str, nargs='?', help="Output file (optional).")
    parser.add_argument('-a', '--autoskip', action='store_true', help="Toggle autoskip for null lines.")
    parser.add_argument('-b', '--bits', action='store_true', help="Dump in binary (bits) instead of hexadecimal.")
    parser.add_argument('-c', '--cols', type=int, default=16, help="Number of columns per line (default: 16).")
    parser.add_argument('-E', '--ebcdic', action='store_true', help="Change ASCII to EBCDIC encoding in the output.")
    parser.add_argument('-g', '--groupsize', type=int, default=2, help="Group output by specified byte size (default: 2).")
    parser.add_argument('-i', '--include', action='store_true', help="Output as a C include file.")
    parser.add_argument('-l', '--len', type=int, help="Limit the number of bytes to process.")
    parser.add_argument('-p', '--plain', action='store_true', help="Output in plain hexdump style.")
    parser.add_argument('-r', '--revert', action='store_true', help="Revert hex dump back to binary.")
    parser.add_argument('-s', '--seek', type=str, help="Start at a specified file offset.")
    parser.add_argument('-u', '--uppercase', action='store_true', help="Use uppercase hex letters.")
    parser.add_argument('-v', '--version', action='store_true', help="Show version information and exit.")
    
    args = parser.parse_args()

    if args.version:
        print("ppd version 1.0")
        sys.exit(0)

    if not args.file and not sys.stdin.isatty():
        args.file = sys.stdin.buffer
    elif not args.file:
        parser.print_help()
        sys.exit(1)

    try:
        file_path = Path(args.file) if isinstance(args.file, str) else args.file
        if isinstance(file_path, Path) and not file_path.is_file():
            print(f"Error: {file_path} is not a valid file.", file=sys.stderr)
            sys.exit(1)

        file_size = file_path.stat().st_size if isinstance(file_path, Path) else 0
        chunk_size = min(65536, file_size if file_size > 0 else 65536)
        width = max(1, args.cols)
        groupsize = max(1, args.groupsize)

        if args.revert:
                if not args.file:
                    print("Error: Input file required", file=sys.stderr)
                    sys.exit(1)
                with open(args.file, 'r') as infile:
                    revert_mode(infile)
                return

        start_offset = 0
        if args.seek:
            try:
                start_offset = int(args.seek, 0)
                if start_offset < 0:
                    start_offset = max(0, file_size + start_offset)
            except ValueError:
                print(f"Error: Invalid seek value: {args.seek}", file=sys.stderr)
                sys.exit(1)

        end_offset = file_size if not args.len else min(start_offset + args.len, file_size)

        with ThreadPoolExecutor() as executor:
            futures = []
            for offset in range(start_offset, end_offset, chunk_size):
                size = min(chunk_size, end_offset - offset)
                if args.bits:
                    futures.append(executor.submit(bits_mode, file_path, offset, size))
                else:
                    futures.append(executor.submit(process_chunk, file_path, offset, size, 
                                                width, groupsize, args.uppercase))

            all_lines = []
            for future in futures:
                try:
                    lines = future.result()
                    all_lines.extend(lines)
                except Exception as e:
                    print(f"Error processing chunk: {e}", file=sys.stderr)
                    sys.exit(1)

        if args.autoskip:
            all_lines = autoskip(all_lines)

        if args.plain:
            all_lines = [plain_format_line(i * width, line.encode() if isinstance(line, str) else line, width) 
                        for i, line in enumerate(all_lines)]

        if args.ebcdic:
            all_lines = [to_ebcdic(line) if isinstance(line, str) else to_ebcdic(str(line))  
                        for line in all_lines if line]

        if args.include:
            print(to_c_include(b''.join(line.encode() if isinstance(line, str) else line 
                                      for line in all_lines)))
        else:
            for line in all_lines:
                if line:
                    print(line)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()