#!/usr/bin/env python3
"""
Compact hex viewer with colored highlighting for BOMs and problematic bytes.
Analyzes files, suggests fixes, and optionally auto-corrects in memory.
"""

import argparse
import sys
from pathlib import Path

# ANSI color codes
RESET    = "\033[0m"
HILITE_BOM  = "\033[48;5;135m"  # Purple background (already has m)
HILITE_NULL = "\033[48;5;240m"  # Dark gray background (already has m)
HILITE_CR   = "\033[48;5;203m"  # Orange background (already has m)
HILITE_INV  = "\033[48;5;100m"  # Dark green background (already has m)
# All known BOM signatures (longest-first)
BOMS = [
    (b"\xff\xfe\x00\x00", "UTF-32 LE"),   # 4 bytes
    (b"\x00\x00\xfe\xff", "UTF-32 BE"),   # 4 bytes
    (b"\xef\xbb\xbf",     "UTF-8"),      # 3 bytes
    (b"\xff\xfe",         "UTF-16 LE"),  # 2 bytes
    (b"\xfe\xff",         "UTF-16 BE"),  # 2 bytes
    # Optional special cases for corrupted Windows outputs:
    (b"\xfe\xfe\xbf",     "UTF-8 corrupt"),
]
]

def detect_bom(data: bytes) -> tuple[int, str]:
    """Return (bom_length, bom_name). 0 length means no BOM."""
    for bom, name in BOMS:
        if data.startswith(bom):
            return len(bom), name
    return 0, "none"

def classify_byte(b: int, bom_range: tuple[int, int], pos: int) -> tuple[str, str]:
    """Classify byte and return (color_code, display_string)."""
    if b == 0x0D:
        return HILITE_CR, f"/[CR]"
    if b == 0x00:
        return HILITE_NULL, f"00"
    if pos in range(*bom_range):
        return HILITE_BOM, f"[{b:02X}]"
    if 0x80 <= b <= 0xFF:
        return HILITE_INV, f"[{b:02X}]"
    if 0x20 <= b <= 0x7E:
        return RESET, chr(b)
    return RESET, f"[{b:02X}]"

def hexdump(lines_with_bom: list[tuple[bytes, int]]) -> None:
    """Compact hex dump with LEGEND + lines (no extra spacing)."""
    print("Legend:")
    print(f"  {HILITE_BOM}[FF]{RESET}{HILITE_BOM}[FE]{RESET}  BOM marker bytes")
    print(f"  {HILITE_NULL}[00]{RESET}       Null bytes (0x00)")
    print(f"  {HILITE_INV}[80-FF]{RESET} Invalid UTF-8 / high bytes")
    print(f"  {HILITE_CR}[CR]{RESET}     Carriage return (0x0D)")
    
    for line_idx, (line, bom_len) in enumerate(lines_with_bom, 1):
        stripped = line.rstrip(b"\r\n")
        actual_bom_len = min(bom_len, len(stripped))
        
        if not stripped:
            continue
        
        print(f"{line_idx:4d} ", end="")
        
        for offset in range(0, len(stripped), 16):
            chunk = stripped[offset:offset + 16]
            
            cells = []
            for i, b in enumerate(chunk):
                abs_idx = offset + i
                color, display = classify_byte(b, (0, actual_bom_len), abs_idx)
                if color != RESET:
                    cells.append(f"{color}{display}{RESET}")
                else:
                    cells.append(display)
            
            pad = "   " * (16 - len(chunk))
            ascii_col = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            
            if offset == 0:
                print(f"{offset:04x} {' '.join(cells)}{pad} |{ascii_col}|")
            else:
                print(f"       {' '.join(cells)}{pad} |{ascii_col}|")
        
        print()

def analyze_file(filepath: Path, num_lines: int) -> tuple[dict, bytes, list[tuple[bytes, int]]]:
    """Analyze file and return stats about problems found."""
    stats = {
        "boms_found": [],
        "has_null_bytes": False,
        "has_carriage_returns": False,
        "has_invalid_utf8": False,
        "total_lines": 0,
        "lines_analyzed": 0,
    }
    
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
    except (PermissionError, OSError) as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Check first 10 bytes for BOM
    first_bytes = raw[:10]
    bom_len, bom_name = detect_bom(first_bytes)
    if bom_len:
        stats["boms_found"].append((bom_len, bom_name, first_bytes[:bom_len].hex(' ')))
    
    # Check for null bytes anywhere in file
    null_count = raw.count(b"\x00")
    if null_count:
        stats["has_null_bytes"] = True
        stats["null_count"] = null_count
    
    # Check for carriage returns
    cr_count = raw.count(b"\r")
    if cr_count:
        stats["has_carriage_returns"] = True
        stats["cr_count"] = cr_count
    
    # Check for invalid UTF-8 (0x80-0xFF)
    invalid_count = sum(1 for b in raw if 0x80 <= b <= 0xFF)
    if invalid_count:
        stats["has_invalid_utf8"] = True
        stats["invalid_count"] = invalid_count
    
    # Scan first N lines - respect num_lines limit strictly
    lines_with_bom = []
    offset = 0
    lines_in_file = 0
    
    while offset < len(raw) and len(lines_with_bom) < num_lines:
        next_newline = raw.find(b"\n", offset)
        if next_newline == -1:
            line = raw[offset:]
        else:
            line = raw[offset:next_newline + 1]
        
        if not line:
            break
        
        lines_in_file += 1
        stripped = line.rstrip(b"\r\n")
        line_bom_len, _ = detect_bom(stripped)
        
        lines_with_bom.append((line, line_bom_len))
        offset = next_newline + 1
    
    stats["lines_analyzed"] = min(num_lines, lines_in_file)
    stats["lines_with_bom"] = sum(1 for _, blen in lines_with_bom if blen > 0)
    stats["total_lines"] = lines_in_file
    
    return stats, raw, lines_with_bom

def generate_sed_commands(filepath: Path, stats: dict) -> list[str]:
    """Generate sed commands to fix detected issues."""
    commands = []
    
    # 1. Remove BOM at start of file
    for bom_len, bom_name, hex_bytes in stats.get("boms_found", []):
        if bom_len == 3 and hex_bytes == "ef bb bf":
            cmd = f"sed -i '1s/^\\xEF\\xBB\\xBF//' {filepath}"
        elif bom_len == 3 and hex_bytes == "fe fe bf":
            cmd = f"sed -i '1s/^\\xFE\\xFE\\xBF//' {filepath}"
        elif bom_len == 2 and hex_bytes.startswith("ff fe"):
            cmd = f"sed -i '1s/^\\xFF\\xFE//' {filepath}"
        elif bom_len == 2 and hex_bytes.startswith("fe ff"):
            cmd = f"sed -i '1s/^\\xFE\\xFF//' {filepath}"
        else:
            cmd = f"# BOM removal: manual intervention needed for {bom_name}"
        commands.append(cmd)
    
    # 2. Remove null bytes
    if stats.get("has_null_bytes"):
        count = stats.get("null_count", "?")
        commands.append(f"# Remove {count} null byte(s) found in file")
        commands.append(f"sed -i 's/\\x00//g' {filepath}")
    
    # 3. Remove carriage returns
    if stats.get("has_carriage_returns"):
        count = stats.get("cr_count", "?")
        commands.append(f"# Remove {count} carriage return(s) (\\r)")
        commands.append(f"sed -i 's/\\r//g' {filepath}")
    
    # 4. Note about invalid UTF-8 (requires perl/python, not sed)
    if stats.get("has_invalid_utf8"):
        count = stats.get("invalid_count", "?")
        commands.append(f"# Note: {count} invalid UTF-8 byte(s) (0x80-0xFF)")
        commands.append("# Remove with Python (no simple sed equivalent):")
        commands.append(f"iconv -c -f utf-8 -t ascii {filepath}")
    
    return commands

def clean_line(line: bytes, stats: dict) -> bytes:
    """Clean a single line, updating stats dict."""
    cleaned = line
    
    # 1. Remove BOM markers
    for bom, name in BOMS:
        count = 0
        while bom in cleaned:
            cleaned = cleaned.replace(bom, b"", 1)
            count += 1
        if count:
            stats["boms_removed"] += count
            stats["bom_types"][name] = stats["bom_types"].get(name, 0) + count
    
    # 2. Remove null bytes
    null_count = cleaned.count(b"\x00")
    if null_count:
        cleaned = cleaned.replace(b"\x00", b"")
        stats["null_bytes_removed"] += null_count
    
    # 3. Remove carriage returns (FIXED: this was missing!)
    cr_count = cleaned.count(b"\r")
    if cr_count:
        cleaned = cleaned.replace(b"\r", b"")
        stats["carriage_returns_removed"] += cr_count
    
    # 4. Remove invalid UTF-8 (bytes 0x80-0xFF)
    invalid_count = sum(1 for b in cleaned if 0x80 <= b <= 0xFF)
    if invalid_count:
        cleaned = bytes(b for b in cleaned if b < 0x80 or b >= 0xF0)
        stats["invalid_utf8_removed"] += invalid_count
    
    return cleaned

def clean_file_in_memory(raw: bytes, stats: dict) -> bytes:
    """Clean entire file loaded in memory - fixes ALL lines regardless of display limit."""
    lines = raw.split(b"\n")
    cleaned_lines = []
    
    for i, line in enumerate(lines):
        # Add newline back except for last line if original had no trailing \n
        if i < len(lines) - 1 or raw.endswith(b"\n"):
            line += b"\n"
        
        processed = clean_line(line, stats)
        if processed:
            cleaned_lines.append(processed)
    
    return b"".join(cleaned_lines)

def prompt_yes_no(question: str) -> bool:
    """Prompt user for yes/no answer."""
    while True:
        try:
            response = input(f"{question} [y/N]: ").strip().lower()
            if response in ('y', 'yes'):
                return True
            elif response in ('n', 'no', ''):
                return False
            else:
                print("Please enter 'y' or 'n'.")
        except (EOFError, KeyboardInterrupt):
            print("\nAborted by user.")
            return False

def verify_after_fix(filepath: Path) -> None:
    """Verify file is clean after auto-fix - WITHOUT re-prompting."""
    print("\nVerifying...")
    
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
    except (PermissionError, OSError) as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return
    
    # Quick verification checks
    issues_remaining = []
    
    if raw[:3] in [b"\xef\xbb\xbf", b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"]:
        issues_remaining.append("BOM at file start")
    
    if raw.count(b"\x00") > 0:
        issues_remaining.append(f"Null bytes (0x00): {raw.count(b'\\x00')} found")
    
    if raw.count(b"\r") > 0:
        issues_remaining.append(f"Carriage returns (\\r): {raw.count(b'\\r')} found")
    
    invalid_count = sum(1 for b in raw if 0x80 <= b <= 0xFF)
    if invalid_count > 0:
        issues_remaining.append(f"Invalid UTF-8 (0x80-0xFF): {invalid_count} found")
    
    if issues_remaining:
        print("⚠ WARNING: Some issues remain after cleaning:")
        for issue in issues_remaining:
            print(f"  • {issue}")
    else:
        print("✓ File is now clean!")

def process_file(filepath: Path, num_lines: int, verbose: bool) -> None:
    """Main processing function."""
    if not filepath.is_file():
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    
    stats, raw, lines_with_bom = analyze_file(filepath, num_lines)
    
    if verbose:
        print(f"File: {filepath}")
        print(f"Size: {len(raw)} bytes ({len(raw)/(1024*1024):.2f} MB)")
        print(f"Lines: {stats['total_lines']}")
        print(f"Lines to display: {num_lines}")
        first_bytes = raw[:10]
        print(f"First 10 bytes: {first_bytes.hex(' ')}")
        print()
    
    # Show hex dump
    hexdump(lines_with_bom)
    
    # Summary
    print("=" * 60)
    print("PROBLEM SUMMARY")
    print("=" * 60)
    
    if stats["boms_found"]:
        for bom_len, bom_name, hex_bytes in stats["boms_found"]:
            print(f"✗ BOM detected at start: {bom_name} ({bom_len} bytes: {hex_bytes})")
    else:
        print("✓ No BOM markers at file start")
    
    if stats.get("has_null_bytes"):
        print(f"✗ Null bytes (0x00) found: {stats.get('null_count')} total")
    else:
        print("✓ No null bytes found")
    
    if stats.get("has_carriage_returns"):
        print(f"⚠ Carriage returns (\\r) found: {stats.get('cr_count')} total")
    else:
        print("✓ No carriage returns found")
    
    if stats.get("has_invalid_utf8"):
        print(f"⚠ High bytes (0x80-0xFF) found: {stats.get('invalid_count')} total")
    else:
        print("✓ No invalid UTF-8 bytes")
    
    print()
    
    # Calculate total problematic bytes
    total_problems = (
        sum(bl for bl, _, _ in stats["boms_found"]) +
        stats.get("null_count", 0) +
        stats.get("cr_count", 0) +
        stats.get("invalid_count", 0)
    )
    
    # Prompt for auto-fix
    if total_problems > 0:
        # Print sed commands FIRST (already filtered by generate_sed_commands)
        sed_commands = generate_sed_commands(filepath, stats)
        if sed_commands:
            print("=" * 60)
            print("MANUAL FIX OPTIONS (sed commands)")
            print("=" * 60)
            print()
            print("bash")
            for cmd in sed_commands:
                if cmd.startswith("#"):
                    print(f"  {cmd}")
                else:
                    print(f"  {cmd}")
            print("bash")
            print()
        
        print("=" * 60)
        print("AUTO-FIX OPTIONS")
        print("=" * 60)
        print()
        print("⚠ WARNING: Auto-fix loads ENTIRE file into memory.")
        print(f"   File size: {filepath.stat().st_size / (1024*1024):.2f} MB")
        print("   Not recommended for very large files (>1GB)")
        print()
        print("Options:")
        print("  1) AUTO-FIX: Let this script fix all issues now")
        print("  2) MANUAL: Run the sed commands shown above")
        print()
        
        if prompt_yes_no("Do you want to auto-fix all issues?\nPress 'N' if you prefer to run the sed commands above?"):
            print("\nFixing file...")
            print(f"  Reading {filepath} ({len(raw)} bytes)...")
            
            cleanup_stats = {
                "boms_removed": 0,
                "bom_types": {},
                "null_bytes_removed": 0,
                "carriage_returns_removed": 0,  # ADDED THIS KEY
                "invalid_utf8_removed": 0,
            }
            
            cleaned_data = clean_file_in_memory(raw, cleanup_stats)
            
            print(f"  Writing cleaned data...")
            with open(filepath, "wb") as f:
                f.write(cleaned_data)
                f.flush()
            
            total_fixed = (
                cleanup_stats["boms_removed"] + 
                cleanup_stats["null_bytes_removed"] + 
                cleanup_stats["carriage_returns_removed"] +  # ADDED
                cleanup_stats["invalid_utf8_removed"]
            )
            
            print(f"\n{'=' * 60}")
            print("CLEANING RESULTS")
            print("=" * 60)
            print(f"✓ File cleaned successfully!")
            print(f"  Total bytes fixed: {total_fixed}")
            
            if cleanup_stats["boms_removed"] > 0:
                print(f"  ✓ BOM markers removed: {cleanup_stats['boms_removed']}")
                for btype, count in sorted(cleanup_stats["bom_types"].items()):
                    print(f"    • {btype}: {count}")
            else:
                print(f"  - BOM markers: None found")
            
            if cleanup_stats["null_bytes_removed"] > 0:
                print(f"  ✓ Null bytes (0x00) removed: {cleanup_stats['null_bytes_removed']}")
            else:
                print(f"  - Null bytes (0x00): None found")
            
            if cleanup_stats["carriage_returns_removed"] > 0:
                print(f"  ✓ Carriage returns (\\r) removed: {cleanup_stats['carriage_returns_removed']}")
            else:
                print(f"  - Carriage returns (\\r): None found")
            
            if cleanup_stats["invalid_utf8_removed"] > 0:
                print(f"  ✓ Invalid UTF-8 (0x80-0xFF) removed: {cleanup_stats['invalid_utf8_removed']}")
            else:
                print(f"  - Invalid UTF-8 (0x80-0xFF): None found")
            
            print(f"  Original size: {len(raw)} bytes → Final size: {len(cleaned_data)} bytes")
            
            # Verify without re-prompting
            verify_after_fix(filepath)
            return
        
        else:
            print("\nUsing manual sed commands...\n")
    else:
        print("=" * 60)
        print("No issues found - file is clean!")
        print("=" * 60)
        return

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compact hex viewer with colored highlighting for BOMs and problematic bytes."
    )
    parser.add_argument(
        "file",
        type=Path,
        help="Input file to inspect"
    )
    parser.add_argument(
        "-n", "--lines",
        type=int,
        default=1,
        metavar="N",
        help="Number of lines to inspect (default: 1)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show additional diagnostic information"
    )
    
    args = parser.parse_args()
    
    try:
        process_file(args.file, args.lines, args.verbose)
    except KeyboardInterrupt:
        print("\nOperation cancelled.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()