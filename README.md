# hexclean.py

***hexclean.py*** is a lightweight Python based hex viewer and text file cleaner that detects and fixes encoding issues such as: **

- Byte Order Marker bytes (BOM bytes)
  
- Null bytes [`00`] inserted by Windows between characters (not shown by most text editors!)
  
- Carriage returns (replace windows /r/n with /n)
  
- remove invalid UTF-8 bytes, such as
  

## Why hexclean?

Windows frequently corrupts text files with BOM markers, null bytes (0x00), and improper line endings (\r\n). These artifacts cause false negatives and pipeline failures especially with tools like hashcat.

Hexclean detects and removes these encoding issues, showing problematic bytes in a color-coded hex view before fixing them.

## Features

- 🔍 **Visual inspection** – Hex dump with color-coded highlighting for problematic bytes
  
- 🧹 **Auto-fix mode** – Clean files in-place with a single confirmation
  
- 📊 **Problem summary** – Detailed statistics on what issues were found
  
- 💻 **Manual commands** – Will suggest SED commands for large files to fix detected issues.
  

  ### Detected & Fixed Issues
  
  | Issue | Description | Fix Method |
  |-------|-------------|------------|
  | **BOM markers** | UTF-8/UTF-16/UTF-32 byte order marks | Auto-remove or sed |
  | **Null bytes** | `\x00` inserted by Windows pipes | Auto-remove or sed |
  | **Carriage returns** | `\r` in Unix text files | Auto-remove or sed |
  | **Invalid UTF-8** | High bytes 0x80-0xFF | Auto-remove or Python |
  
No dependencies beyond Python 3.6+.

## Usage

### Inspect file (first 5 lines by default)

`./hexclean.py test.txt -n 5`

`Legend: [███] BOM marker bytes 00 Null bytes (0x00) <XX> Invalid UTF-8 / high bytes (0x80-0xFF) <CR> Carriage return (0x0D) 1 0000 [EF][BB][BF] 48 65 6C 6C 6F 20 57 6F 72 6C 64 21 |Hello World!|`

### Auto-fix mode

`./hexclean.py test.txt -c`

### Verbose mode

`./hexclean.py test.txt -v -n 5`

### Command Reference

| Flag | Description |
| --- | --- |
| `-n N` | Number of lines to inspect (default: 1) |
| `-v` | Show verbose diagnostic information |
| `-h` | Display help message |

### SED chained commands to clean your text file of any nasty Windows bytes
**Clean all at ones**
`sed -i -e '1s/^\xEF\xBB\xBF//' \
       -e '1s/^\xFE\xFF//' \
       -e '1s/^\xFF\xFE//' \
       -e '1s/^\x00\x00\xFE\xFF//' \
       -e '1s/^\xFF\xFE\x00\x00//' \
       -e 's/\x00//g'  \
       file.txt`
# Remove all BOM markers from START of file only (single byte replacement)
`sed -i '1s/^\xEF\xBB\xBF//' file.txt`     # UTF-8 BOM
`sed -i '1s/^\xFE\xFF//' file.txt`         # UTF-16 BE BOM
`sed -i '1s/^\xFF\xFE//' file.txt`         # UTF-16 LE BOM
`sed -i '1s/^\x00\x00\xFE\xFF//' file.txt` # UTF-32 BE BOM
`sed -i '1s/^\xFF\xFE\x00\x00//' file.txt` # UTF-32 LE BOM
`sed -i 's/\x00//g' my_file.txt`           # Remove '00' nul bytes

### License
Apache V2 license, see license file for details
