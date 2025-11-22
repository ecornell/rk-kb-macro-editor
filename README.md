# KB Macro Editor

A command-line tool for parsing, creating, and editing `.rkm` keyboard macro files.

## Features

- **Read** macro files and display their contents
- **Create** new macro files from text input
- **Update** existing macro files (name, text, or both)
- **Hexdump** macro files for debugging and analysis

## Requirements

- Python 3.13+
- No external dependencies

## Installation

Clone the repository and use directly:

```bash
git clone <repository-url>
cd kb-macro-editor
```

## Usage

### Read a macro file

Display the contents of an existing macro:

```bash
python main.py read path/to/macro.rkm
```

Show detailed event list with `-v`:

```bash
python main.py read -v path/to/macro.rkm
```

### Create a new macro

Create a macro that types specific text:

```bash
python main.py create -n "My Macro" -t "Hello World!" -o output.rkm
```

Options:
- `-n, --name` - Macro name (required)
- `-t, --text` - Text to type (required)
- `-o, --output` - Output file path (required)

### Update an existing macro

Modify the name or text of an existing macro:

```bash
# Update text only
python main.py update macro.rkm -t "New text"

# Update name only
python main.py update macro.rkm -n "New Name"

# Update both and save to new file
python main.py update macro.rkm -n "New Name" -t "New text" -o new_macro.rkm

# Adjust key timing
python main.py update macro.rkm -t "Fast typing" --timing 2
```

Options:
- `-n, --name` - New macro name
- `-t, --text` - New text to type
- `-o, --output` - Output file (default: overwrite input)
- `--timing` - Key timing value (default: 4)

### Hexdump a macro file

View the raw binary contents:

```bash
python main.py hexdump path/to/macro.rkm
```

## Supported Keys

The tool supports a wide range of keys:

- **Letters**: A-Z
- **Numbers**: 0-9
- **Function keys**: F1-F12
- **Arrow keys**: LEFT, UP, RIGHT, DOWN
- **Navigation**: HOME, END, PAGEUP, PAGEDOWN, INSERT, DELETE
- **Common keys**: SPACE, ENTER, TAB, BACKSPACE, ESCAPE
- **Modifiers**: SHIFT, CTRL, ALT, WIN (left/right variants)
- **Punctuation**: All standard punctuation including shifted characters
- **Numpad**: NUMPAD0-9, MULTIPLY, ADD, SUBTRACT, DECIMAL, DIVIDE

## File Format

`.rkm` files use a binary format with:
- 4-byte magic header (`A0 88 FB FA`)
- 20-byte header section
- 84-byte UTF-16LE macro name
- Key events (8 bytes each: VK code, state, timing)
- Fixed total file size of 834 bytes

## License

MIT
