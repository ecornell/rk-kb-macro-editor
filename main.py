import argparse
import struct
import sys
from dataclasses import dataclass
from typing import List

# File format constants
MAGIC_BYTES = bytes([0xa0, 0x88, 0xfb, 0xfa])
HEADER_SIZE = 0x14  # 20 bytes before name
NAME_SIZE = 84  # UTF-16LE padded name field
NAME_OFFSET = 0x14
EVENTS_OFFSET = 0x68
EVENT_SIZE = 8
TOTAL_FILE_SIZE = 834

# Virtual key codes (Windows)
VK_CODES = {
    'A': 0x41, 'B': 0x42, 'C': 0x43, 'D': 0x44, 'E': 0x45, 'F': 0x46,
    'G': 0x47, 'H': 0x48, 'I': 0x49, 'J': 0x4A, 'K': 0x4B, 'L': 0x4C,
    'M': 0x4D, 'N': 0x4E, 'O': 0x4F, 'P': 0x50, 'Q': 0x51, 'R': 0x52,
    'S': 0x53, 'T': 0x54, 'U': 0x55, 'V': 0x56, 'W': 0x57, 'X': 0x58,
    'Y': 0x59, 'Z': 0x5A,
    '0': 0x30, '1': 0x31, '2': 0x32, '3': 0x33, '4': 0x34,
    '5': 0x35, '6': 0x36, '7': 0x37, '8': 0x38, '9': 0x39,
    'SPACE': 0x20, 'ENTER': 0x0D, 'TAB': 0x09, 'BACKSPACE': 0x08,
    'LSHIFT': 0xA0, 'RSHIFT': 0xA1, 'LCTRL': 0xA2, 'RCTRL': 0xA3,
    'LALT': 0xA4, 'RALT': 0xA5,
}

# Reverse lookup
VK_NAMES = {v: k for k, v in VK_CODES.items()}

# Characters that require shift
SHIFT_CHARS = {
    '!': '1', '@': '2', '#': '3', '$': '4', '%': '5',
    '^': '6', '&': '7', '*': '8', '(': '9', ')': '0',
    '_': '-', '+': '=', '{': '[', '}': ']', '|': '\\',
    ':': ';', '"': "'", '<': ',', '>': '.', '?': '/',
    '~': '`',
}


@dataclass
class KeyEvent:
    """Represents a single key event (press or release)."""
    vk_code: int
    is_down: bool
    timing: int = 4  # Default timing value

    def to_bytes(self) -> bytes:
        """Convert to 8-byte binary format."""
        state = 1 if self.is_down else 0
        return struct.pack('<HHI', self.vk_code, state, self.timing)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'KeyEvent':
        """Parse from 8-byte binary format."""
        vk_code, state, timing = struct.unpack('<HHI', data)
        return cls(vk_code=vk_code, is_down=(state == 1), timing=timing)

    def __repr__(self) -> str:
        name = VK_NAMES.get(self.vk_code, f'0x{self.vk_code:02X}')
        action = 'DOWN' if self.is_down else 'UP'
        return f'KeyEvent({name}, {action}, timing={self.timing})'


@dataclass
class RkmMacro:
    """Represents a parsed .rkm macro file."""
    name: str
    events: List[KeyEvent]
    header_data: bytes  # Preserve original header bytes

    @classmethod
    def from_file(cls, filepath: str) -> 'RkmMacro':
        """Parse an .rkm file."""
        with open(filepath, 'rb') as f:
            data = f.read()

        # Validate magic bytes
        if data[:4] != MAGIC_BYTES:
            raise ValueError(f'Invalid magic bytes: {data[:4].hex()}')

        # Extract header (preserved for writing)
        header_data = data[:HEADER_SIZE]

        # Extract name (UTF-16LE, null-terminated within 84 bytes)
        name_bytes = data[NAME_OFFSET:NAME_OFFSET + NAME_SIZE]
        name = name_bytes.decode('utf-16-le').rstrip('\x00')

        # Parse events
        events = []
        event_start = EVENTS_OFFSET + 2  # Skip the 01 00 marker
        pos = event_start

        while pos + EVENT_SIZE <= len(data):
            event_data = data[pos:pos + EVENT_SIZE]
            # Stop if we hit all zeros (padding)
            if event_data == b'\x00' * EVENT_SIZE:
                break
            events.append(KeyEvent.from_bytes(event_data))
            pos += EVENT_SIZE

        return cls(name=name, events=events, header_data=header_data)

    def to_bytes(self) -> bytes:
        """Convert macro to binary format."""
        # Start with header
        result = bytearray(self.header_data)

        # Add name (UTF-16LE, padded to 84 bytes)
        name_bytes = self.name.encode('utf-16-le')
        name_padded = name_bytes[:NAME_SIZE].ljust(NAME_SIZE, b'\x00')
        result.extend(name_padded)

        # Add event marker (01 00)
        result.extend(b'\x01\x00')

        # Add events
        for event in self.events:
            result.extend(event.to_bytes())

        # Pad to total file size
        result.extend(b'\x00' * (TOTAL_FILE_SIZE - len(result)))

        return bytes(result)

    def save(self, filepath: str) -> None:
        """Save macro to file."""
        with open(filepath, 'wb') as f:
            f.write(self.to_bytes())

    def get_text(self) -> str:
        """Attempt to reconstruct the typed text from key events."""
        text = []
        shift_held = False

        for event in self.events:
            if event.vk_code in (0xA0, 0xA1):  # Shift keys
                shift_held = event.is_down
            elif event.is_down:
                char = VK_NAMES.get(event.vk_code, '')
                if len(char) == 1:
                    if shift_held:
                        # Find shifted character
                        for shifted, base in SHIFT_CHARS.items():
                            if base.upper() == char:
                                text.append(shifted)
                                break
                        else:
                            text.append(char.upper())
                    else:
                        text.append(char.lower())
                elif char == 'SPACE':
                    text.append(' ')
                elif char == 'ENTER':
                    text.append('\n')

        return ''.join(text)

    def print_events(self) -> None:
        """Print all events in a readable format."""
        print(f'Macro: {self.name}')
        print(f'Text: {self.get_text()}')
        print(f'Events ({len(self.events)}):')
        for i, event in enumerate(self.events):
            print(f'  {i:3d}: {event}')


def text_to_events(text: str, timing: int = 4) -> List[KeyEvent]:
    """Convert a text string to key events."""
    events = []

    for char in text:
        needs_shift = False
        vk_code = None

        if char.upper() in VK_CODES:
            vk_code = VK_CODES[char.upper()]
            needs_shift = char.isupper() or char in SHIFT_CHARS
        elif char in SHIFT_CHARS:
            base_char = SHIFT_CHARS[char]
            vk_code = VK_CODES.get(base_char.upper())
            needs_shift = True
        elif char == ' ':
            vk_code = VK_CODES['SPACE']
        elif char == '\n':
            vk_code = VK_CODES['ENTER']

        if vk_code is not None:
            if needs_shift:
                events.append(KeyEvent(VK_CODES['RSHIFT'], True, timing))

            events.append(KeyEvent(vk_code, True, timing))
            events.append(KeyEvent(vk_code, False, timing))

            if needs_shift:
                events.append(KeyEvent(VK_CODES['RSHIFT'], False, timing))

    return events


def create_macro(name: str, text: str) -> RkmMacro:
    """Create a new macro from text."""
    # Default header data (from analyzed file)
    header_data = bytes([
        0xa0, 0x88, 0xfb, 0xfa, 0x0d, 0x0f, 0x41, 0x00,
        0x00, 0x00, 0x00, 0xc0, 0x02, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    ])

    events = text_to_events(text)
    return RkmMacro(name=name, events=events, header_data=header_data)


def cmd_read(args):
    """Read and display a macro file."""
    try:
        macro = RkmMacro.from_file(args.file)
        if args.verbose:
            macro.print_events()
        else:
            print(f'Name: {macro.name}')
            print(f'Text: {macro.get_text()}')
            print(f'Events: {len(macro.events)}')
    except FileNotFoundError:
        print(f'Error: File not found: {args.file}', file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)


def cmd_create(args):
    """Create a new macro file."""
    macro = create_macro(args.name, args.text)
    macro.save(args.output)
    print(f'Created macro "{args.name}" with text "{args.text}"')
    print(f'Saved to: {args.output}')


def cmd_update(args):
    """Update an existing macro file."""
    try:
        macro = RkmMacro.from_file(args.file)
        old_text = macro.get_text()

        if args.name:
            macro.name = args.name
        if args.text:
            macro.events = text_to_events(args.text, args.timing)

        output = args.output if args.output else args.file
        macro.save(output)

        print(f'Updated macro:')
        if args.name:
            print(f'  Name: {macro.name}')
        if args.text:
            print(f'  Text: "{old_text}" -> "{args.text}"')
        print(f'Saved to: {output}')
    except FileNotFoundError:
        print(f'Error: File not found: {args.file}', file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)


def cmd_hexdump(args):
    """Show hex dump of a macro file."""
    try:
        with open(args.file, 'rb') as f:
            data = f.read()

        print(f'File: {args.file} ({len(data)} bytes)')
        print()
        for i in range(0, len(data), 16):
            hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
            print(f'{i:04x}: {hex_part:<48} {ascii_part}')
    except FileNotFoundError:
        print(f'Error: File not found: {args.file}', file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog='rkm-editor',
        description='Parse and edit .rkm keyboard macro files'
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # read command
    read_parser = subparsers.add_parser('read', help='Read and display a macro file')
    read_parser.add_argument('file', help='Path to .rkm file')
    read_parser.add_argument('-v', '--verbose', action='store_true',
                             help='Show detailed event list')
    read_parser.set_defaults(func=cmd_read)

    # create command
    create_parser = subparsers.add_parser('create', help='Create a new macro file')
    create_parser.add_argument('-n', '--name', required=True, help='Macro name')
    create_parser.add_argument('-t', '--text', required=True, help='Text to type')
    create_parser.add_argument('-o', '--output', required=True, help='Output file path')
    create_parser.set_defaults(func=cmd_create)

    # update command
    update_parser = subparsers.add_parser('update', help='Update an existing macro file')
    update_parser.add_argument('file', help='Path to .rkm file')
    update_parser.add_argument('-n', '--name', help='New macro name')
    update_parser.add_argument('-t', '--text', help='New text to type')
    update_parser.add_argument('-o', '--output', help='Output file (default: overwrite input)')
    update_parser.add_argument('--timing', type=int, default=4,
                               help='Key timing value (default: 4)')
    update_parser.set_defaults(func=cmd_update)

    # hexdump command
    hex_parser = subparsers.add_parser('hexdump', help='Show hex dump of a macro file')
    hex_parser.add_argument('file', help='Path to .rkm file')
    hex_parser.set_defaults(func=cmd_hexdump)

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
