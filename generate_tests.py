#!/usr/bin/env python3
"""Generate test .rkm files for all supported VK codes."""

import os
from main import (
    VK_CODES, KeyEvent, RkmMacro, MAX_EVENTS,
    MAGIC_BYTES, HEADER_SIZE
)

# Default header data
DEFAULT_HEADER = bytes([
    0xa0, 0x88, 0xfb, 0xfa, 0x0d, 0x0f, 0x41, 0x00,
    0x00, 0x00, 0x00, 0xc0, 0x02, 0x04, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
])

TEST_DIR = os.path.join(os.path.dirname(__file__), 'test_macros')


def create_key_test_events(vk_codes_dict: dict, timing: int = 4) -> list[KeyEvent]:
    """Create press/release events for each VK code in the dict."""
    events = []
    for name, code in vk_codes_dict.items():
        events.append(KeyEvent(code, True, timing))   # Key down
        events.append(KeyEvent(code, False, timing))  # Key up
    return events


def save_test_macro(name: str, events: list[KeyEvent], filename: str) -> None:
    """Save a test macro to file."""
    macro = RkmMacro(name=name, events=events, header_data=DEFAULT_HEADER)
    filepath = os.path.join(TEST_DIR, filename)
    macro.save(filepath)
    print(f'Created: {filename} ({len(events)} events)')


def main():
    # Create test directory
    os.makedirs(TEST_DIR, exist_ok=True)

    # Group VK codes by category
    categories = {
        'letters': {k: v for k, v in VK_CODES.items() if len(k) == 1 and k.isalpha()},
        'numbers': {k: v for k, v in VK_CODES.items() if len(k) == 1 and k.isdigit()},
        'function': {k: v for k, v in VK_CODES.items() if k.startswith('F') and k[1:].isdigit()},
        'arrows': {k: v for k, v in VK_CODES.items() if k in ('LEFT', 'UP', 'RIGHT', 'DOWN')},
        'navigation': {k: v for k, v in VK_CODES.items() if k in ('HOME', 'END', 'PAGEUP', 'PAGEDOWN', 'INSERT', 'DELETE')},
        'common': {k: v for k, v in VK_CODES.items() if k in ('SPACE', 'ENTER', 'TAB', 'BACKSPACE', 'ESCAPE', 'ESC', 'CAPSLOCK', 'NUMLOCK', 'SCROLLLOCK', 'PRINTSCREEN', 'PAUSE')},
        'modifiers': {k: v for k, v in VK_CODES.items() if any(m in k for m in ('SHIFT', 'CTRL', 'ALT', 'WIN'))},
        'punctuation': {k: v for k, v in VK_CODES.items() if k in ('SEMICOLON', 'EQUALS', 'COMMA', 'MINUS', 'PERIOD', 'SLASH', 'BACKTICK', 'LBRACKET', 'BACKSLASH', 'RBRACKET', 'QUOTE')},
        'numpad': {k: v for k, v in VK_CODES.items() if k.startswith('NUMPAD') or k in ('MULTIPLY', 'ADD', 'SEPARATOR', 'SUBTRACT', 'DECIMAL', 'DIVIDE')},
    }

    print(f'Generating test macros in {TEST_DIR}/')
    print(f'Max events per macro: {MAX_EVENTS}')
    print()

    # Generate a test file for each category
    for category, codes in categories.items():
        if not codes:
            continue

        # Remove duplicates (like ESC/ESCAPE which map to same code)
        unique_codes = {}
        seen_values = set()
        for name, code in codes.items():
            if code not in seen_values:
                unique_codes[name] = code
                seen_values.add(code)

        events = create_key_test_events(unique_codes)

        # Check if within limits
        if len(events) > MAX_EVENTS:
            print(f'WARNING: {category} has {len(events)} events, exceeds {MAX_EVENTS}')
            events = events[:MAX_EVENTS]

        save_test_macro(
            name=f'Test {category.title()}',
            events=events,
            filename=f'test_{category}.rkm'
        )

    # Create an "all keys" macro split into parts if needed
    all_codes = {}
    seen_values = set()
    for name, code in VK_CODES.items():
        if code not in seen_values:
            all_codes[name] = code
            seen_values.add(code)

    all_events = create_key_test_events(all_codes)

    # Split into multiple files if needed
    events_per_file = MAX_EVENTS - (MAX_EVENTS % 2)  # Ensure even number
    num_files = (len(all_events) + events_per_file - 1) // events_per_file

    print()
    print(f'Total unique VK codes: {len(all_codes)}')
    print(f'Total events needed: {len(all_events)}')
    print(f'Splitting into {num_files} file(s)')
    print()

    for i in range(num_files):
        start = i * events_per_file
        end = min(start + events_per_file, len(all_events))
        chunk = all_events[start:end]

        save_test_macro(
            name=f'All Keys Part {i+1}',
            events=chunk,
            filename=f'test_all_keys_part{i+1}.rkm'
        )

    print()
    print('Done!')


if __name__ == '__main__':
    main()
