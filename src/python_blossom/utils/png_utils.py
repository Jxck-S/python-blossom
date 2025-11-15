"""Utility functions for generating minimal PNG files without external dependencies."""

import random
import struct
import zlib


# Larger 8x12 bitmap font for bigger text rendering
FONT_8X12 = {
    'b': [
        0b11000000,
        0b10100000,
        0b10100000,
        0b11000000,
        0b10100000,
        0b10100000,
        0b11000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
    ],
    'l': [
        0b11000000,
        0b10000000,
        0b10000000,
        0b10000000,
        0b10000000,
        0b10000000,
        0b11100000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
    ],
    'o': [
        0b01110000,
        0b10001000,
        0b10001000,
        0b10001000,
        0b10001000,
        0b10001000,
        0b01110000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
    ],
    's': [
        0b01110000,
        0b10000000,
        0b10000000,
        0b01110000,
        0b00001000,
        0b00001000,
        0b11110000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
    ],
    'm': [
        0b10101000,
        0b11011000,
        0b10101000,
        0b10101000,
        0b10101000,
        0b10101000,
        0b10101000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
    ],
    '_': [
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b11111100,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
    ],
    'p': [
        0b11100000,
        0b10010000,
        0b10010000,
        0b11100000,
        0b10000000,
        0b10000000,
        0b10000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
    ],
    'y': [
        0b10001000,
        0b10001000,
        0b10001000,
        0b01110000,
        0b00001000,
        0b00001000,
        0b11110000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
    ],
    't': [
        0b11100000,
        0b01000000,
        0b01000000,
        0b01000000,
        0b01000000,
        0b01000000,
        0b00110000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
    ],
    'h': [
        0b10010000,
        0b10010000,
        0b10010000,
        0b11100000,
        0b10010000,
        0b10010000,
        0b10010000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
    ],
    'n': [
        0b00000000,
        0b11100000,
        0b10010000,
        0b10010000,
        0b10010000,
        0b10010000,
        0b10010000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
        0b00000000,
    ],
}


def draw_lines_pattern(pixel_data: bytearray, width: int, height: int, iteration: int) -> None:
    """Draw geometric line patterns on pixel data for visual integrity verification.
    
    Creates diagonal and horizontal lines based on iteration to create
    recognizable patterns rather than random noise.
    
    :param pixel_data: Bytearray of pixel data (modified in-place).
    :param width: Image width.
    :param height: Image height.
    :param iteration: Used to vary the pattern.
    """
    bytes_per_pixel = 3
    bytes_per_row = 1 + width * bytes_per_pixel  # filter byte + RGB pixels
    
    # Draw diagonal lines with color modulation
    line_spacing = 20 + iteration * 5
    for offset in range(-height, width, line_spacing):
        for i in range(max(0, height)):
            x = offset + i
            y = i
            if 0 <= x < width and 0 <= y < height:
                row_offset = y * bytes_per_row
                pixel_idx = row_offset + 1 + x * bytes_per_pixel
                if pixel_idx + 2 < len(pixel_data):
                    pixel_data[pixel_idx] = min(255, pixel_data[pixel_idx] + 40)
                    pixel_data[pixel_idx + 1] = max(0, pixel_data[pixel_idx + 1] - 20)
                    pixel_data[pixel_idx + 2] = min(255, pixel_data[pixel_idx + 2] + 30)
    
    # Draw horizontal stripes
    stripe_height = 30 + iteration * 3
    for y in range(0, height, stripe_height):
        row_offset = y * bytes_per_row
        for x in range(width):
            pixel_idx = row_offset + 1 + x * bytes_per_pixel
            if pixel_idx + 2 < len(pixel_data):
                r_val = max(0, pixel_data[pixel_idx] - 20)
                g_val = min(255, pixel_data[pixel_idx + 1] + 30)
                b_val = max(0, pixel_data[pixel_idx + 2] - 20)
                pixel_data[pixel_idx] = r_val
                pixel_data[pixel_idx + 1] = g_val
                pixel_data[pixel_idx + 2] = b_val


def draw_text_on_image(pixel_data: bytearray, width: int, height: int, text: str, 
                       x: int, y: int, color: tuple) -> None:
    """Draw text on image pixel data using larger bitmap font.
    
    :param pixel_data: Bytearray of pixel data (modified in-place).
    :param width: Image width.
    :param height: Image height.
    :param text: Text to draw (lowercase letters and underscore supported).
    :param x: Starting x coordinate.
    :param y: Starting y coordinate.
    :param color: (R, G, B) tuple for text color.
    """
    char_width = 10
    bytes_per_pixel = 3
    bytes_per_row = 1 + width * bytes_per_pixel  # filter byte + RGB pixels
    
    for char_idx, char in enumerate(text.lower()):
        if char not in FONT_8X12:
            continue
        char_x = x + char_idx * char_width
        bitmap = FONT_8X12[char]
        for row in range(12):
            if y + row >= height:
                continue
            for col in range(8):
                px = char_x + col
                if px >= width:
                    continue
                if bitmap[row] & (1 << (7 - col)):
                    # Calculate correct byte offset: (row_index * bytes_per_row) + (x_offset * 3)
                    py = y + row
                    row_offset = py * bytes_per_row
                    pixel_offset = row_offset + 1 + px * bytes_per_pixel
                    if pixel_offset + 2 < len(pixel_data):
                        pixel_data[pixel_offset] = color[0]
                        pixel_data[pixel_offset + 1] = color[1]
                        pixel_data[pixel_offset + 2] = color[2]


def create_minimal_png(width: int, height: int, iteration: int) -> bytes:
    """Create a PNG file with geometric patterns and text overlay.
    
    Creates a PNG with a base color that shifts per iteration, geometric
    line patterns for visual verification, and text drawn on top.
    
    :param width: Image width in pixels.
    :param height: Image height in pixels.
    :param iteration: Iteration number to vary the base color and patterns.
    :return: PNG file bytes.
    """
    # Base color shifts with each iteration: RGB
    r_base = min(255, 100 + iteration * 20)
    g_base = min(255, 50 + iteration * 10)
    b_base = max(0, 150 - iteration * 20)
    
    # PNG signature
    png_sig = b'\x89PNG\r\n\x1a\n'
    
    # IHDR chunk (image header)
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)  # 8-bit RGB
    ihdr_chunk = _make_chunk('IHDR', ihdr_data)
    
    # IDAT chunk (image data) - create solid color base with patterns
    pixel_list = []
    for _ in range(height):
        row = bytearray(b'\x00')  # filter type: none
        for _ in range(width):
            row.extend(bytes([r_base, g_base, b_base]))
        pixel_list.append(bytes(row))
    
    # Flatten to single bytearray for pattern and text drawing
    pixel_data = bytearray(b''.join(pixel_list))
    
    # Draw geometric line patterns for visual integrity
    draw_lines_pattern(pixel_data, width, height, iteration)
    
    # Draw text on image (white text)
    draw_text_on_image(pixel_data, width, height, "blossom_python", 
                      x=20, y=20, color=(255, 255, 255))
    
    compressed = zlib.compress(bytes(pixel_data), 9)
    idat_chunk = _make_chunk('IDAT', compressed)
    
    # IEND chunk (end marker)
    iend_chunk = _make_chunk('IEND', b'')
    
    return png_sig + ihdr_chunk + idat_chunk + iend_chunk


def _make_chunk(chunk_type: str, data: bytes) -> bytes:
    """Create a PNG chunk with CRC.
    
    :param chunk_type: 4-character chunk type (e.g., 'IHDR', 'IDAT', 'IEND').
    :param data: Chunk data bytes.
    :return: Complete PNG chunk with length and CRC.
    """
    chunk_type_bytes = chunk_type.encode('ascii')
    length = struct.pack('>I', len(data))
    crc_data = chunk_type_bytes + data
    crc = zlib.crc32(crc_data) & 0xffffffff
    crc_bytes = struct.pack('>I', crc)
    return length + crc_data + crc_bytes
