#!/usr/bin/env python3
"""
Utility functions for text formatting, hashing, and logging.
Includes color formatting utilities using colorama and hash generation functions.
"""

# Standard library imports
import sys
import os
import time
import hashlib
import warnings
from datetime import datetime
from io import BytesIO
from typing import Any, Dict, Type, TypeVar, TextIO, Callable, Awaitable, Iterable, List, Union, Optional

# Third-party imports
from colorama import init
from colorama.ansi import AnsiCodes, Style, Fore

# Type definitions
T = TypeVar('T')  # Generic type variable for Singleton instances

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Suppress DeprecationWarnings globally
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Pre-defined colored symbols for status indicators
RED_STOP = f"{Fore.RED}⛔{Style.RESET_ALL}"
GREEN_TICK = f"{Fore.GREEN}✅{Style.RESET_ALL}"


def color_text(text: str, color: AnsiCodes) -> str:
    """
    Apply ANSI color formatting to text.

    Args:
        text: The text to be colored
        color: The colorama ANSI color code to apply

    Returns:
        The text wrapped with color formatting codes
    """
    return f"{color}{text}{Style.RESET_ALL}"


def cyan(text: str) -> str:
    """Format text in cyan color."""
    return color_text(text, Fore.CYAN)


def white(text: str) -> str:
    """Format text in white color."""
    return color_text(text, Fore.WHITE)


def yellow(text: str) -> str:
    """Format text in yellow color."""
    return color_text(text, Fore.YELLOW)


def green(text: str) -> str:
    """Format text in green color."""
    return color_text(text, Fore.GREEN)


def red(text: str) -> str:
    """Format text in red color."""
    return color_text(text, Fore.RED)


def plog(
    *objects: Any,
    sep: str = ' ',
    end: str = '\n',
    file: TextIO = sys.stderr,
    flush: bool = True
) -> str:
    """
    Enhanced logging function that behaves similarly to built-in print.

    Formats and writes log messages to a specified output stream with customizable
    formatting options. Automatically strips leading whitespace from output.

    Args:
        *objects: Variable length argument list of objects to print
        sep: String separator between objects (default: single space)
        end: String to append after the last value (default: newline)
        file: Output stream to write to (default: sys.stderr)
        flush: Whether to force flush the stream after writing (default: True)

    Returns:
        The formatted output string that was written to the stream
    """
    import re

    # Join objects with separator and add ending
    output = sep.join(map(str, objects)) + end

    # Strip leading whitespace
    output = re.sub(r"^[ \s]+", "", output)

    # Write and optionally flush
    file.write(output)
    if flush:
        file.flush()

    return output


def sha256(data: str, digest: bool = True) -> Union[str, Any]:
    """
    Generate SHA256 hash of input string.

    Args:
        data: Input string to hash
        digest: If True returns hexadecimal digest, if False returns hash object

    Returns:
        Hexadecimal digest string or hash object depending on digest parameter
    """
    hash_obj = hashlib.sha256(data.encode())
    return hash_obj.hexdigest() if digest else hash_obj


def get_hash(data: Optional[str] = None, length: int = 6) -> str:
    """
    Generate a shortened hash value, optionally based on input data.

    If no data is provided, generates hash from system information and random noise.

    Args:
        data: Optional input string to hash
        length: Length of returned hash digest (default: 6 characters)

    Returns:
        First 'length' characters of SHA256 hash
    """
    def generate_noise() -> int:
        """Generate random noise value based on current timestamp."""
        import random
        seconds, microseconds = f"{time.time()}".split('.')
        timestamp_product = int(seconds) * int(microseconds)
        return random.randint(int(microseconds), timestamp_product)

    if not data:
        # Combine system info, timestamp and random noise if no data provided
        data = f"{os.getgid()}{os.environ}{time.time()}{generate_noise()}"

    return hashlib.sha256(data.encode()).hexdigest()[:length]


__all__ = [
    "sha256", "sha512", "get_hash",
    "plog",
    "red", "green", "yellow", "white", "cyan",
    "RED_STOP", "GREEN_TICK"
]
