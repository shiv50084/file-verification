#!/usr/bin/env python3
# coding=utf-8

"""
Generate a file with random binary content
"""


import random
import argparse


def file_generate(name: str, size: int):
    random.seed(size)
    
    with open(name, "wb") as f:
        for i in range(size):
            f.write(random.randint(ord('A'), ord('z')).to_bytes(1, byteorder="little"))


def main():
    parser = argparse.ArgumentParser(description="Generate binary file")
    parser.add_argument('filename', type=str, default="testfile", nargs="?")
    parser.add_argument('size', type=int, default=1024,  nargs="?")

    args = parser.parse_args()
    file_generate(args.filename, args.size)


if __name__ == "__main__":
    main()
