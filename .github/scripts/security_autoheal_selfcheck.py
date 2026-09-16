#!/usr/bin/env python3
from security_autoheal import load_config, selftest

if __name__ == "__main__":
    selftest(load_config())
