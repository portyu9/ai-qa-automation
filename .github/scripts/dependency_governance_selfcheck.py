#!/usr/bin/env python3
from dependency_governance import load_config, selftest

if __name__ == "__main__":
    selftest(load_config())
