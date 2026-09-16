#!/usr/bin/env python3
from dependency_recovery import load_recovery_config, selftest

if __name__ == "__main__":
    selftest(load_recovery_config())
