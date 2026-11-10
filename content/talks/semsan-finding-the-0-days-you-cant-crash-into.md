+++
title = "SEMSAN: Finding the 0-Days You Can't Crash Into"
date = 2026-11-06T09:45:00+01:00
draft = false
+++

Traditional fuzzers and sanitizers catch memory corruption bugs, but miss vulnerabilities that never cause a crash. This talk introduces SEMSAN, an eBPF-based sanitizer that turns violations of custom runtime invariants into crashes a fuzzer can detect, and walks through five 0-days it uncovered, from argument injections and path traversals to privilege escalation and remote code execution.

Presented at [Black Alps 2026](https://blackalps.ch/ba-26/talk/semsan-finding-the-0-days-you-can-t-crash-into).
