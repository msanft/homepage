+++
title = 'Immutable and Reproducible OS Images with NixOS'
date = 2024-09-25T09:30:00+02:00
draft = false
[params]
    video = 'https://www.youtube.com/watch?v=YAl27ciB6c8'
    slides = 'f'
+++

Many consider NixOS a great tool for declarative definition of their OS, but only few know about its capabilities for Image-based Linux. NixOS offers the tools to combine modern technologies such as discoverable disk images (DDIs), unified kernel images (UKIs), and TPM-based measured boot for transforming declarative configurations into security-focused and immutable OS images for both the server and the desktop.

This talk showcases how we build such reproducible and immutable DDIs with NixOS, and how ukify, systemd-repart, dm-verity and measured boot are involved in that process. We will also briefly cover the support of SecureBoot in NixOS through the Lanzaboote project, and what else is yet to come for image-based NixOS.
