# Timer-Based TCP Congestion Control for Linux Kernel

## Introduction
This repository hosts the kernel source code developed as part of a collaborative master thesis project. The thesis presents a novel approach to TCP congestion control in the Linux kernel, introducing a timer-based mechanism distinct from traditional methods.

## Overview
The congestion control module developed in this project is fundamentally different from conventional TCP congestion control strategies. Rather than relying exclusively on ACK-clocking or a congestion window, this implementation is based on time. Packet transmissions are dictated by timer expirations during both the Slow Start and Congestion Avoidance phases. Our approach effectively interpolates the transmission behavior of traditional TCP congestion control while ensuring a smooth distribution of packets over time, resulting in more consistent traffic patterns.

## Conceptual Basis
The conceptual foundation for the congestion control logic is derived from an unpublished paper, which was not publicly available at the time of this writing.

## Key Modifications
The primary changes in the implementation are located in the following files within the Linux kernel source:
- `net/ipv4/tcp_tb.c`: Core file for the timer-based TCP congestion control.
- `net/ipv4/tcp_output.c`: Modifications related to packet output mechanisms.
- `net/ipv4/tcp_input.c`: Adjustments in the packet input processing.
.

## Acknowledgments
This project is based on research and ideas presented in an unpublished paper and has been developed as part of a master thesis in computer networking.
