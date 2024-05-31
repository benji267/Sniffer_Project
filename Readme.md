# Network Analyzer in C

A network analyzer implemented in C by Benjamin Metzger.

## Overview

This project is a network analyzer built in C, allowing users to analyze network packets. The source code is organized into the following directories:

- `src`: Contains the .c files.
- `include`: Includes the .h files.
- `obj`: Stores the .o files after compilation.

## Compilation and Execution

To compile the project, run the following command:

```bash
make
```
To clean the project, run the following command:

```bash
make clean
```

To launch the project, run the following command:

```bash
./sniffer
```
Options

-v value:  Sets the verbosity level of the analysis. If not specified, the default value is 1 (very concise). Different verbosity levels provide varying amounts of information, similar to Wireshark:

    - 1: Very concise
    - 2: Concise
    - 3: Detailed

-o filename: Specifies the output file for the analysis results.

-i interface: Specifies the input interface for packet capture.

If no options are specified, the program will run with the default verbosity level of 1, and will analyse the fake frame define in sniffer.h.

Example Usage:

```bash
./sniffer -v 2 -o dns.pcap
```


## Makefile

For detailed information on the build and compilation process, refer to the [Makefile](Makefile).
