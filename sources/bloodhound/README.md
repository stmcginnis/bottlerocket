# bloodhound

Current version: 0.1.0

## Introduction

Bloodhound is a command line orchestrator for running a set of compliance
checks. This can be used to run CIS benchmark compliance, though can be extended
to perform any kind of check that adheres to the expected checker interface.

Checks are performed and their results are provided in an overall report.
The checker report can be written to a file, or viewed from stdout.
By default the report is provided in a human readable text format, but can also
be generated as JSON to make it easy to consume programmatically for integrating
into further compliance automation.

## Usage

Bloodhound is ultimately intended to be used throught he Bottlerocket `apiclient`
interface. It can be executed from sheltie with the following options:

```txt
Command line arguments for the bloodhound program

Usage: bloodhound [OPTIONS]

Options:
  -c, --checks <CHECK_DIR>  Path to the directory containing checker binaries [default: /usr/libexec/cis-checks/bottlerocket]
  -f, --format <FORMAT>     Format of the output [default: text] [possible values: text, json]
  -l, --level <LEVEL>       The CIS benchmark compliance level to check [default: 1]
  -o, --output <OUTPUT>     Write output to a file at given path [default: stdout]
  -h, --help                Print help
```

## Colophon

This text was generated from `README.tpl` using [cargo-readme](https://crates.io/crates/cargo-readme), and includes the rustdoc from `src/main.rs`.
