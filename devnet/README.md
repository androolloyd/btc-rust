# btc-rust Devnet

A Kurtosis-based multi-node test network for btc-rust.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Kurtosis CLI](https://docs.kurtosis.com/install/)

## Quick Start

1. Build the Docker image from the project root:

```bash
docker build -f devnet/Dockerfile -t btc-rust:latest .
```

2. Run the devnet with Kurtosis:

```bash
kurtosis run devnet/
```

This spins up a three-node regtest network:

| Participant | Role          | P2P Port | RPC Port |
|-------------|---------------|----------|----------|
| miner       | Block producer| 18444    | 18443    |
| node1       | Full node     | -        | -        |
| node2       | Full node     | -        | -        |

## Inspecting the Network

List running enclaves:

```bash
kurtosis enclave ls
```

View logs for a participant:

```bash
kurtosis service logs <enclave-id> miner
```

Execute a command inside a participant:

```bash
kurtosis service exec <enclave-id> miner -- btc-node rpc getblockcount
```

## Stopping the Network

```bash
kurtosis enclave stop <enclave-id>
kurtosis clean -a
```

## Configuration

Edit `kurtosis.yml` to add more nodes, change ports, or adjust command-line flags.
All participants run with `--network regtest --output json` for machine-readable output.
