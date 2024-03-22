# Secure Messaging Application

This project implements a secure messaging application using modern cryptographic principles, including the Modulo-based Diffie-Hellman Exchange, Extended Triple Diffie-Hellman (X3DH) Public Key Exchange method, and Double Ratcheting for Forward Secrecy. These protocols provide robust security measures for end-to-end encrypted messaging, similar to those found in popular messaging applications like WhatsApp and Signal.

The foundational Diffie-Hellman Key Exchange protocol was introduced in the seminal paper by Whitfield Diffie and Martin Hellman, which you can read [here](https://www-ee.stanford.edu/~hellman/publications/24.pdf). The X3DH and Double Ratcheting algorithms, developed by Signal, further extend this framework to offer enhanced security features for asynchronous messaging environments.

## Features

- Modulo-based Diffie-Hellman and [Extended Triple Diffie-Hellman Key Exchange](https://signal.org/docs/specifications/x3dh/) for secure generation of shared secrets.
- Support for generating and managing one-time prekeys, incorporating [Double Ratcheting](https://signal.org/docs/specifications/doubleratchet) mechanisms for forward secrecy.

## Installation

### Prerequisites
Python 3.6 or later installed on your system. This project depends on several Python libraries, which are listed in the `requirements.txt` file.
To install the required libraries, run the following command in your terminal:

### Setting Up a Virtual Environment

It's recommended to use a virtual environment for running this project to manage dependencies efficiently. You can set up a virtual environment by running:

```bash
pip install -r requirements.txt

python -m venv venv

source venv/bin/activate
