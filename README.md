<p align="center" >
  <img width="150px" src="https://pushzero-assets.akamai.com/static/pushzero_logo.png" align="center"/>
</p>

# Akamai Krypton SSH Agent for P
The `akr` command line utility is Akamai's "Krypton" SSH Agent, the successor to [`kr`](https://github.com/kryptco/kr) which works exclusively with the [Akamai MFA Authenticator](https://mfa.akamai.com/app) for iOS and Android.
Akr enables your smart phone to become a "push-based" FIDO2 authenticator for SSH authentication.

__Akr__ enables SSH to authenticate with a FIDO2 key stored in the __Akamai MFA Authenticator app__
([iOS](https://apps.apple.com/us/app/akamai-pushzero/id1503619894#?platform=iphone) +
[Android](https://play.google.com/store/apps/details?id=com.akamai.pushzero)).

__Akr__runs as an SSH agent: when you run `ssh [user@server]`, SSH asks the agent for a FIDO2 private key signature
operation. This request is routed to a
paired mobile phone (running the Akamai MFA app), where the user decides whether to allow the operation or
not. If allowed, the phone simply sends the signature back to the agent. _Private keys never leaves the phone._


# Getting Started

## Usage
[TODO]: akr setup, akr pair, akr generate, then demo server

## Requirements
[TODO]: OS requirements + SSH cli/server requirements


## Installation instructions
### macOS (brew)
```sh
$ brew install akamai/mfa/akr
```

### Debian
[TODO]

### CentOS
[TODO]

### RHEL
[TODO]

### Build from source
`akr` is built entirely with Rust. Ensure you have Rust installed (https://rustup.rs) and run `cargo build`.

## Notes on Configuration
Running `akr setup` updates your SSH config file and installeds the `akr` ssh-agent as a background service on your system.
To see what `akr` configures, run `akr setup --print-only`.

The SSH config additions looks as follows:
```
# Begin Akamai MFA SSH Config
Host *
	IdentityAgent /Users/<username>/.akr/akr-ssh-agent.sock
# End Akamai MFA SSH Config
```
This enables your native system SSH to communicate to the `akr` ssh-agent process over a unix socket.

# License
All rights reserved by Akamai Technologies.

# Security Disclosure
For any security related questions, please contact our security team.
Please disclose any issues responsibly using our [Akamai Security GPG Public Key](https://www.akamai.com/us/en/multimedia/documents/infosec/akamai-security-general.pub)
and send communications to [security@akamai.com](mailto://security@akamai.com).
