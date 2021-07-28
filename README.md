<p align="center" >
  <img width="150px" src="https://pushzero-assets.akamai.com/static/pushzero_logo.png" align="center"/>
</p>

# Akamai "Krypton" FIDO2 SSH Agent and CLI
The `akr` command line utility is Akamai's "Krypton" SSH Agent, the successor to [`kr`](https://github.com/kryptco/kr) which works exclusively with the [Akamai MFA Authenticator](https://mfa.akamai.com/app) for iOS and Android.
Akr enables your smart phone to become a "push-based" FIDO2 authenticator for SSH authentication.

`akr` enables SSH to authenticate with a FIDO2 key stored in the __Akamai MFA Authenticator app__
([iOS](https://apps.apple.com/us/app/akamai-pushzero/id1503619894#?platform=iphone) +
[Android](https://play.google.com/store/apps/details?id=com.akamai.pushzero)).

`akr` runs as an SSH agent: when you run `ssh [user@server]`, SSH asks the agent for a FIDO2 private key signature
operation. This request is routed to a
paired mobile phone (running the Akamai MFA app), where the user decides whether to allow the operation or
not. If allowed, the phone simply sends the signature back to the agent. _Private keys never leaves the phone._


# Getting Started
## First run
1. First, run `akr setup` to create configurations and start the agent
2. Next, pair your device: run `akr pair`
3. Scan the QR code with the [Akamai MFA app](https://mfa.akamai.com/app)
4. Run `akr generate --name mykey` to generate your first SSH key in Akamai MFA. This will output your SSH __public__ key.
5. Add your public key to a server or `github.com`


## Verify everything works
To verify whether your Akamai MFA FIDO2 key works, try the following:

```sh
$ ssh ssh.demo.krypt.co -p 5000
```

If everything works correctly, you should see something like this:
```sh
Hello John!

You have successfully authenticated to the Akamai MFA SSH FIDO2 test server! 
```

## Overview of Commands
Usage:  
`akr [options] [command] [arguments]`

Options:
 
| Syntax | Description |
| - | - |
| -V, --version | Display the version number for the akr client. |
| -h, --help | Display usage information for akr client. |
 

Commands:

| Command | Description | Example
| - | - | - | 
| setup | Setup the background daemon and updates ssh configuration | `akr setup`
| pair  | Pair with your phone/tablet | `akr pair`
| generate | Generate a new SSH credential | `akr generate --name <ssh_credential_name>`
| unpair | Unpair from your phone/tablet | `akr unpair`
| load | Load public keys from the Akamai MFA app on your phone/tablet | `akr load`
| status | Get pairing info from your phone/tablet | `akr status`
| check  | Health check of all the dep systems and system configs| `akr check`

## Requirements
  * macOS (10.15+) or Linux (64 Bit) (Debian, RHEL, and CentOS).
  * OpenSSH Client and Server 8.2+

## Installation instructions
### macOS (brew)
```sh
$ brew install akamai/mfa/akr
```

### Debian
```sh
curl -SsL https://akamai.github.io/akr-pkg/debian/KEY.gpg | sudo apt-key add -
sudo curl -SsL -o /etc/apt/sources.list.d/akr.list https://akamai.github.io/akr-pkg/debian/akr.list
sudo apt update
sudo apt install kr
```

### CentOS/RHEL
```sh
$ sudo vim /etc/yum.repos.d/akr.repo
[akr]
name=akr repository
baseurl=https://akamai.github.io/akr-pkg/rpm/
gpgcheck=0
enabled=1

$ sudo yum -y update
$ sudo yum -y install kr
```

### Build from source
`akr` is built entirely with Rust. Ensure you have Rust installed (https://rustup.rs) and run `cargo build`.

## Notes on Configuration
Running `akr setup` updates your SSH config file and installs the `akr` ssh-agent as a background service on your system.
To see what `akr` configures, run `akr setup --print-only`.

The SSH config additions looks as follows:
```
# Begin Akamai MFA SSH Config
Host *
	IdentityAgent /Users/<username>/.akr/akr-ssh-agent.sock
# End Akamai MFA SSH Config
```
This enables your native system SSH to communicate to the `akr` ssh-agent process over a unix socket.

# Security Disclosure
For any security related questions, please contact our security team.
Please disclose any issues responsibly using our [Akamai Security GPG Public Key](https://www.akamai.com/us/en/multimedia/documents/infosec/akamai-security-general.pub)
and send communications to [security@akamai.com](mailto://security@akamai.com).

# License
Copyright (c) 2021, Akamai Technologies.
All rights reserved.
