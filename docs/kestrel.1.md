---
title: kestrel
section: 1
header: Kestrel Manual
---

# NAME
kestrel - File Encryption Utility

# SYNOPSIS
kestrel encrypt [FILE] -t NAME -f NAME [-o FILE] [-k KEYRING]

kestrel decrypt [FILE] -t NAME [-o FILE] [-k KEYRING]

kestrel key generate [-o FILE]

kestrel key change-pass PRIVATE-KEY

kestrel key extract-pub PRIVATE-KEY

kestrel password encrypt|decrypt [FILE] [-o FILE]

# DESCRIPTION
Kestrel is a file encryption utility that lets you encrypt files to anyone with a public key.

Start by generating your key pair using: kestrel key generate

**KEYRING FORMAT**

The keyring is a simple text file listing public and private keys. Keys can
appear is any order, and each name and key must be unique.

Example:

[Key]  
Name = alice  
PublicKey = BASE64-PUBLIC-KEY  
PrivateKey = BASE64-PRIVATE-KEY  

[Key]  
Name = bob  
\# Simple Comment  
PublicKey = BASE64-PUBLIC-KEY  

# OPTIONS
-t, --to NAME  
Recipient key name. Decrypt requires a private key.

-f, --from NAME  
Sender key name. Must be a private key.

-o, --output FILE  
Output file name.

-k, --keyring KEYRING  
Location of a keyring file.

-h, --help  
Print help information.

-v, --version  
Print version information.

--env-pass  
Read password from the KESTREL_PASSWORD environment variable.

The change-pass command requires setting both KESTREL_PASSWORD and KESTREL_NEW_PASSWORD if --env-pass is used.

# AUTHOR
Kyle Schreiber <kyle@80x24.net>
