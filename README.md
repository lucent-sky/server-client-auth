# server‑client‑auth

## Overview

`server‑client‑auth` is a simple authentication system implemented in C. It demonstrates a minimal server and client that authenticate users based on a stored password and salt. The system reads user credentials from a simple flat file (`user_db.txt`), combines a private password with a per‑user salt, and hashes the result to protect against rainbow table attacks. :contentReference[oaicite:0]{index=0}

This project is intended for educational purposes or as a starting point for a lightweight, C‑based authentication mechanism.

## Features

- Simple server‑client authentication written in portable C
- Stores users with salts to improve security against precomputed hash attacks
- Uses hashing to protect stored passwords
- Includes a minimal demonstration database (`user_db.txt`) with user entries

## Project Structure

At a high level, the repository contains:

- LICENSE
- Makefile
- client.c
- server.c
- common.h
- crypto_utils.c
- crypto_utils.h
- user_db.txt


The server.c and client.c files implement the basic server and client, crypto_utils.* contain hashing support and utility functions, and common.h holds shared definitions.

## Building

You can build both the server and client from the included Makefile, or manually:

```
gcc -o server server.c crypto_utils.c
gcc -o client client.c crypto_utils.c
```

# Usage

## Setting up the User Database

The user_db.txt file contains user entries in a simple format:
```
username:salt:password
```

New users can be added by any admin account.  The uploaded user_db.txt is propagated with 2 users, an admin and user, for reference.  The program will let you create an admin account if you delete the entire contents of the user_db.txt file.



