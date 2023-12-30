# Server Protocol

Client <-> Proxy (Basic Shroom Protocol)
Proxy <-> Server (TCP + SSL) as described below


## Handshake (12 bytes)

The handshake is sent, after a remote client succesfuly etablishes a connection

| Offset | Value              | Size |
|--------|--------------------|------|
| 0      | Hdr(0xFEAB)        | 2    |
| 2      | Proxy Id(u32)      | 4    |
| 6      | Proxy Version(u16) | 2    |
| 8      | IPv4 Address       | 4    |


## Packet structure


| Offset | Value              | Size |
|--------|--------------------|------|
| 0      | Length(u32)        | 4    |
| 4      | Payload            | n    |