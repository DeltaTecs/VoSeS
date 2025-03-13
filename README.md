# VoSeS
Volatile Secret Searcher - massively parallel, brute force memory dump analysis for (D)TLS 1.2 secret extraction

You have:
- A wireshark capture file of application traffic
- A memory dump of the machine that was made while the application ran
and you want to decrypt the application traffic?

Then this tool works for you. Requirements:
- CUDA capable device * happy jensen noises *
- the traffic must be entrypted with tls 1.2 or dtls 1.2
- this tool supports only GCM_AES_128_SHA_256 and GCM_AES_256_SHA_384 encryption

Compile on windows:
`mkdir build`
`cd build`
`cmake ..`
`cmake --build .`

Run:
```
voses.exe
  --client_random|-cr <32-byte hex>
  --server_random|-sr <32-byte hex>
  --client_finished|-cf <hex, max 61 bytes>
  --algorithm|-a <gcm_256_sha_384|gcm_128_sha_256>
  --haystack|-h <path>  (memory dump file path)
  [--entropy|-e <float>]
  [--entropy-scan|-es]
```

set entropy to a different filter value if you like. scan will show you how many 48 byte locations match your filter.

When a master secret matching your randoms and cipher text is found it will be printed in a format that can be read by wireshark as a master secret log file.
