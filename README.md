This repository provides a tool designated to generate a **signed metadata block**, essential for the sealing key derivation mechanism.

## Building

To build the tool run the following command

```$ cargo build --release```

## Usage

To run the tool, you need to provide a private key (secp384r1) in pem format and the manifest in .yaml format.

Here are the example content of the example `manifest.yaml` file

```
realm_id: "com.company.realm"
version: "1.0.0"
svn: 1
rim: "5be4e8eb153c89f9d0a4030b4959268ae9e2b21058bce1a8bada7f124c3e77b3"
hash_algo: SHA256
```

The RIM (Realm Initial Measurements) and the selected hash algorithm should be taken from the output of the realm measurement tool.

To generate a private key, one can use the openssl tool e.g.:

```
openssl ecparam -genkey -name secp384r1 -noout -out private.pem
```

Once you have the private key and the manifest file, you can generate the metadata file by running the following command:

```
$ realm-metadata-tool create -m manifest.yaml -k private.pem -o metadata.bin
Metadata file 'metadata.bin' has been created!
```

The generated `metadat.bin` file can by provisioned to the RMM by providing the `--metadata metadata.bin` option to the `lkvm` tool.

To verify the signature of the generated metadata file, run the following command:

```
$ realm-metadata-tool verify -i metadata.bin
The signature of 'metadata.bin' metadata file is valid
```

To check the content of the metadata file, you can use the `dump` sub-command:

```
$ realm-metadata-tool dump -i metadata.bin
fmt:        1
realm_id:   'com.company.realm'
rim:        5BE4E8EB153C89F9D0A4030B4959268AE9E2B21058BCE1A8BADA7F124C3E77B30000000000000000000000000000000000000000000000000000000000000000
hash_algo:  SHA256
version:    1.0.0
svn:        1
public_key: 995A9A4A9273350464E0A91C6EB39A0CEC3BD4F756B79B3BE7EBA2A7AE7033E5BC75E520FA4279FF136B37D1CA8A18B5FE1DF6E90EF0ADE3FA65D8DB91B831367A460A7E36CDF0DF1A9DD682A5520754D51088E0072AF97AF69FC48874ECDD37
signature: 'C09C7793028594DB3A84506566B2ECA012B11A0ED987327AAF8B15BA3E4E2B7CF5C494D0E246135AF30DA4E16019CBCA143D7AC2FE44A57BD63AB15DA0E77F40851D548B6E6DB29C6ADA5BA95FAE69A03937FD502FE8DFB4DEBF3ECD8FE328EA'
```
