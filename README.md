## Scaleway DNS provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [Scaleway DNS](https://www.scaleway.com/en/dns/).

### Installation

#### Command line

```
pip install octodns_scaleway
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.14
octodns_scaleway==0.0.1
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/octodns/octodns_scaleway.git@ec9661f8b335241ae4746eea467a8509205e6a30#egg=octodns_scaleway
```

### Configuration

```yaml
providers:
  scaleway:
    class: octodns_scaleway.ScalewayProvider
    # API Secret Key
    token: env/SCALEWAY_SECRET_KEY
    # API Create zone
    create_zone: True
```

#### Create Zone
Optional argument (default: False).  
If set to True, Automaticaly create new zone when needed, be carreful, create a new zone can add fee.  
If set to False, try to use only the master zone.

### Support Information

#### Records

ScalewayProvider supports A, AAAA, ALIAS, CAA, CNAME, LOC, MX, NAPTR, NS, PTR, SPF, SRV, SSHFP, TXT

#### Dynamic

ScalewayProvider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
