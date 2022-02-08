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
    create_zone: False
```

#### Create Zone
Optional argument *(default: `False`)*.  
If set to `True`, Automaticaly create new zone when needed. **Be carreful: create a new zone can add fee.**  
If set to `False`, use the root zone.

### Support Information

#### Records

ScalewayProvider supports A, AAAA, ALIAS, CAA, CNAME, LOC, MX, NAPTR, NS, PTR, SPF, SRV, SSHFP, TXT

#### Dynamic

ScalewayProvider does partially support dynamic records.

Specification:
- All the pool name must have this pattern: `pool-{n}` (eg: `pool-0`, `pool-1`, `pool-2`...)
- The Geo province code isn't supported (eg: `NA`: ok, `EU-FR`: ok, `NA-US-KY`: not ok)
- If you set the country code, you can't mix multiple continents within a same pool (eg: `EU-FR, EU-BE`: ok, `EU-FR, NA`: not ok)
- Healthcheck only accept the default `obey` status

Full example:
```yaml
record-dynamic-geo:
  dynamic:
    pools:
      pool-0:
        fallback: pool-3
        values:
        - value: 1.1.1.1
        - value: 1.1.1.2
      pool-1:
        fallback: pool-3
        values:
        - value: 2.2.2.2
      pool-2:
        fallback: pool-3
        values:
        - value: 3.3.3.3
      pool-3:
        values:
        - value: 4.4.4.4
    rules:
    - geos:
      - AS
      - OC
      pool: pool-0
    - geos:
      - EU-CH
      - EU-FR
      pool: pool-1
    - geos:
      - EU-BE
      pool: pool-2
    - pool: pool-3
  ttl: 60
  type: A
  value: 5.5.5.5

record-dynamic-weigh:
  dynamic:
    pools:
      pool-0:
        values:
        - value: 1.1.1.1
          weight: 1
        - value: 1.1.1.2
          weight: 100
    rules:
    - pool: pool-0
  ttl: 60
  type: A
  value: 5.5.5.5

record-dynamic-healthcheck:
  dynamic:
    pools:
      pool-0:
        values:
        - value: 1.1.1.1
        - value: 1.1.1.2
    rules:
    - pool: pool-0
  octodns:
    healthcheck:
      host: my-domain.tld
      path: /check
      port: 443
      protocol: HTTPS
  ttl: 60
  type: A
  value: 5.5.5.5
```

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
