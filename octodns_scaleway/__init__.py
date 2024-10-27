#
#
#

from collections import defaultdict
from requests import Session
from logging import getLogger
from urllib.parse import urlparse

from octodns.record import Record
from octodns.record.geo import GeoCodes
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider

__VERSION__ = '0.0.4'
__API_VERSION__ = 'v2beta1'


class ScalewayClientException(ProviderException):
    pass


class ScalewayProviderException(ProviderException):
    pass


class ScalewayClientBadRequest(ScalewayClientException):
    def __init__(self):
        super(ScalewayClientBadRequest, self).__init__('Bad request')


class ScalewayClientUnauthorized(ScalewayClientException):
    def __init__(self):
        super(ScalewayClientUnauthorized, self).__init__('Unauthorized')


class ScalewayClientForbidden(ScalewayClientException):
    def __init__(self):
        super(ScalewayClientForbidden, self).__init__('Forbidden')


class ScalewayClientNotFound(ScalewayClientException):
    def __init__(self):
        super(ScalewayClientNotFound, self).__init__('Not found')


class ScalewayClientUnknownDomainName(ScalewayClientException):
    def __init__(self):
        super(ScalewayClientUnknownDomainName, self).__init__('Domain not '
                                                              'found')


class ScalewayClient(object):
    def __init__(self, token, id, create_zone):
        self.log = getLogger(f'ScalewayClient[{id}]')
        session = Session()
        session.headers.update({'x-auth-token': token})
        self._session = session
        self.endpoint = f'https://api.scaleway.com/domain/{__API_VERSION__}'
        self.create_zone = create_zone

    def _request(self, method, path, params={}, data=None):
        url = f'{self.endpoint}{path}'
        r = self._session.request(method, url, params=params, json=data)
        if r.status_code == 400:
            raise ScalewayClientBadRequest()
        if r.status_code == 401:
            raise ScalewayClientUnauthorized()
        elif r.status_code == 403:
            raise ScalewayClientForbidden()
        elif r.status_code == 404:
            raise ScalewayClientNotFound()
        r.raise_for_status()
        return r

    def zone_records(self, zone_name):
        try:
            return self._request('GET', f'/dns-zones/{zone_name}/records'
                                 '?page_size=1000').json()['records']
        except ScalewayClientForbidden:
            return []

    def record_updates(self, zone_name, data):
        self.log.debug(f'record_updates: zone_name={zone_name}, data={data}')
        self._request('PATCH', f'/dns-zones/{zone_name}/records',
                      data=data)


class ScalewayProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = True
    SUPPORTS_POOL_VALUE_STATUS = False
    SUPPORTS = set((['A', 'AAAA', 'ALIAS', 'CAA', 'CNAME', 'DNAME',
                     'LOC', 'MX', 'NAPTR', 'NS', 'PTR', 'SPF',
                     'SRV', 'SSHFP', 'TXT']))

    def __init__(self, id, token, create_zone=False, *args, **kwargs):
        self.log = getLogger(f'ScalewayProvider[{id}]')
        self.log.debug('__init__: id=%s, token=***, create_zone=%s', id,
                       create_zone)
        super(ScalewayProvider, self).__init__(id, *args, **kwargs)
        self._client = ScalewayClient(token, id, create_zone)

        self._zone_records = {}

    def _data_dynamic_geo(self, geo_ip_config):
        pools = {}
        rules = []

        matches = []
        # merge the sames matches for multiple values
        for match in geo_ip_config['matches']:
            match['datas'] = []
            found = False
            for _match in matches:
                shared_items = {
                    k: match[k]
                    for k in match if k in _match and match[k] == _match[k]
                }

                # compare if the match have the same number of keys
                # ans if they are shared all they items but data and datas
                if len(match.keys()) == len(_match.keys()) \
                   and len(shared_items) == len(_match.keys()) - 2:
                    _match['datas'].append(match['data'])
                    found = True
                    break

            if not found:
                match['datas'] = [match['data']]
                matches.append(match)

        # rules
        n = 0
        fallback = None
        for match in matches:
            geos = []
            if 'countries' in match and len(match['countries']):
                for country in match['countries']:
                    geos.append(GeoCodes.country_to_code(country))
            else:
                geos = match['continents']

            rules.append({
                'pool': f'pool-{n}',
                'geos': geos
            })
            n += 1

        if geo_ip_config['default']:
            fallback = f'pool-{n}'
            rules.append({
                'pool': fallback
            })

        # pools
        n = 0
        for match in matches:
            values = []
            for data in match['datas']:
                values.append({
                    'value': data,
                    'weight': 1,
                    'status': 'obey'
                })
            pools[f'pool-{n}'] = {
                'fallback': fallback if fallback else None,
                'values': values
            }
            n += 1

        if fallback:
            pools[f'pool-{n}'] = {
                'fallback': None,
                'values': [{
                    'value': geo_ip_config['default'],
                    'weight': 1,
                    'status': 'obey'
                }]
            }

        return {
            'pools': pools,
            'rules': rules
        }

    def _data_dynamic_weight(self, weighted_config):
        pools = {
            'pool-0': {
                'values': []
            }
        }
        rules = [{
            'pool': 'pool-0'
        }]

        values = []
        for ips in weighted_config['weighted_ips']:
            values.append({
                'value': ips['ip'],
                'weight': ips['weight']
            })

        pools['pool-0']['values'] = values
        return {
            'pools': pools,
            'rules': rules
        }

    def _data_dynamic_healthcheck(self, http_service_config):
        url = urlparse(http_service_config['url'])
        return {
            'pools': {
                'pool-0': {
                    'values': [{'value': ip} for ip in
                               http_service_config['ips']]
                }
            },
            'rules': [{
                'pool': 'pool-0'
            }],
            'octodns': {
                'healthcheck': {
                    'host': url.hostname,
                    'path': url.path,
                    'port': url.port,
                    'protocol': url.scheme.upper()
                }
            }
        }

    def _data_for_multiple(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': [record['data'] for record in records]
        }

    def _data_for_single(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'value': records[0]['data']
        }

    def _data_for_A_AAAA(self, _type, records):
        record = {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': []
        }

        for r in records:
            if 'geo_ip_config' in r:
                record['dynamic'] = self._data_dynamic_geo(
                    r['geo_ip_config'])
            elif 'weighted_config' in r:
                record['dynamic'] = self._data_dynamic_weight(
                    r['weighted_config'])
            elif 'http_service_config' in r:
                healthcheck = self._data_dynamic_healthcheck(
                    r['http_service_config'])
                record['dynamic'] = {
                    'pools': healthcheck['pools'],
                    'rules': healthcheck['rules']
                }
                record['octodns'] = healthcheck['octodns']

            record['values'].append(r['data'])

        return record

    _data_for_A = _data_for_A_AAAA
    _data_for_AAAA = _data_for_A_AAAA
    _data_for_NS = _data_for_multiple

    _data_for_ALIAS = _data_for_single
    _data_for_PTR = _data_for_single
    _data_for_DNAME = _data_for_single

    def _data_for_CAA(self, _type, records):
        values = []
        for record in records:
            try:
                flags, tag, value = record['data'].split(' ', 2)
            except ValueError:
                # invalid record
                continue

            values.append({
                'flags': flags,
                'tag': tag,
                # Remove quotes around value.
                'value': value[1:-1],
            })
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': values
        }

    def _data_for_CNAME(self, _type, records):
        record = {
            'ttl': records[0]['ttl'],
            'type': _type,
            'value': records[0]['data']
        }

        for r in records:
            if 'geo_ip_config' in r:
                record['dynamic'] = self._data_dynamic_geo(r['geo_ip_config'])

        return record

    def _data_for_LOC(self, _type, records):
        values = []
        for record in records:
            try:
                lat_degrees, lat_minutes, lat_seconds, lat_direction, \
                    long_degrees, long_minutes, long_seconds, long_direction, \
                    altitude, size, precision_horz, precision_vert = \
                    record['data'].replace('m', '').split(' ', 11)
            except ValueError:
                # invalid record
                continue

            values.append({
                'lat_degrees': lat_degrees,
                'lat_minutes': lat_minutes,
                'lat_seconds': lat_seconds,
                'lat_direction': lat_direction,
                'long_degrees': long_degrees,
                'long_minutes': long_minutes,
                'long_seconds': long_seconds,
                'long_direction': long_direction,
                'altitude': altitude,
                'size': size,
                'precision_horz': precision_horz,
                'precision_vert': precision_vert,
            })
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': values
        }

    def _data_for_MX(self, _type, records):
        values = []
        for record in records:
            try:
                priority, server = record['data'].split(' ', 1)
            except ValueError:
                # invalid record
                continue
            values.append({
                'preference': priority,
                'exchange': server
            })
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': values
        }

    def _data_for_NAPTR(self, _type, records):
        values = []
        for record in records:
            try:
                order, preference, flags, service, regexp,\
                    replacement = record['data'].split(' ', 5)
            except ValueError:
                # invalid record
                continue

            values.append({
                'order': order,
                'preference': preference,
                'flags': flags[1:-1],
                'service': service[1:-1],
                'regexp': regexp[1:-1],
                'replacement': replacement
            })
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': values
        }

    def _data_for_SRV(self, _type, records):
        values = []
        for record in records:
            try:
                priority, weight, port, target = record['data'].split(' ', 3)
            except ValueError:
                # invalid record
                continue
            values.append({
                'priority': priority,
                'weight': weight,
                'port': port,
                'target': target,
            })
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': values
        }

    def _data_for_SSHFP(self, _type, records):
        values = []
        for record in records:
            try:
                algorithm, fingerprint_type, \
                    fingerprint = record['data'].split(' ', 2)
            except ValueError:
                # invalid record
                continue

            values.append({
                'algorithm': algorithm,
                'fingerprint': fingerprint,
                'fingerprint_type': fingerprint_type
            })
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': values
        }

    def _data_for_TXT(self, _type, records):
        values = [record['data'].replace(';', '\\;') for record in records]
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': values
        }

    _data_for_SPF = _data_for_TXT

    def zone_records(self, zone):
        if zone.name not in self._zone_records:
            try:
                self._zone_records[zone.name] = \
                    self._client.zone_records(zone.name[:-1])
            except ScalewayClientNotFound:
                return []

        return self._zone_records[zone.name]

    def populate(self, zone, target=False, lenient=False):
        self.log.debug('populate: name=%s, target=%s, lenient=%s', zone.name,
                       target, lenient)

        values = defaultdict(lambda: defaultdict(list))
        for record in self.zone_records(zone):
            _type = record['type']
            if _type not in self.SUPPORTS:
                continue
            values[record['name']][record['type']].append(record)

        before = len(zone.records)
        for name, types in values.items():
            for _type, records in types.items():
                data = getattr(self, f'_data_for_{_type}')(_type, records)
                record = Record.new(zone, name, data,
                                    source=self, lenient=lenient)
                zone.add_record(record, lenient=lenient)

        exists = zone.name in self._zone_records
        self.log.info('populate:   found %s records, exists=%s',
                      len(zone.records) - before, exists)
        return exists

    def _record_name(self, name):
        return name if name else '@'

    def _params(self, record):
        dynamic = {}
        if getattr(record, 'dynamic', False):
            dynamic = self._params_dynamic(record)

        records = getattr(self, f'_params_for_{record._type}')(record)
        if dynamic and len(records):
            records = [records[0] | dynamic]

        return records

    def _params_delete(self, record):
        return {
            'delete': {
                'idFields': {
                    'type': record.record._type,
                    'name': record.record.name
                }
            }
        }

    def _params_update(self, record):
        return {
            'set': {
                'idFields': {
                    'type': record.record._type,
                    'name': record.record.name
                },
                'records': self._params(record.new)
            }
        }

    def _params_create(self, record):
        return {
            'add': {
                'records': self._params(record.new)
            }
        }

    def _params_for_multiple(self, record):
        params = []
        for value in record.values:
            params.append({
                'name': self._record_name(record.name),
                'ttl': record.ttl,
                'type': record._type,
                'data': value.replace('\\;', ';'),
            })

        return params

    def _params_for_single(self, record):
        record.values = [record.value]
        return self._params_for_multiple(record)

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple
    _params_for_NS = _params_for_multiple
    _params_for_TXT = _params_for_multiple

    _params_for_ALIAS = _params_for_single
    _params_for_CNAME = _params_for_single
    _params_for_DNAME = _params_for_single
    _params_for_PTR = _params_for_single

    def _params_for_CAA(self, record):
        record.values = [f'{v.flags} {v.tag} "{v.value}"' for v in
                         record.values]
        return self._params_for_multiple(record)

    def _params_for_LOC(self, record):
        record.values = [f'{v.lat_degrees} {v.lat_minutes} '
                         f'{v.lat_seconds:.3f} '
                         f'{v.lat_direction} {v.long_degrees} '
                         f'{v.long_minutes} '
                         f'{v.long_seconds:.3f} {v.long_direction} '
                         f'{v.altitude:.2f}m {v.size:.2f}m '
                         f'{v.precision_horz:.2f}m {v.precision_vert:.2f}m'
                         for v in record.values]
        return self._params_for_multiple(record)

    def _params_for_MX(self, record):
        record.values = [f'{v.preference} {v.exchange}' for v in record.values]
        return self._params_for_multiple(record)

    def _params_for_NAPTR(self, record):
        record.values = [f'{v.order} {v.preference} "{v.flags}" "{v.service}" '
                         f'"{v.regexp}" {v.replacement}' for v in
                         record.values]
        return self._params_for_multiple(record)

    def _params_for_SPF(self, record):
        record._type = 'TXT'
        return self._params_for_TXT(record)

    def _params_for_SRV(self, record):
        record.values = [f'{v.priority} {v.weight} {v.port} {v.target}'
                         for v in record.values]
        return self._params_for_multiple(record)

    def _params_for_SSHFP(self, record):
        record.values = [f'{v.algorithm} {v.fingerprint_type} '
                         f'{v.fingerprint}' for v in record.values]
        return self._params_for_multiple(record)

    def _params_dynamic(self, record):
        have_geo = False
        have_weight = False
        have_http_service = False

        pools = record.dynamic.pools
        rules = record.dynamic.rules
        healthcheck = record._octodns.get('healthcheck', {})

        n = 0
        for pool in pools:
            # check pools names
            if pool != f'pool-{n}':
                raise ScalewayProviderException(f'Pool name "{pool}" should be'
                                                f' "pool-{n}"')
            n += 1

        # check the type of dynamic record
        if healthcheck != {}:
            have_http_service = True

        for rule in rules:
            pool = pools[rule._data()['pool']]

            for value in pool._data()['values']:
                if value['weight'] != 1:
                    have_weight = True

            if 'geos' in rule._data():
                have_geo = True

        if (have_weight + have_http_service + have_geo) > 1:
            raise ScalewayProviderException('Cannot mix dynamic record types '
                                            '(geo, weight and service)')

        values = {}
        if have_geo:
            matches = []
            default = None
            for rule in rules:
                pool = pools[rule._data()['pool']]
                if 'geos' not in rule._data():
                    default = pool._data()['values'][0]['value']
                    continue

                match = {
                    'continents': [],
                    'countries': []
                }
                for geo in rule._data()['geos']:
                    codes = GeoCodes.parse(geo)

                    if codes['province_code'] is not None:
                        raise ScalewayProviderException('Geo province code '
                                                        'isn\'t supported')
                    if codes['country_code'] is not None:
                        match['countries'].append(codes['country_code'])
                    if not match['continents']\
                       .__contains__(codes['continent_code']):
                        match['continents'].append(codes['continent_code'])

                for value in pool._data()['values']:
                    # copy the math to avoid changing address match value
                    m = match.copy()
                    m['data'] = value['value']
                    matches.append(m)

            values['geo_ip_config'] = {
                'matches': matches
            }
            if default:
                values['geo_ip_config']['default'] = default

        elif have_weight:
            values['weighted_config'] = {
                'weighted_ips': []
            }
            for value in pools['pool-0']._data()['values']:
                values['weighted_config']['weighted_ips'].append({
                    'ip': value['value'],
                    'weight': value['weight']
                })

        elif have_http_service:
            values['http_service_config'] = {
                'ips': [],
                'must_contain': None,
                'url': f'{record.healthcheck_protocol}://'
                       f'{record.healthcheck_host()}:{record.healthcheck_port}'
                       f'{record.healthcheck_path}',
                'user_agent': f'scaleway-octodns/{__VERSION__}',
                'strategy': 'all'
            }
            for value in pools['pool-0']._data()['values']:
                values['http_service_config']['ips'].append(value['value'])

        else:
            raise ScalewayProviderException('No dynamic type record found')

        return values

    def _apply_updates(self, zone, updates):
        self._client.record_updates(zone, {
            'return_all_records': False,
            'disallow_new_zone_creation': not self._client.create_zone,
            'changes': updates
        })

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        zone = desired.name[:-1]
        self.log.debug('_apply: zone=%s, len(changes)=%d', desired.name,
                       len(changes))

        # Generate the changes to apply all the Delete, Update and Create
        # in a single call
        creates = []
        updates = []
        deletes = []
        for change in changes:
            class_name = change.__class__.__name__.lower()
            if class_name == 'create':
                creates.append(self._params_create(change))
            elif class_name == 'update':
                updates.append(self._params_update(change))
            else:
                updates.append(self._params_delete(change))

        # Apply the update in the right order: deletes, updates and creates
        try:
            self._apply_updates(zone, deletes + updates + creates)
        except ScalewayClientForbidden:
            e = ScalewayClientUnknownDomainName()
            e.__cause__ = None
            raise e

        # Clear out the cache if any
        self._zone_records.pop(desired.name, None)

    def _process_desired_zone(self, desired):
        for record in desired.records:
            # test records
            if getattr(record, 'dynamic', False):
                self._params_dynamic(record)

        return super(ScalewayProvider, self)._process_desired_zone(desired)
