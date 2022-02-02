#
#
#

from collections import defaultdict
from requests import Session
from logging import getLogger

from octodns.record import Record
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider

__VERSION__ = '0.0.1'


class ScalewayClientException(ProviderException):
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
    def __init__(self, msg):
        super(ScalewayClientUnknownDomainName, self).__init__(msg)


class ScalewayClient(object):
    def __init__(self, token, id, create_zone):
        self.log = getLogger(f'ScalewayClient[{id}]')
        session = Session()
        session.headers.update({'x-auth-token': token})
        self._session = session
        self.endpoint = 'http://127.0.0.1:4789/domain/v2beta1'
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
            if self.create_zone:
                return []
            else:
                e = ScalewayClientUnknownDomainName('This zone does '
                                                    'not exists, set the arg '
                                                    'create_zone to True to '
                                                    'allow creation of a new '
                                                    'zone')
                e.__cause__ = None
                raise e

    def record_updates(self, zone_name, data):
        self._request('PATCH', f'/dns-zones/{zone_name}/records',
                      data=data)


class ScalewayProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS = set((['A', 'AAAA', 'ALIAS', 'CAA', 'CNAME', 'LOC', 'MX',
                     'NAPTR', 'NS', 'PTR', 'SPF', 'SRV', 'SSHFP',
                     'TXT']))

    def __init__(self, id, token, create_zone=True, *args, **kwargs):
        self.log = getLogger(f'ScalewayProvider[{id}]')
        self.log.debug('__init__: id=%s, token=***, create_zone=%s', id,
                       create_zone)
        super(ScalewayProvider, self).__init__(id, *args, **kwargs)
        self._client = ScalewayClient(token, id, create_zone)

        self._zone_records = {}

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

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple
    _data_for_NS = _data_for_multiple

    _data_for_ALIAS = _data_for_single
    _data_for_CNAME = _data_for_single
    _data_for_PTR = _data_for_single

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
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': [records[0]['data']]
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

    def _params_delete(self, record):
        return {
            "delete": {
                "idFields": {
                    "type": record.record._type,
                    "name": record.record.name
                }
            }
        }

    def _params_update(self, record):
        return {
            "set": {
                "idFields": {
                    "type": record.record._type,
                    "name": record.record.name
                },
                "records": getattr(self, f'_params_for_{record.new._type}')
                                  (record.new)
            }
        }

    def _params_create(self, record):
        return {
            "add": {
                "records": getattr(self, f'_params_for_{record.record._type}')
                                  (record.new)
            }
        }

    def _params_for_multiple(self, record):
        params = []
        for value in record.values:
            params.append({
                'name': self._record_name(record.name),
                'ttl': record.ttl,
                'type': record._type,
                'data': value,
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

    def _apply_updates(self, zone, updates):
        self._client.record_updates(zone, {
            "return_all_records": False,
            "changes": updates
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
        self._apply_updates(zone, deletes + updates + creates)

        # Clear out the cache if any
        self._zone_records.pop(desired.name, None)
