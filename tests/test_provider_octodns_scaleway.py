#
#
#

from requests import HTTPError
from requests_mock import ANY, mock as requests_mock
from unittest import TestCase
from unittest.mock import Mock, call

from octodns.record import Record
from octodns_scaleway import ScalewayClientBadRequest,\
    ScalewayClientUnknownDomainName, ScalewayClientNotFound, ScalewayProvider
from octodns.zone import Zone


class TestScalewayProvider(TestCase):
    expected = Zone('unit.tests.', [])
    for name, data in (
        ('sub', {
            'ttl': 1800,
            'type': 'NS',
            'values': [
                '6.2.3.4.',
                '7.2.3.4.'
            ]
        }),
        ('sub', {
            'ttl': 1800,
            'type': 'CAA',
            'value': {
                'flags': 0,
                'tag': 'issue',
                'value': 'ca.unit.tests'
            }
        }),
        ('sub', {
            'ttl': 1800,
            'type': 'LOC',
            'value': {
                'altitude': '4.00',
                'lat_degrees': '51',
                'lat_direction': 'N',
                'lat_minutes': '57',
                'lat_seconds': '0.123',
                'long_degrees': '5',
                'long_direction': 'E',
                'long_minutes': '54',
                'long_seconds': '0.000',
                'precision_horz': '10000.00',
                'precision_vert': '10.00',
                'size': '1.00'
            }
        }),
        ('sub', {
            'ttl': 1800,
            'type': 'MX',
            'values': [{
                'preference': 10,
                'exchange': 'smtp-1.unit.tests.',
            }, {
                'preference': 20,
                'exchange': 'smtp-2.unit.tests.',
            }]
        }),
        ('sub', {
            'ttl': 1800,
            'type': 'NAPTR',
            'value': {
                'order': 10,
                'preference': 20,
                'flags': 'U',
                'service': 'SIP+D2U',
                'regexp': '!^.*$!sip:info@bar.example.com!',
                'replacement': '.',
            }
        }),
        ('sub', {
            'ttl': 1800,
            'type': 'SPF',
            'value': 'v=spf1 ip4:127.0.0.1/24 ip4:192.168.1.1 a -all'
        }),
        ('sub', {
            'ttl': 1800,
            'type': 'SSHFP',
            'value': {
                'algorithm': 2,
                'fingerprint': '123456789abcdef67890123456789abcdef67899',
                'fingerprint_type': 1
            }
        }),
        ('', {
            'ttl': 1800,
            'type': 'ALIAS',
            'value': 'alias.unit.tests.'
        }),
        ('_srv._tcp2', {
            'ttl': 1800,
            'type': 'SRV',
            'value': {
                'priority': 10,
                'weight': 20,
                'port': 30,
                'target': 'cname.unit.tests.'
            }
        })
    ):
        expected.add_record(Record.new(expected, name, data))

    def test_populate(self):
        provider = ScalewayProvider('test', 'token')

        # Bad Request
        with requests_mock() as mock:
            mock.get(ANY, status_code=400,
                     text='{"message": "error on field \'change\': unknown '
                          'field"}')

            with self.assertRaises(ScalewayClientBadRequest) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)
            self.assertEqual('Bad request', str(ctx.exception))

        # Bad auth
        with requests_mock() as mock:
            mock.get(ANY, status_code=401,
                     text='{"message":"authentication is denied","method":'
                          '"api_key","reason":"invalid_argument",'
                          '"type":"denied_authentication"}')

            with self.assertRaises(Exception) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)
            self.assertEqual('Unauthorized', str(ctx.exception))

        # Forbidden without zone creation
        with requests_mock() as mock:
            provider2 = ScalewayProvider('test', 'token', False)
            mock.get(ANY, status_code=403,
                     text='{"message": "domain not found"}')

            with self.assertRaises(ScalewayClientUnknownDomainName) as ctx:
                zone = Zone('unit.tests.', [])
                provider2.populate(zone)
            self.assertEqual('This zone does not exists, set the arg '
                             'create_zone to True to allow creation '
                             'of a new zone', str(ctx.exception))

        # General error
        with requests_mock() as mock:
            mock.get(ANY, status_code=502, text='Things caught fire')

            with self.assertRaises(HTTPError) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)
            self.assertEqual(502, ctx.exception.response.status_code)

        # Forbidden but with zone creation
        with requests_mock() as mock:
            mock.get(ANY, status_code=403, text='{"records": []}')

            zone2 = Zone('unit.tests2.', [])
            provider.populate(zone2)
            self.assertEqual(0, len(zone2.records))

        # Non-existent zone doesn't populate anything
        with requests_mock() as mock:
            mock.get(ANY, status_code=404,
                     text='{"message": "Domain `foo.bar` not found"}')

            zone = Zone('unit.tests.', [])
            provider.populate(zone)
            self.assertEqual(0, len(zone.records))
            self.assertEqual(set(), zone.records)

        # No diffs == no changes
        with requests_mock() as mock:
            with open('tests/fixtures/scaleway-ok.json') as fh:
                mock.get('http://127.0.0.1:4789/domain/v2beta1/dns-zones/'
                         'unit.tests/records?page_size=1000', text=fh.read())

            zone = Zone('unit.tests.', [])

            provider.populate(zone)
            self.assertEqual(11, len(zone.records))
            changes = self.expected.changes(zone, provider)
            self.assertEqual(19, len(changes))

        # 2nd populate makes no network calls/all from cache
        again = Zone('unit.tests.', [])
        provider.populate(again)
        self.assertEqual(11, len(again.records))
        changes = self.expected.changes(zone, provider)
        self.assertEqual(19, len(changes))

        # bust the cache
        del provider._zone_records[zone.name]

        # test handling of invalid content
        with requests_mock() as mock:
            with open('tests/fixtures/scaleway-nok.json') as fh:
                mock.get(ANY, text=fh.read())

            zone = Zone('unit.tests.', [])
            provider.populate(zone, lenient=True)
            self.assertEqual(set([
                Record.new(zone, '', {
                    'ttl': 600,
                    'type': 'SSHFP',
                    'values': []
                }, lenient=True),
                Record.new(zone, '_srv._tcp', {
                    'ttl': 600,
                    'type': 'SRV',
                    'values': []
                }, lenient=True),
                Record.new(zone, 'naptr', {
                    'ttl': 600,
                    'type': 'NAPTR',
                    'values': []
                }, lenient=True),
                Record.new(zone, 'caa', {
                    'ttl': 600,
                    'type': 'CAA',
                    'values': []
                }, lenient=True),
                Record.new(zone, 'loc', {
                    'ttl': 600,
                    'type': 'LOC',
                    'values': []
                }, lenient=True),
                Record.new(zone, 'mx', {
                    'ttl': 600,
                    'type': 'MX',
                    'values': []
                }, lenient=True),
            ]), zone.records)

    def test_apply(self):
        provider = ScalewayProvider('test', 'token', False)

        resp = Mock()
        resp.json = Mock()
        provider._client._request = Mock(return_value=resp)

        # non-existent domain, create everything
        resp.json.side_effect = [
            ScalewayClientNotFound,  # no zone in populate
            ScalewayClientNotFound,  # no domain during apply
        ]
        plan = provider.plan(self.expected)

        n = len(self.expected.records)
        self.assertEqual(n, len(plan.changes))
        self.assertEqual(n, provider.apply(plan))
        # self.assertEqual(n, provider.apply(plan))
        self.assertFalse(plan.exists)

        provider._client._request.assert_has_calls([
            # created at least some of the record with expected data
            call('GET', '/dns-zones/unit.tests/records?page_size=1000'),
            call('PATCH', '/dns-zones/unit.tests/records', data={
                'return_all_records': False,
                'changes': [
                    {
                        'add': {
                            'records': [
                                {
                                    'name': '@',
                                    'ttl': 1800,
                                    'type': 'ALIAS',
                                    'data': 'alias.unit.tests.'
                                }
                            ]
                        }
                    },
                    {
                        'add': {
                            'records': [
                                {
                                    'name': '_srv._tcp2',
                                    'ttl': 1800,
                                    'type': 'SRV',
                                    'data': '10 20 30 cname.unit.tests.'
                                }
                            ]
                        }
                    },
                    {
                        'add': {
                            'records': [
                                {
                                    'name': 'sub',
                                    'ttl': 1800,
                                    'type': 'CAA',
                                    'data': '0 issue "ca.unit.tests"'
                                }
                            ]
                        }
                    },
                    {
                        'add': {
                            'records': [
                                {
                                    'name': 'sub',
                                    'ttl': 1800,
                                    'type': 'LOC',
                                    'data': '51 57 0.123 N 5 54 0.000 E 4.00m'\
                                    ' 1.00m 10000.00m 10.00m'
                                }
                            ]
                        }
                    },
                    {
                        'add': {
                            'records': [
                                {
                                    'name': 'sub',
                                    'ttl': 1800,
                                    'type': 'MX',
                                    'data': '10 smtp-1.unit.tests.'
                                },
                                {
                                    'name': 'sub',
                                    'ttl': 1800,
                                    'type': 'MX',
                                    'data': '20 smtp-2.unit.tests.'
                                }
                            ]
                        }
                    },
                    {
                        'add': {
                            'records': [
                                {
                                    'name': 'sub',
                                    'ttl': 1800,
                                    'type': 'NAPTR',
                                    'data': '10 20 "U" "SIP+D2U" '\
                                    '"!^.*$!sip:info@bar.example.com!" .'
                                }
                            ]
                        }
                    },
                    {
                        'add': {
                            'records': [
                                {
                                    'name': 'sub',
                                    'ttl': 1800,
                                    'type': 'NS',
                                    'data': '6.2.3.4.'
                                },
                                {
                                    'name': 'sub',
                                    'ttl': 1800,
                                    'type': 'NS',
                                    'data': '7.2.3.4.'
                                }
                            ]
                        }
                    },
                    {
                        'add': {
                            'records': [
                                {
                                    'name': 'sub',
                                    'ttl': 1800,
                                    'type': 'TXT',
                                    'data': 'v=spf1 ip4:127.0.0.1/24 '\
                                    'ip4:192.168.1.1 a -all'
                                }
                            ]
                        }
                    },
                    {
                        'add': {
                            'records': [
                                {
                                    'name': 'sub',
                                    'ttl': 1800,
                                    'type': 'SSHFP',
                                    'data': '2 1 123456789abcdef67890'\
                                    '123456789abcdef67899'
                                }
                            ]
                        }
                    }
                ]
            }),
        ])
        # expected number of total calls
        self.assertEqual(2, provider._client._request.call_count)

        provider._client._request.reset_mock()

        # delete 1 and update 1
        provider._client.zone_records = Mock(return_value=[
            {
                'name': 'www',
                'data': '1.2.3.4',
                'ttl': 300,
                'type': 'A',
            },
            {
                'name': 'www',
                'data': '2.2.3.4',
                'ttl': 300,
                'type': 'A',
            },
            {
                'name': 'ttl',
                'data': '3.2.3.4',
                'ttl': 600,
                'type': 'A',
            }
        ])
        # Domain exists, we don't care about return
        resp.json.side_effect = ['{}']

        wanted = Zone('unit.tests.', [])
        wanted.add_record(Record.new(wanted, 'ttl', {
            'ttl': 300,
            'type': 'A',
            'value': '3.2.3.4'
        }))

        plan = provider.plan(wanted)
        self.assertTrue(plan.exists)
        self.assertEqual(2, len(plan.changes))
        self.assertEqual(2, provider.apply(plan))
        # recreate for update, and deletes for the 2 parts of the other
        provider._client._request.assert_has_calls([
            call('PATCH', '/dns-zones/unit.tests/records', data={
                'return_all_records': False,
                'changes': [
                    {
                        'set': {
                            'idFields': {
                                'type': 'A',
                                'name': 'ttl'
                            },
                            'records': [
                                {
                                    'name': 'ttl',
                                    'ttl': 300,
                                    'type': 'A',
                                    'data': '3.2.3.4'
                                }
                            ]
                        }
                    },
                    {
                        'delete': {
                            'idFields': {
                                'type': 'A',
                                'name': 'www'
                            }
                        }
                    }
                ]
            })
        ], any_order=True)
