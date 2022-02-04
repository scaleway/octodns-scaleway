#
#
#

from requests import HTTPError
from requests_mock import ANY, mock as requests_mock
from unittest import TestCase
from unittest.mock import Mock, call

from octodns.record import Record
from octodns_scaleway import ScalewayClientBadRequest,\
    ScalewayClientUnknownDomainName, ScalewayClientNotFound, ScalewayProvider,\
    ScalewayProviderException
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
        }),
        ('dynamic', {
            'ttl': 1800,
            'type': 'A',
            'value': '1.1.1.1',
            'dynamic': {
                'pools': {
                    'pool-0': {
                        'fallback': 'pool-3',
                        'values': [{
                            'value': '2.2.2.2',
                        }],
                    },
                    'pool-1': {
                        'fallback': 'pool-3',
                        'values': [{
                            'value': '3.3.3.3',
                        }],
                    },
                    'pool-2': {
                        'fallback': 'pool-3',
                        'values': [{
                            'value': '4.4.4.4',
                        }],
                    },
                    'pool-3': {
                        'fallback': None,
                        'values': [{
                            'value': '5.5.5.5',
                        }],
                    },
                },
                'rules': [
                    {
                        'pool': 'pool-0',
                        'geos': [
                            'EU-FR',
                            'EU-BE'
                        ]
                    },
                    {
                        'pool': 'pool-1',
                        'geos': ['EU']
                    },
                    {
                        'pool': 'pool-2',
                        'geos': ['NA-US']
                    },
                    {
                        'pool': 'pool-3'
                    }
                ]
            }
        }),
        ('dynamic2', {
            'ttl': 1800,
            'type': 'A',
            'value': '1.1.1.1',
            'dynamic': {
                'pools': {
                    'pool-0': {
                        'fallback': None,
                        'values': [
                            {
                                'value': '2.2.2.2',
                            },
                            {
                                'value': '2.2.2.3',
                            }
                        ],
                    },
                },
                'rules': [
                    {
                        'pool': 'pool-0',
                        'geos': ['EU']
                    }
                ]
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
                mock.get('/domain/v2beta1/dns-zones/'
                         'unit.tests/records?page_size=1000', text=fh.read())

            zone = Zone('unit.tests.', [])

            provider.populate(zone)
            self.assertEqual(13, len(zone.records))
            changes = self.expected.changes(zone, provider)
            self.assertEqual(23, len(changes))

        # 2nd populate makes no network calls/all from cache
        again = Zone('unit.tests.', [])
        provider.populate(again)
        self.assertEqual(13, len(again.records))
        changes = self.expected.changes(zone, provider)
        self.assertEqual(23, len(changes))

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
        # Non-existent zone doesn't populate anything
        with requests_mock() as mock:
            provider = ScalewayProvider('test', 'token', True)

            mock.get('/domain/v2beta1/dns-zones/unit.not-exists'
                     '/records?page_size=1000', status_code=403)
            mock.patch('/domain/v2beta1/dns-zones/'
                       'unit.not-exists/records', status_code=403,
                       text='{"message": "domain not found"}')

            zone_not_exists = Zone('unit.not-exists.', [])
            zone_not_exists.add_record(Record.new(zone_not_exists, 'ttl', {
                'ttl': 300,
                'type': 'A',
                'value': '3.2.3.4'
            }))

            plan_not_exists = provider.plan(zone_not_exists)
            self.assertTrue(plan_not_exists.exists)
            self.assertEqual(1, len(plan_not_exists.changes))
            with self.assertRaises(ScalewayClientUnknownDomainName) as ctx:
                provider.apply(plan_not_exists)
            self.assertEqual('Domain not found', str(ctx.exception))

        # Test dynamic record exceptions
        with requests_mock() as mock:
            provider = ScalewayProvider('test', 'token', True)

            zone_dynamic = Zone('unit.dynamic.', [])
            zone_dynamic.add_record(Record.new(zone_dynamic, 'dynamic', {
                'ttl': 300,
                'type': 'A',
                'value': '3.2.3.4',
                'dynamic': {
                    'pools': {
                        'pool-0': {
                            'values': [{'value': '2.2.2.2'}],
                        },
                    },
                    'rules': [{
                        'pool': 'pool-0'
                    }]
                }
            }))

            with self.assertRaises(ScalewayProviderException) as ctx:
                provider.plan(zone_dynamic)
            self.assertEqual('No dynamic type record found',
                             str(ctx.exception))

            zone_dynamic.add_record(Record.new(zone_dynamic, 'dynamic', {
                'ttl': 300,
                'type': 'A',
                'value': '3.2.3.4',
                'dynamic': {
                    'pools': {
                        'pool-0': {
                            'values': [{
                                'value': '2.2.2.2',
                                'status': 'up'
                            }],
                        },
                    },
                    'rules': [{
                        'pool': 'pool-0'
                    }]
                }
            }), replace=True)

            with self.assertRaises(ScalewayProviderException) as ctx:
                provider.plan(zone_dynamic)
            self.assertEqual('Only accept geos, not weight or status',
                             str(ctx.exception))

            zone_dynamic.add_record(Record.new(zone_dynamic, 'dynamic', {
                'ttl': 300,
                'type': 'A',
                'value': '3.2.3.4',
                'dynamic': {
                    'pools': {
                        'pool-0': {
                            'values': [{
                                'value': '1.1.1.1'
                            }],
                        },
                    },
                    'rules': [{
                        'pool': 'pool-0',
                        'geos': ['NA-US-KY']
                    }]
                }
            }), replace=True)

            with self.assertRaises(ScalewayProviderException) as ctx:
                provider.plan(zone_dynamic)
            self.assertEqual('Geo province code isn\'t supported',
                             str(ctx.exception))

            zone_dynamic.add_record(Record.new(zone_dynamic, 'dynamic', {
                'ttl': 300,
                'type': 'A',
                'value': '3.2.3.4',
                'dynamic': {
                    'pools': {
                        'pool-0': {
                            'values': [{
                                'value': '1.1.1.1'
                            }],
                        },
                        'fallback': {
                            'values': [{
                                'value': '2.2.2.2'
                            }],
                        },
                    },
                    'rules': [
                        {
                            'pool': 'pool-0',
                            'geos': ['NA-US']
                        },
                        {
                            'pool': 'fallback'
                        }
                    ]
                }
            }), replace=True)

            with self.assertRaises(ScalewayProviderException) as ctx:
                provider.plan(zone_dynamic)
            self.assertEqual('Pool name "fallback" should be "pool-1"',
                             str(ctx.exception))

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
        self.assertFalse(plan.exists)

        provider._client._request.assert_has_calls([
            # created at least some of the record with expected data
            call('GET', '/dns-zones/unit.tests/records?page_size=1000'),
            call('PATCH', '/dns-zones/unit.tests/records', data={
                'return_all_records': False,
                'disallow_new_zone_creation': True,
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
                                    'name': 'dynamic',
                                    'ttl': 1800,
                                    'type': 'A',
                                    'data': '1.1.1.1',
                                    'geo_ip_config': {
                                        'matches': [
                                            {
                                                'continents': ['EU'],
                                                'countries': ['BE', 'FR'],
                                                'data': '2.2.2.2'
                                            },
                                            {
                                                'continents': ['EU'],
                                                'countries': [],
                                                'data': '3.3.3.3'
                                            },
                                            {
                                                'continents': ['NA'],
                                                'countries': ['US'],
                                                'data': '4.4.4.4'
                                            }
                                        ],
                                        'default': '5.5.5.5'
                                    }
                                }
                            ]
                        }
                    },
                    {
                        'add': {
                            'records': [
                                {
                                    'name': 'dynamic2',
                                    'ttl': 1800,
                                    'type': 'A',
                                    'data': '1.1.1.1',
                                    'geo_ip_config': {
                                        'matches': [
                                            {
                                                'continents': ['EU'],
                                                'countries': [],
                                                'data': '2.2.2.2'
                                            },
                                            {
                                                'continents': ['EU'],
                                                'countries': [],
                                                'data': '2.2.2.3'
                                            }
                                        ]
                                    }
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

        provider._client._request.assert_has_calls([
            call('PATCH', '/dns-zones/unit.tests/records', data={
                'return_all_records': False,
                'disallow_new_zone_creation': True,
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
