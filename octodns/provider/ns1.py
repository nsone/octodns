#
#
#

from __future__ import absolute_import, division, print_function, \
    unicode_literals

from logging import getLogger
from collections import OrderedDict, defaultdict
from ns1 import NS1
from ns1.rest.errors import RateLimitException, ResourceException
from incf.countryutils.transformations import cc_to_cn, cn_to_ctca2
from time import sleep

from six import text_type

from ..record import Record
from .base import BaseProvider


class Ns1Provider(BaseProvider):
    '''
    Ns1 provider

    ns1:
        class: octodns.provider.ns1.Ns1Provider
        api_key: env/NS1_API_KEY
    '''
    SUPPORTS_GEO = True
    SUPPORTS_DYNAMIC = False
    SUPPORTS = set(('A', 'AAAA', 'ALIAS', 'CAA', 'CNAME', 'MX', 'NAPTR',
                    'NS', 'PTR', 'SPF', 'SRV', 'TXT'))
    ZONE_NOT_FOUND_MESSAGE = 'server error: zone not found'
    GEO_FILTER_CHAIN = [
        {"filter": "shuffle", "config": {}},
        {"filter": "geotarget_country", "config": {}},
        {"filter": "select_first_n", "config": {"N": 1}}
    ]

    def __init__(self, id, api_key, *args, **kwargs):
        self.log = getLogger('Ns1Provider[{}]'.format(id))
        self.log.debug('__init__: id=%s, api_key=***', id)
        super(Ns1Provider, self).__init__(id, *args, **kwargs)
        _NS1 = NS1(apiKey=api_key)
        self._NS1Records = _NS1.records()
        self._NS1Zones = _NS1.zones()
        self._zone_cache = {}
        self._record_cache = {}

    def loadZone(self, zone, create=False):
        zone = zone.rstrip('.')
        if zone not in self._zone_cache:
            if create:
                self.log.debug('loadZone: creating zone %s', zone)
                self._zone_cache[zone] = self._NS1Zones.create(zone)
            else:
                try:
                    self._zone_cache[zone] = self._NS1Zones.retrieve(zone)
                except ResourceException as e:
                    if e.message != self.ZONE_NOT_FOUND_MESSAGE:
                        raise
        return self._zone_cache.get(zone)

    def loadRecord(self, domain, _type, zone):
        domain = domain.rstrip('.')
        zone = zone.rstrip('.')
        self.log.debug('loadRecord(%s, %s, %s)', domain, _type, zone)
        rec = (zone, domain, _type)
        if rec not in self._record_cache:
            self._record_cache[rec] = self._NS1Records.retrieve(*rec)
        return self._record_cache.get(rec)

    def _data_for_A(self, _type, record):
        data = {'ttl': record['ttl'], 'type': _type, 'values': []}

        # If it's not a geo-enabled record, we'll only have the short version
        # returned by the /v1/zones/<zone> endpoint, which has no metadata.
        if not record.get('answers'):
            data['values'] = [str(a) for a in record.get('short_answers', [])]
            return data

        # For geo-enabled records we will have the full record object.
        geo = defaultdict(list)
        for answer in record.get('answers', []):
            meta = answer.get('meta', {})
            countries = meta.get('country')
            us_states = meta.get('us_state')
            ca_provinces = meta.get('ca_province')

            # Because us_state and ca_province metadata both imply a country,
            # only check for country if neither of those are specified.
            if us_states:
                for state in us_states:
                    key = str('NA-US-%s' % state)
                    geo[key].extend([str(a) for a in answer['answer']])
            elif ca_provinces:
                for province in ca_provinces:
                    key = str('NA-CA-%s' % province)
                    geo[key].extend([str(a) for a in answer['answer']])
            elif countries:
                for country in countries:
                    continent = cn_to_ctca2(cc_to_cn(country))
                    key = '{}-{}'.format(continent, country)
                    geo[key].extend([str(a) for a in answer['answer']])
            else:
                # No geo metadata means this is the regionless default answer
                # that octo requires be present on all geo records.
                data['values'].extend([str(a) for a in answer['answer']])

        data['geo'] = OrderedDict(geo)
        return data

    _data_for_AAAA = _data_for_A

    def _data_for_SPF(self, _type, record):
        values = [v.replace(';', '\\;') for v in record['short_answers']]
        return {
            'ttl': record['ttl'],
            'type': _type,
            'values': values
        }

    _data_for_TXT = _data_for_SPF

    def _data_for_CAA(self, _type, record):
        values = []
        for answer in record['short_answers']:
            flags, tag, value = answer.split(' ', 2)
            values.append({
                'flags': flags,
                'tag': tag,
                'value': value,
            })
        return {
            'ttl': record['ttl'],
            'type': _type,
            'values': values,
        }

    def _data_for_CNAME(self, _type, record):
        try:
            value = record['short_answers'][0]
        except IndexError:
            value = None
        return {
            'ttl': record['ttl'],
            'type': _type,
            'value': value,
        }

    _data_for_ALIAS = _data_for_CNAME
    _data_for_PTR = _data_for_CNAME

    def _data_for_MX(self, _type, record):
        values = []
        for answer in record['short_answers']:
            preference, exchange = answer.split(' ', 1)
            values.append({
                'preference': preference,
                'exchange': exchange,
            })
        return {
            'ttl': record['ttl'],
            'type': _type,
            'values': values,
        }

    def _data_for_NAPTR(self, _type, record):
        values = []
        for answer in record['short_answers']:
            order, preference, flags, service, regexp, replacement = \
                answer.split(' ', 5)
            values.append({
                'flags': flags,
                'order': order,
                'preference': preference,
                'regexp': regexp,
                'replacement': replacement,
                'service': service,
            })
        return {
            'ttl': record['ttl'],
            'type': _type,
            'values': values,
        }

    def _data_for_NS(self, _type, record):
        return {
            'ttl': record['ttl'],
            'type': _type,
            'values': [a if a.endswith('.') else '{}.'.format(a)
                       for a in record['short_answers']],
        }

    def _data_for_SRV(self, _type, record):
        values = []
        for answer in record['short_answers']:
            priority, weight, port, target = answer.split(' ', 3)
            values.append({
                'priority': priority,
                'weight': weight,
                'port': port,
                'target': target,
            })
        return {
            'ttl': record['ttl'],
            'type': _type,
            'values': values,
        }

    def ensure_fqdn(self, name):
        return "%s." % name.rstrip('.')

    def populate(self, zone, target=False, lenient=False):
        self.log.debug('populate: name=%s, target=%s, lenient=%s',
                       zone.name,
                       target, lenient)

        ns1_zone = self.loadZone(zone.name)
        if not ns1_zone:
            return False

        count = 0
        for record in ns1_zone.get('records', []):
            _type = record['type']
            if _type not in self.SUPPORTS:
                continue
            count += 1
            if _type in ['ALIAS', 'CNAME', 'MX', 'NS', 'PTR', 'SRV']:
                for i, a in enumerate(record['short_answers']):
                    record['short_answers'][i] = self.ensure_fqdn(a)
            if record['tier'] != 1:
                record = self.loadRecord(record['domain'], _type, zone)
            data_for = getattr(self, '_data_for_{}'.format(_type))
            name = zone.hostname_from_fqdn(record['domain'])
            record = Record.new(zone, name, data_for(_type, record),
                                source=self, lenient=lenient)
            zone.add_record(record, lenient=lenient)

        self.log.info('populate:   found %s records, exists=True', count)

        return True

    def _params_for_A(self, record):
        params = {'answers': record.values, 'ttl': record.ttl}
        if hasattr(record, 'geo'):
            # purposefully set non-geo answers to have an empty meta,
            # so that we know we did this on purpose if/when troubleshooting
            params['answers'] = [{"answer": [x], "meta": {}}
                                 for x in record.values]
            has_country = False
            for iso_region, target in record.geo.items():
                if len(iso_region.split('-')) > 1:
                    has_country = True
                for answer in target.values:
                    params['answers'].append({
                        'answer': [answer],
                        'meta': {'iso_region_code': [iso_region]},
                    })
            params['filters'] = self.GEO_FILTER_CHAIN if has_country else []
        self.log.debug("params for A: %s", params)
        return params

    _params_for_AAAA = _params_for_A
    _params_for_NS = _params_for_A

    def _params_for_SPF(self, record):
        # NS1 seems to be the only provider that doesn't want things
        # escaped in values so we have to strip them here and add
        # them when going the other way
        values = [v.replace('\\;', ';') for v in record.values]
        return {'answers': values, 'ttl': record.ttl}

    _params_for_TXT = _params_for_SPF

    def _params_for_CAA(self, record):
        values = [(v.flags, v.tag, v.value) for v in record.values]
        return {'answers': values, 'ttl': record.ttl}

    def _params_for_CNAME(self, record):
        return {'answers': [record.value], 'ttl': record.ttl}

    _params_for_ALIAS = _params_for_CNAME
    _params_for_PTR = _params_for_CNAME

    def _params_for_MX(self, record):
        values = [(v.preference, v.exchange) for v in record.values]
        return {'answers': values, 'ttl': record.ttl}

    def _params_for_NAPTR(self, record):
        values = [(v.order, v.preference, v.flags, v.service, v.regexp,
                   v.replacement) for v in record.values]
        return {'answers': values, 'ttl': record.ttl}

    def _params_for_SRV(self, record):
        values = [(v.priority, v.weight, v.port, v.target)
                  for v in record.values]
        return {'answers': values, 'ttl': record.ttl}

    def _params_for(self, record):
        params_for_type = getattr(self, '_params_for_%s' % record._type)
        return params_for_type(record)

    def _apply_Create(self, change):
        rec = change.new
        zone = rec.zone.name.rstrip('.')
        domain = rec.fqdn.rstrip('.')
        params = self._params_for(rec)
        try:
            self._NS1Records.create(zone, domain, rec._type, **params)
        except RateLimitException as e:
            self.log.warn('_apply_Create: rate limit exceeded, slowing down')
            sleep(int(e.period) / 10)
            self._apply_Create(change)

    def _apply_Update(self, change):
        rec = change.new
        zone = rec.zone.name.rstrip('.')
        domain = rec.fqdn.rstrip('.')
        params = self._params_for(rec)
        try:
            self._NS1Records.update(zone, domain, rec._type, **params)
        except RateLimitException as e:
            self.log.warn('_apply_Update: rate limit exceeded, slowing down')
            sleep(int(e.period) / 10)
            self._apply_Update(change)

    def _apply_Delete(self, change):
        rec = change.existing
        zone = rec.zone.name.rstrip('.')
        domain = rec.fqdn.rstrip('.')
        try:
            self._NS1Records.delete(zone, domain, rec._type)
        except RateLimitException as e:
            self.log.warn('_apply_Delete: rate limit exceeded, slowing down')
            sleep(int(e.period) / 10)
            self._apply_Delete(change)

    def _apply(self, plan):
        self.log.debug('_apply: zone=%s, len(changes)=%d', plan.desired.name,
                       len(plan.changes))
        self.loadZone(plan.desired.name, create=True)
        for change in plan.changes:
            class_name = change.__class__.__name__
            getattr(self, '_apply_{}'.format(class_name))(change)
