#
#
#

from __future__ import absolute_import, division, print_function, \
    unicode_literals

from logging import getLogger
from collections import OrderedDict, defaultdict
from ns1 import NS1
from ns1.records import Record as NS1Record
from ns1.rest.errors import RateLimitException, ResourceException
from incf.countryutils import transformations
from time import sleep

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
    SUPPORTS = set(('A', 'AAAA', 'ALIAS', 'CAA', 'CNAME', 'MX', 'NAPTR',
                    'NS', 'PTR', 'SPF', 'SRV', 'TXT'))

    ZONE_NOT_FOUND_MESSAGE = 'server error: zone not found'

    def __init__(self, id, api_key, *args, **kwargs):
        self.log = getLogger('Ns1Provider[{}]'.format(id))
        self.log.debug('__init__: id=%s, api_key=***', id)
        super(Ns1Provider, self).__init__(id, *args, **kwargs)
        self._NS1 = NS1(apiKey=api_key)
        self._zone_cache = {}
        self._record_cache = {}

    def loadZone(self, zone, create=False):
        zone = zone.rstrip('.')
        if zone not in self._zone_cache:
            try:
                self._zone_cache[zone] = self._NS1.loadZone(zone)
            except ResourceException as e:
                if e.message != self.ZONE_NOT_FOUND_MESSAGE:
                    raise
                if create:
                    self.log.debug('loadZone: creating zone %s', zone)
                    self._zone_cache[zone] = self._NS1.createZone(zone)
        return self._zone_cache.get(zone)

    def loadRecord(self, domain, _type, zone):
        domain = domain.rstrip('.')
        zone = zone.rstrip('.')
        self.log.debug('loadRecord(%s, %s, %s)', domain, _type, zone)
        rec = (domain, _type, zone)
        if rec not in self._record_cache:
            self._record_cache[rec] = self._NS1.loadRecord(*rec)
        return self._record_cache.get(rec)

    def _data_for_A(self, _type, record):
        # record meta (which would include geo information) is only
        # returned when getting a record's detail, not from zone detail
        geo = defaultdict(list)
        data = {
            'ttl': record['ttl'],
            'type': _type,
        }
        values, codes = [], []
        if 'answers' not in record:
            values = record['short_answers']
        for answer in record.get('answers', []):
            meta = answer.get('meta', {})
            if meta:
                # country + state and country + province are allowed
                # in that case though, supplying a state/province would
                # be redundant since the country would supercede in when
                # resolving the record.  it is syntactically valid, however.
                country = meta.get('country', [])
                us_state = meta.get('us_state', [])
                ca_province = meta.get('ca_province', [])
                for cntry in country:
                    cn = transformations.cc_to_cn(cntry)
                    con = transformations.cn_to_ctca2(cn)
                    key = '{}-{}'.format(con, cntry)
                    geo[key].extend(answer['answer'])
                for state in us_state:
                    key = 'NA-US-{}'.format(state)
                    geo[key].extend(answer['answer'])
                for province in ca_province:
                    key = 'NA-CA-{}'.format(province)
                    geo[key].extend(answer['answer'])
                for code in meta.get('iso_region_code', []):
                    key = code
                    geo[key].extend(answer['answer'])
            else:
                values.extend(answer['answer'])
                codes.append([])
        values = [unicode(x) for x in values]
        geo = OrderedDict(
            {unicode(k): [unicode(x) for x in v] for k, v in geo.items()}
        )
        data['values'] = values
        data['geo'] = geo
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
        for record in ns1_zone.data['records']:
            _type = record['type']
            if _type not in self.SUPPORTS:
                continue
            count += 1
            if _type in ['ALIAS', 'CNAME', 'MX', 'NS', 'PTR', 'SRV']:
                for i, a in enumerate(record['short_answers']):
                    record['short_answers'][i] = self.ensure_fqdn(a)
            if record['tier'] != 1:
                r = self.loadRecord(record['domain'], _type, ns1_zone.zone)
                record = r.data
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
                key = 'iso_region_code'
                value = iso_region
                if not has_country and \
                   len(value.split('-')) > 1:  # pragma: nocover
                    has_country = True
                for answer in target.values:
                    params['answers'].append(
                        {
                            'answer': [answer],
                            'meta': {key: [value]},
                        },
                    )
            params['filters'] = []
            if has_country:
                params['filters'].append(
                    {"filter": "shuffle", "config": {}}
                )
                params['filters'].append(
                    {"filter": "geotarget_country", "config": {}}
                )
                params['filters'].append(
                    {"filter": "select_first_n",
                     "config": {"N": 1}}
                )
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

    def _get_name(self, record):
        return record.fqdn[:-1] if record.name == '' else record.name

    def _apply_Create(self, ns1_zone, change):
        new = change.new
        name = self._get_name(new)
        _type = new._type
        params = getattr(self, '_params_for_{}'.format(_type))(new)
        meth = getattr(ns1_zone, 'add_{}'.format(_type))
        try:
            meth(name, **params)
        except RateLimitException as e:
            self.log.warn('_apply_Create: rate limit exceeded, slowing down')
            sleep(e.period / 10)
            self._apply_Create(ns1_zone, change)

    def _apply_Update(self, ns1_zone, change):
        existing = change.existing
        name = self._get_name(existing)
        _type = existing._type
        record = NS1Record(self.loadZone(ns1_zone.zone), name, _type)
        record.data = True
        new = change.new
        params = getattr(self, '_params_for_{}'.format(_type))(new)
        try:
            record.update(**params)
        except RateLimitException as e:
            self.log.warn('_apply_Update: rate limit exceeded, slowing down')
            sleep(e.period / 10)
            self._apply_Update(ns1_zone, change)

    def _apply_Delete(self, ns1_zone, change):
        existing = change.existing
        name = self._get_name(existing)
        _type = existing._type
        record = self.loadRecord(name, _type, ns1_zone.zone)
        try:
            record.delete()
        except RateLimitException as e:
            self.log.warn('_apply_Delete: rate limit exceeded, slowing down')
            sleep(e.period / 10)
            self._apply_Delete(ns1_zone, change)

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug('_apply: zone=%s, len(changes)=%d', desired.name,
                       len(changes))

        domain_name = desired.name[:-1]
        ns1_zone = self.loadZone(domain_name, True)

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, '_apply_{}'.format(class_name))(ns1_zone,
                                                          change)
