#!/usr/bin/env python3

# Copyright 2021 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import json
import unittest
import sys
sys.path.append('lib')  # noqa
sys.path.append('src')  # noqa
from ops.testing import Harness
from ops.charm import CharmBase
import interface_api_endpoints


class TestAPIEndpointsRequires(unittest.TestCase):

    class MyCharm(CharmBase):

        def __init__(self, *args):
            super().__init__(*args)
            self.seen_events = []
            self.ingress = interface_api_endpoints.APIEndpointsRequires(
                self,
                'loadbalancer',
                {
                    'endpoints': [{
                        'service-type': 'ceph-dashboard',
                        'frontend-port': 8443,
                        'backend-port': 8443,
                        'backend-ip': '10.0.0.10',
                        'check-type': 'httpd'}]})

    def setUp(self):
        super().setUp()
        self.harness = Harness(
            self.MyCharm,
            meta='''
name: my-charm
requires:
  loadbalancer:
    interface: api-endpoints
'''
        )
        self.eps = [{
            'service-type': 'ceph-dashboard',
            'frontend-port': 8443,
            'backend-port': 8443,
            'backend-ip': '10.0.0.10',
            'check-type': 'httpd'}]

    def add_loadbalancer_relation(self):
        rel_id = self.harness.add_relation(
            'loadbalancer',
            'service-loadbalancer')
        self.harness.add_relation_unit(
            rel_id,
            'service-loadbalancer/0')
        self.harness.update_relation_data(
            rel_id,
            'service-loadbalancer/0',
            {'ingress-address': '10.0.0.3'})
        return rel_id

    def test_init(self):
        self.harness.begin()
        self.assertEqual(
            self.harness.charm.ingress.config_dict,
            {'endpoints': self.eps})
        self.assertEqual(
            self.harness.charm.ingress.relation_name,
            'loadbalancer')

    def test__on_relation_changed(self):
        self.harness.begin()
        rel_id = self.add_loadbalancer_relation()
        rel_data = self.harness.get_relation_data(
            rel_id,
            'my-charm/0')
        self.assertEqual(
            rel_data['endpoints'],
            json.dumps(self.eps))

    def test_update_config(self):
        self.harness.begin()
        rel_id = self.add_loadbalancer_relation()
        new_eps = copy.deepcopy(self.eps)
        new_eps.append({
            'service-type': 'ceph-dashboard',
            'frontend-port': 9443,
            'backend-port': 9443,
            'backend-ip': '10.0.0.10',
            'check-type': 'https'})
        self.harness.charm.ingress.update_config(
            {'endpoints': new_eps})
        rel_data = self.harness.get_relation_data(
            rel_id,
            'my-charm/0')
        self.assertEqual(
            rel_data['endpoints'],
            json.dumps(new_eps))


class TestAPIEndpointsProvides(unittest.TestCase):

    class MyCharm(CharmBase):

        def __init__(self, *args):
            super().__init__(*args)
            self.seen_events = []
            self.api_eps = interface_api_endpoints.APIEndpointsProvides(self)
            self.framework.observe(
                self.api_eps.on.ep_ready,
                self._log_event)

        def _log_event(self, event):
            self.seen_events.append(type(event).__name__)

    def setUp(self):
        super().setUp()
        self.harness = Harness(
            self.MyCharm,
            meta='''
name: my-charm
provides:
  loadbalancer:
    interface: api-endpoints
'''
        )

    def test_on_changed(self):
        self.harness.begin()
        # No MonReadyEvent as relation is absent
        self.assertEqual(
            self.harness.charm.seen_events,
            [])
        rel_id = self.harness.add_relation('loadbalancer', 'ceph-dashboard')
        self.harness.add_relation_unit(
            rel_id,
            'ceph-dashboard/0')
        self.harness.update_relation_data(
            rel_id,
            'ceph-dashboard/0',
            {'ingress-address': '10.0.0.3'})
        self.assertEqual(
            self.harness.charm.seen_events,
            ['EndpointDataEvent'])
