#!/usr/bin/env python3

import json

from ops.framework import (
    StoredState,
    EventBase,
    ObjectEvents,
    EventSource,
    Object)


class EndpointDataEvent(EventBase):
    pass


class APIEndpointsEvents(ObjectEvents):
    ep_ready = EventSource(EndpointDataEvent)


class APIEndpointsRequires(Object):

    on = APIEndpointsEvents()
    _stored = StoredState()

    def __init__(self, charm, relation_name, config_dict):
        super().__init__(charm, relation_name)
        self.config_dict = config_dict
        self.relation_name = relation_name
        self.framework.observe(
            charm.on[self.relation_name].relation_changed,
            self._on_relation_changed)

    def _on_relation_changed(self, event):
        """Handle the relation-changed event."""
        event.relation.data[self.model.unit]['endpoints'] = json.dumps(
            self.config_dict['endpoints'])

    def update_config(self, config_dict):
        """Allow for updates to relation."""
        self.config_dict = config_dict
        relation = self.model.get_relation(self.relation_name)
        if relation:
            relation.data[self.model.unit]['endpoints'] = json.dumps(
                self.config_dict['endpoints'])


class APIEndpointsProvides(Object):

    on = APIEndpointsEvents()
    _stored = StoredState()

    def __init__(self, charm):
        super().__init__(charm, "loadbalancer")
        # Observe the relation-changed hook event and bind
        # self.on_relation_changed() to handle the event.
        self.framework.observe(
            charm.on["loadbalancer"].relation_changed,
            self._on_relation_changed)
        self.charm = charm

    def _on_relation_changed(self, event):
        """Handle a change to the loadbalancer relation."""
        self.on.ep_ready.emit()
