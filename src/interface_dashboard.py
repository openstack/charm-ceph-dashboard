#!/usr/bin/env python3

import logging

from ops.framework import (
    StoredState,
    EventBase,
    ObjectEvents,
    EventSource,
    Object)


class MonReadyEvent(EventBase):
    pass


class CephDashboardEvents(ObjectEvents):
    mon_ready = EventSource(MonReadyEvent)


class CephDashboardRequires(Object):

    on = CephDashboardEvents()
    _stored = StoredState()
    READY_KEY = 'mon-ready'

    def __init__(self, charm, relation_name):
        super().__init__(charm, relation_name)
        self.relation_name = relation_name
        self.framework.observe(
            charm.on[relation_name].relation_changed,
            self.on_changed)

    def on_changed(self, event):
        logging.debug("CephDashboardRequires on_changed")
        for u in self.dashboard_relation.units:
            if self.dashboard_relation.data[u].get(self.READY_KEY) == 'True':
                logging.debug("Emitting mon ready")
                self.on.mon_ready.emit()

    @property
    def dashboard_relation(self):
        return self.framework.model.get_relation(self.relation_name)
