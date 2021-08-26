# Overview

The ceph-dashboard configures the [Ceph Dashboard][ceph-dashboard-upstream].
The charm is intended to be used in conjunction with the
[ceph-mon][ceph-mon-charm] charm.

# Usage

## Configuration

See file `config.yaml` for the full list of options, along with their
descriptions and default values.

## Deployment

We are assuming a pre-existing Ceph cluster.

Deploy the ceph-dashboard as a subordinate to the ceph-mon charm.

    juju deploy ceph-dashboard
    juju relate ceph-dashboard ceph-mon

## Embedded Grafana Dashboards

To enable the embedded grafana dashboards within the Ceph dashboard
some additional relations are needed.

    juju relate ceph-dashboard:grafana-dashboard grafana:dashboards
    juju relate ceph-dashboard:prometheus prometheus:website
    juju relate ceph-mon:prometheus prometheus:target
    juju relate ceph-osd:juju-info telegraf:juju-info
    juju relate ceph-mon:juju-info telegraf:juju-info

Grafana, Telegraf and Prometheus should be related in the standard way

    juju relate grafana:grafana-source prometheus:grafana-source
    juju relate telegraf:prometheus-client prometheus:target
    juju relate telegraf:dashboards grafana:dashboards

Grafana must be using https so either supply a certificates and key via
the ssl\_\* charm config options or add a vault relation.

    juju deploy grafana:certificates vault:certificates

Grafana should be set with the following charm options:

    juju config grafana anonymous=True
    juju config grafana allow_embedding=True
    juju config grafana install_plugins="https://storage.googleapis.com/plugins-community/vonage-status-panel/release/1.0.11/vonage-status-panel-1.0.11.zip,https://storage.googleapis.com/plugins-community/grafana-piechart-panel/release/1.6.2/grafana-piechart-panel-1.6.2.zip"

Telegraf should be set with the following charm options:

    juju config telegraf hostname="{host}"

NOTE: That is "{host}" verbatim, nothing needs to be substituted.


Currently the dashboard cannot autodect the api endpoint of the grafana
service, so the end of the deployment run the following:

    juju config ceph-dashboard  grafana-api-url="https://<IP of grafana unit>:3000"

## Enabling Prometheus Alerting

To enable Prometheus alerting, add the following relations:

    juju relate ceph-dashboard:prometheus prometheus:website
    juju relate ceph-mon:prometheus prometheus:target
    juju relate ceph-dashboard:alertmanager-service prometheus-alertmanager:alertmanager-service
    juju relate prometheus:alertmanager-service prometheus-alertmanager:alertmanager-service

<!-- LINKS -->

[ceph-dashboard]: https://docs.ceph.com/en/latest/mgr/dashboard/
[ceph-mon-charm]: https://jaas.ai/ceph-mon
