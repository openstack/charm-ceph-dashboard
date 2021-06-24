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


<!-- LINKS -->

[ceph-dashboard]: https://docs.ceph.com/en/latest/mgr/dashboard/
[ceph-mon-charm]: https://jaas.ai/ceph-mon
