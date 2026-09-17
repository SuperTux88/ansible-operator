# Targeting external hosts

A `StaticInventory` targets hosts you name **literally** — hostnames or IPs — and reaches them over
ordinary SSH with a key **you supply**. Use it for anything that is not a Node of this cluster:
external servers, IoT and edge appliances, network gear, or the nodes of a different cluster.

Unlike a `ClusterInventory`, there is no managed-SSH proxy, no node-root elevation, and no
`NodeAccessPolicy` gating. The operator connects out as whatever user your key authorizes.

## Defining hosts

`spec.hosts` is a list of groups; each group has a `name` and a literal `hosts` list. The group name
becomes an Ansible group your playbook can target.

```yaml
apiVersion: ansible.cloudbending.dev/v1beta1
kind: StaticInventory
metadata:
  name: edge-appliances
spec:
  hosts:
    - name: webservers
      hosts:
        - server1.example.com
        - server2.example.com
        - 192.168.73.42
  ssh:
    user: root
    secretRef:
      name: ssh-key
```

## Group variables

Each group may carry a `variables` map, rendered as Ansible **group vars** for every host in the
group. Use it to pin facts the playbook author should not need to know — for example
`ansible_python_interpreter`, so playbooks don't have to guess where Python lives on your appliances:

```yaml
spec:
  hosts:
    - name: webservers
      hosts:
        - server1.example.com
      variables:
        ansible_python_interpreter: /usr/bin/python3
```

Group variables are part of a plan's execution hash, so changing one re-applies the playbook on the
next run. The connection variables the operator manages — `ansible_user`, the `ansible_ssh_*`
options, `ansible_host`, and `ansible_port` — are rejected: they come from the `ssh` block below, and
a plan that references an inventory setting one does not run until you remove it.

## SSH credentials

`spec.ssh` is mandatory — a `StaticInventory` with no way to reach its hosts is not usable:

- `ssh.user` — the SSH login user (`ansible_user`).
- `ssh.secretRef.name` — a Kubernetes Secret **in the same namespace** holding the private key.

The referenced Secret is mounted read-only into the run and its keys are used as files:

- **`id_rsa`** (required) — the SSH **private key** to authenticate with. Despite the name it may be
  any key type OpenSSH accepts, e.g. Ed25519.
- **`known_hosts`** (optional) — an OpenSSH `known_hosts` file used to verify the hosts. Provide it
  to pin host keys; without it, host-key verification follows your image's SSH defaults.

Create the key Secret before the run, for example:

```sh
kubectl create secret generic ssh-key \
  --namespace my-team \
  --from-file=id_rsa=./id_ed25519 \
  --from-file=known_hosts=./known_hosts
```

Because the key lives in a Secret in the plan's namespace, changing it re-triggers affected plans
(the operator watches referenced Secrets), and rotating a key is just updating the Secret.

## Multiple inventories, multiple credentials

A single `PlaybookPlan` can reference several `StaticInventory`s, each with its **own** `ssh` block
and key Secret; they are mounted at distinct paths and do not collide. You can also mix
`StaticInventory` and `ClusterInventory` references in one plan; external hosts and cluster Nodes then
appear in the same rendered inventory and are applied by the same Job.

**One name, one machine.** Within a plan, an external host may not share a name with a cluster Node
the same plan reaches. Everything about a host is keyed by its name — its lock, its recorded outcome,
its connection variables — so a name meaning two machines would give one of them an outcome the other
earned. The operator refuses such a plan before it runs anything and says which host and which two
groups; see
[the plan's inputs cannot be read](./results-and-troubleshooting.md#the-plans-inputs-cannot-be-read).
The names only have to be unique within one plan. Renaming the external host is not a way out on its
own, though: the operator renders no `ansible_host` for a `StaticInventory` host and the group's
`variables` may not supply one, so the name is what Ansible dials. Narrow one of the two inventories
instead, until the plan no longer reaches both.

## Dependencies between plans are cluster-Nodes only

The [`spec.provides`](./playbook-plans.md#declaring-what-a-plan-provides) mechanism — a plan
publishing what it has finished so other plans can wait for it — works by labelling **Node objects**,
so it does not extend to `StaticInventory` hosts. An external machine has no Kubernetes object to
carry the label.

That cuts both ways. A plan whose hosts are external can still set `provides`, but nothing is
published for those hosts (if the plan also targets cluster Nodes, those are labelled as usual). And
a dependent plan's `StaticInventory` groups are unaffected by dependency labels: they use no
selectors at all, so their hosts are always in the run. Order work on external machines within a
single playbook instead, or across plans by hand.

## What you do not set

As with cluster nodes, the operator renders `ansible_user`, `ansible_ssh_private_key_file`, and the
host-key options into the inventory for you from the `ssh` block. Do not set these in your playbook —
target `hosts: <group>` (or `all`) and let the operator wire up the connection.
