# Taso

A storage substrate for agents: every Vessel's work is a hash-chained
Chronicle, and a Vessel's sealed state can become the next Template.
The specifications the code cites are in [`docs/spec`](docs/spec/README.md).

## Supported hosts

Taso runs on **Linux without SELinux**, for example Ubuntu and Debian.

The Warden (`taso-wardend`) refuses to start on a host where SELinux is
enabled, in enforcing or permissive mode. The test is whether
`/sys/fs/selinux/enforce` exists. An empty `/sys/fs/selinux` directory
alone does not count: kernels that can run SELinux create it even when
SELinux is off.

The reason: SELinux puts a label on every file, stored as an extended
attribute (xattr). A manifest cannot describe xattrs, so it refuses every
entry that has one (P4 spec D32). On an SELinux host nothing could ever
become a Template.

Not yet supported: Amazon Linux 2023 (SELinux permissive by default),
Bottlerocket and Azure Container Linux (SELinux enforcing). Supporting
them is a later decision. It changes no stored format, because labels
are never part of a manifest.

To check a host:

```
test -e /sys/fs/selinux/enforce && echo "SELinux enabled: unsupported" || echo "no SELinux: supported"
```

## Dates in manifests

A manifest records each entry's modification time exactly as the
kernel stores it: whole seconds since 1970-01-01 (signed 64-bit) plus
nanoseconds (P4 spec D30). That covers any date, before 1970 or far
beyond 2262, so no file is ever refused for its date.

The date is a field that any program can set to anything (`touch -d`,
`tar`, `git`). It is not when Taso wrote the file. What a manifest
carries is what the filesystem stored, and filesystems have their own
limits. ext4, for example, stores dates up to the year 2446 and clamps
later ones when they are set.
