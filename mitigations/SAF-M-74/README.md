# SAF-M-74: Per-Invocation Capability Brokering

## Overview
**Mitigation ID**: SAF-M-74  
**Category**: Isolation and Containment  
**Effectiveness**: High  
**Implementation Complexity**: Medium  
**First Published**: 2026-06-15

## Description
Per-Invocation Capability Brokering interposes a supervisor between an MCP server and the host OS for every individual tool call. Rather than granting a tool server a static set of OS-level permissions at startup, the broker enforces a declared capability manifest on a per-call basis, specifying exactly which filesystem paths, network destinations, and syscalls a given tool is permitted to access during that invocation and no others.

The broker is implemented as an embeddable library, not a sidecar or external gateway, so it ships as a dependency of the MCP server itself with no additional infrastructure required. On Linux, filesystem access control is enforced by Linux Landlock LSM and syscall filtering by seccomp. Invocation attestation is provided via Sigstore, producing a signed, tamper-evident record of the capability set active at the time of each tool call. Credential access during tool execution uses a phantom token model: the tool receives a short-lived, single-use token scoped to the current invocation, and the underlying credential is never exposed to the tool server process.

## Mitigates
- [SAF-T1302](../../techniques/SAF-T1302/README.md): High-Privilege Tool Abuse — Landlock and seccomp enforce a per-call capability ceiling; a tool cannot reach paths or syscalls outside its declared manifest even when an agent is tricked into invoking it.
- [SAF-T1303](../../techniques/SAF-T1303/README.md): Container Sandbox Escape via Runtime Exec — does not prevent the underlying runtime vulnerability; after a boundary violation, per-invocation Landlock and seccomp profiles limit which host paths and syscalls remain reachable.
- [SAF-T1304](../../techniques/SAF-T1304/README.md): Credential Relay Chain — phantom tokens are scoped to one invocation and expire on completion, reducing the window for relaying stolen credentials to higher-privilege tools.
- [SAF-T1101](../../techniques/SAF-T1101/README.md): Command Injection — does not prevent injection; per-invocation seccomp and binary allowlists confine what an injected command can spawn or access, reducing blast radius.
- [SAF-T1111](../../techniques/SAF-T1111/README.md): AI Agent CLI Weaponization — where weaponization flows through MCP tool execution, capability manifests scope which binaries and paths are reachable per invocation; does not address postinstall scripts that invoke standalone AI CLIs outside MCP.

## Technical Implementation

### Prerequisites
- Linux kernel 5.13+ (Landlock LSM enabled; verify with `CONFIG_SECURITY_LANDLOCK=y`)
- seccomp support (standard in all major Linux distributions since kernel 3.17)
- Sigstore toolchain for attestation (cosign or equivalent)

### Capability Manifest
Each MCP server declares a capability manifest specifying the per-invocation constraints for each tool:

```yaml
tools:
  read_file:
    filesystem:
      allow_read:
        - /data/inputs
    network: none
    syscalls: default_read_only

  execute_query:
    filesystem:
      allow_read:
        - /etc/db.conf
    network:
      allow_connect:
        - 10.0.0.5:5432
    syscalls: default_network
```

### Enforcement Flow
```
MCP Host
    |
    v
nono broker (embeddable library)
    |  -- reads tool capability manifest
    |  -- applies Landlock ruleset for this invocation
    |  -- applies seccomp filter for this invocation
    |  -- issues phantom token (scoped, short-lived)
    |  -- emits Sigstore attestation record
    |
    v
Tool execution (capability-bounded)
    |
    v
nono broker
    |  -- revokes phantom token
    |  -- tears down Landlock + seccomp context
    |  -- finalizes attestation record
    v
MCP Host (returns result)
```

### Integration Examples

```rust
use nono::{Broker, CapabilityManifest};

let manifest = CapabilityManifest::from_file("nono.yaml")?;
let broker = Broker::new(manifest);

broker.execute("read_file", |ctx| {
    tool_impl(ctx)
})?;
```

```python
from nono import Broker

broker = Broker.from_manifest("nono.yaml")

with broker.invocation("read_file") as ctx:
    result = tool_impl(ctx.token)
```

```typescript
import { Broker } from '@nolabs/nono';

const broker = await Broker.fromManifest('nono.yaml');

const result = await broker.invoke('read_file', async (ctx) => {
  return toolImpl(ctx.token);
});
```

### Monitoring
Violations of the per-invocation capability manifest produce kernel-level audit events. Monitor for:
- `LANDLOCK_ACCESS_FS_*` denial events against paths outside the declared manifest
- seccomp `SECCOMP_RET_KILL` or `SECCOMP_RET_ERRNO` events for filtered syscalls
- Phantom token usage outside the declared invocation window
- Sigstore attestation gaps indicating broker bypass

## References
- [Linux Landlock LSM documentation](https://docs.kernel.org/userspace-api/landlock.html)
- [seccomp filter documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [Sigstore project](https://www.sigstore.dev/)
- [nono reference implementation](https://nono.sh)
- [Kubefence (Red Hat NRI plugin)](https://github.com/redhat-nfvpe/kubefence)
- [AgentBound formal reference (arXiv:2510.21236)](https://arxiv.org/abs/2510.21236)

## Related Mitigations
- [SAF-M-9](../SAF-M-9/README.md): Sandboxed Testing — isolates test execution from production at the environment level; complementary to per-call capability enforcement in running production servers

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-06-15 | Initial documentation | SAF-MCP Contributors |
