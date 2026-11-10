> 当前安装与平台入口见[一键安装](installation.md)。Windows 仅使用 `.js`；Mac 仅保留 `securecrt_bridge.py` 原生层，工具均为 JS/Rust。

# Unified Connectors

The only public MCP namespace is `connector_*`. SecureCRT, Xshell and system
OpenSSH are selected by `backend` and expose their supported capabilities in
the returned session object. The old `securecrt_*` names are no longer
registered by the server.

For the complete backend contract and Xshell setup, see
[connector architecture](connector-architecture.md).

## Screen-backed desktop session

Use `connector_list` to inspect SecureCRT or Xshell sessions, then open an
explicit session:

```json
{
  "backend": "securecrt",
  "target": "opaque-session-id-from-connector_list",
  "mode": "exec"
}
```

The Xshell backend discovers `.xsh` names below each current session's folder,
then probes those names with `SelectTabName`. Every Xshell process registers an
isolated file-IPC instance; Rust aggregates live instances and routes
attachments back to their originating process. Its `connector_list` result
reports `enumeration: "instance_registry"`; session file contents are never
read.
The `connector_list` response distinguishes the native `id` from the backend-qualified
`session_id` (`securecrt/discovered/<id>` or `xshell/discovered/<id>`).
Both are accepted as `connector_open.target` for the matching backend; an attachment
ID or another backend's discovered ID is rejected. A discovered `session_id` is valid for read-only `connector_read_screen`, `connector_get_status` and
`connector_heartbeat`: all revalidate the exact native session, but do not
create an attachment or renew an attachment lease. `connector_open` returns a
different attachment-backed `session_id` required for commands and attachment
lease renewal. It also supports `connector_exec_batch`, `connector_read_screen`,
`connector_interrupt`, `connector_acknowledge`, and `connector_close`.
Neither backend is a native PTY. The unified list result
exposes discovery as `xshell_enumeration` and reports probe counts and
per-name errors in `xshell_discovery`. Set `connector_list.backend` to query only
one backend; unavailable Xshell diagnostics are returned only for explicit
`backend="xshell"` queries.

`connector_open.mode` selects a channel: desktop backends require `exec`;
OpenSSH also supports `pty`. It is distinct from `connector_exec.mode`.
Desktop `attach_mode` selects `shared` (default), `exclusive`, or `observe`.
Observation does not require an idle prompt and cannot send commands. It is
safe to inspect a pager this way, but observation does not authorize exiting it.
After confirming an idle shell, close the observer and reopen shared/exclusive;
provide the exact `expected_prompt` for a nonstandard prompt. No automatic
upgrade, acknowledgement, key press or command retry occurs.

Updated native adapters retain discovered handles for 900 seconds of inactivity;
read-only native session checks renew that lease. SecureCRT caption changes are
display updates, not identity changes. Handles are still bound to the native
object/endpoint and bridge generation, not permanent host/user aliases. Observed
disconnects, endpoint changes or bridge restart invalidate them; Windows also
rejects index changes. Attachments retain a 600-second owner lease; use
`connector_heartbeat` during long analysis pauses. List/open/heartbeat include
`expires_in_ms` for their respective lease. Screen reads do not renew attachment
leases. Lease expiry or process restart requires list → inspect → open → use the
new attachment session_id. Never replay an uncertain command as part of recovery.
Handle suffixes are opaque: the Windows counter is shared with attachment,
screen and capture handles, so sequence gaps do not indicate session replacement.

For SecureCRT/Xshell, omitting `connector_exec.mode` defaults to `posix`:
the caller must have inspected an idle POSIX shell. Completion markers provide
the exit code and normal completion needs no idle acknowledgement. Non-POSIX
input contexts require an explicit suitable mode such as `prompt` or `snapshot`.
Explicit `snapshot` still leaves completion unknown and requires recovery.
Timeouts, lost replies and unresolved work retain their inspection and explicit
acknowledgement requirements; no command is retried automatically.
`prompt` mode requires a nonempty literal `wait_for` (up to 512 bytes, no control
characters); `expected_prompt` validates the pre-send boundary and is not a
substitute. The schema advertises this conditional requirement on `connector_exec`,
not `connector_open`. Prompt completion requires that literal in captured output,
not a leftover screen prompt. It returns `state="completed"`,
`execution_state="completed_unverified"`, `exit_code=null`: capture reached the
requested literal, but command exit is unverified. POSIX markers remain the
preferred evidence for an inspected POSIX shell; callers need not add their own.

Updated Windows bridges additionally advertise `restore_prompt` and support
`connector_restore_prompt` with explicit idle confirmation, a fresh screen
token and the original prompt. Only a completed owned capture and a blank
column-1 line permit one Enter. Unknown/active work, changed identity/width,
typed input and other owners reject. Mac/older bridges reject without input.
`connector_read_screen` accepts `full`, `context_only`, `tail_lines` and `max_bytes`;
omitting returned text never weakens the full-frame token check. Successful
tool replies include `structuredContent` as well as compatible text JSON.
Omit those projection limits to read the entire captured native frame up to
65536 UTF-8 bytes. Set `full=true` to return the entire already-captured native frame
without that projection cap; it cannot be combined with `context_only=true`,
`tail_lines` or `max_bytes`. The native protocol frame remains bounded to 262144
bytes. This is a bounded SDK frame (Xshell samples at most 50 rows),
not complete terminal scrollback. `screen_text_truncated` and omitted-byte counts
describe response projection; use `full=true` for an unprojected new sample.
Discarded scrollback cannot be recovered by requesting more bytes. Use retained
command output and `connector_read` for pagination.
Set `include_recovery_token=false` for ordinary inspection without a returned
token. Reading itself never requires acknowledgement. The default remains true
for existing recovery callers; tokens expire after 30 seconds. Successful command
responses only suggest reading another page when `next_cursor` is present.

## OpenSSH command session

Open an `exec` session with an OpenSSH Host alias or destination using
`connector_open`:

```json
{
  "backend": "openssh",
  "target": "php-test",
  "config_path": null,
  "mode": "exec"
}
```

The connector starts one long-lived `ssh -T` process and wraps each command in
unique begin/end markers. It does not perform a new handshake for every
command. Use `connector_exec` for one command,
`connector_exec_batch` for a sequential list, and
`connector_read` for additional UTF-8-byte pages.

`operation_id` is deduplicated within the daemon lifetime. A write or transport
failure after dispatch is `unknown`; never resubmit it automatically. Inspect
the original session and call `connector_acknowledge` only after confirming
that the shell is idle.

## OpenSSH PTY session

Use `connector_stream_open` (or `connector_open` with
`mode: "pty"`) for logs,
REPLs, pagers, editors and password prompts. The Windows implementation uses
the system OpenSSH client and the cross-platform PTY layer; Linux uses the
same OpenSSH client with a Unix PTY. Output is a bounded absolute-cursor ring
buffer. If bytes are not valid UTF-8, the response includes a lossy `text`
preview and a `base64` field.

`connector_stream_write` is raw terminal input. It is intentionally not parsed
as a shell command. The MCP does not store passwords or change the user's
OpenSSH authentication policy; the calling model/client owns approval and
credential handling. `connector_resize` updates the PTY dimensions
and `connector_interrupt` sends an explicit interrupt without claiming remote
termination.

## Authentication and host keys

The backend uses the user's OpenSSH configuration, Agent, ProxyJump and
known_hosts by default. `config_path` is an optional explicit `ssh_config`
path. The connector does not add `StrictHostKeyChecking=no`, store passwords,
or silently fall back to another backend. Select the backend explicitly.

## Limits and measurements

Windows SecureCRT and Xshell POSIX execution and batches optionally accept `prefer_native_log=true`
and return `capture_transport`. This uses a private temporary native log of the
same authenticated session, including command echo on disk; never opt in for
secrets. It preserves existing user logging, falls back only before send after
complete rollback, and retains original completion/no-replay checks. Other
platforms/modes retain their existing path. SecureCRT uses raw UTF-8; Xshell inherits
its configured log format and supports BOM-tagged UTF-16. See [capture usage](agent-usage.en.md).

Command output is retained up to the configured bounded cache and returned in
pages of at most 64KiB. PTY streams retain a bounded rolling tail and report a
cursor gap when a slow reader falls behind. `connector_metrics` reports active
sessions, completed/unknown counts, retained bytes and native read counts.
Each completed or unknown command also exposes `timing.queue_wait_us`,
`timing.first_byte_us`, `timing.completion_us`, `timing.native_read_count`,
`timing.output_bytes` and `timing.throughput_bps`. Use the benchmark harness to compare
OpenSSH connector latency and throughput with a direct `ssh` command on the
same host; SecureCRT screen reads and OpenSSH PTY reads are reported as
separate backends.

OpenSSH retains at most 32 finished command results of 1MiB each, 128 sessions,
and 4096 operation fingerprints per process. Old output can expire without
removing its operation receipt: resubmitting that operation refuses replay.
At the operation limit, inspect and finish existing work before restarting the
process. An unterminated native output line is read in bounded chunks; timeout
keeps the received partial output. A queued command rechecks the unresolved
interlock while holding the session lock, before any write.
