# libPyElk

A lightweight Python library for managing Elasticsearch operations with ease.

libPyElk wraps the official Elasticsearch Python client to connect securely to a cluster configured with [libPyConfiguration](https://github.com/erickrr-bd/libPyConfiguration), run the searches used by alerting tools (query string, time ranges, aggregations), manage snapshots, repositories and indexes, and validate the integrity of documents.

**Version:** 2.5 - November 2026
**Author:** Erick Roberto Rodriguez Rodriguez ([erodriguez@tekium.mx](mailto:erodriguez@tekium.mx), [erickrr.tbd93@gmail.com](mailto:erickrr.tbd93@gmail.com))

---

## Features

- **Secure connections:** TLS certificates are always verified (custom CA or certifi's public CAs). Disabling verification requires an explicit `insecure = True`.
- **Encrypted credentials:** HTTP Authentication and API Key are decrypted with their context (`<context>:<field>`) and the passphrase is wiped from memory right after.
- **HTTPS enforced:** authentication over plain HTTP is rejected.
- **Compatible with strict X.509 checks (Python >= 3.13):** `relax_x509_strict` accepts a CA without RFC 5280 extensions while still verifying the chain of trust and the hostname.
- **Efficient searches:** filter context (no scoring, cacheable), newest events first, exact total count (`track_total_hits`).
- **Safe destructive operations:** index and snapshot names are validated, so wildcards (`*`, `logs-*`, `a,b`) are never deleted by mistake.
- **Lightweight integrity checks:** `scan` with `_source` disabled (only metadata is transferred) and the scroll always cleared.
- **Clear errors:** API and network errors are raised as `RuntimeError` / `ConnectionError` with the original exception in `__cause__`.
- No terminal interface dependencies: it can be used in daemons and services.

## Requirements

- Python 3.12 or later.
- Python libraries:

| Library | Version |
|---|---|
| [elasticsearch](https://pypi.org/project/elasticsearch/) | >= 8.18.0 (includes `elasticsearch.dsl`) |
| [libPyUtils](https://github.com/erickrr-bd/libPyUtils) | >= 2.4.0 |
| [libPyConfiguration](https://github.com/erickrr-bd/libPyConfiguration) | >= 1.3.0 (only to build the configuration object) |

> **The client's major version must match the cluster's.** An Elasticsearch 8 cluster rejects the 9.x client (`media_type_header_exception ... compatible-with=9`). Pin the version in your application:
>
> | Cluster | Client |
> |---|---|
> | 8.x | `elasticsearch>=8.18.0,<9.0.0` |
> | 9.x | `elasticsearch>=9.0.0,<10.0.0` |
>
> The `elasticsearch-dsl` package is no longer needed (and conflicts with the 9.x client): since 8.18.0 the DSL is part of the client as `elasticsearch.dsl`.

## Installation

With pip:

```bash
pip install git+https://github.com/erickrr-bd/libPyElk.git
```

With Poetry (pinning the client for an 8.x cluster):

```toml
[tool.poetry.dependencies]
elasticsearch = "^8.18.0"
libPyElk = { git = "https://github.com/erickrr-bd/libPyElk.git" }
```

## Usage

### Connection

```python
from libPyElk import libPyElk
from libPyUtils import libPyUtils
from libPyConfiguration import libPyConfiguration

utils = libPyUtils()
configuration = libPyConfiguration.__new__(libPyConfiguration)	# No terminal interface needed in a service.
configuration.convert_dict_to_object(utils.read_yaml_file("/opt/My-App/configuration/my_app.yaml"))

elk = libPyElk()
conn_es = elk.create_connection(configuration, "/opt/My-App/configuration/key", context = "my_app", owner = "my_app")
print(conn_es.info()["version"]["number"])
```

`create_connection` uses the authentication method of the configuration (none, HTTP Authentication or API Key). Create the connection **once** and reuse it: the client is thread-safe and has its own connection pool.

| Parameter | Default | Description |
|---|---|---|
| `context` | | Encryption context used by libPyConfiguration (e.g. `"my_app"`). |
| `owner` | `None` | User expected to own the key file. |
| `insecure` | `False` | `True` disables certificate verification. Avoid it: it allows man-in-the-middle attacks. |
| `allow_legacy` | `False` | `True` decrypts credentials encrypted by libPyConfiguration < 1.3 (migration only). |
| `relax_x509_strict` | `False` | `True` accepts a custom CA without RFC 5280 extensions (e.g. *"CA cert does not include key usage extension"*). The chain of trust and the hostname are still verified. |

Request timeout: 30 s, 3 retries (`libPyElk.REQUEST_TIMEOUT`, `libPyElk.MAX_RETRIES`).

### Search with query string

```python
gte = utils.get_gte_date("minutes", 5)	# "now-5m/m"
lte = utils.get_lte_date("minutes")		# "now/m"

result = elk.search_query_string(conn_es, "winlogbeat-*", "event.code: 4625", "@timestamp", gte, lte, True, size = 50, fields = ["host.name", "user.name", "source.ip"])
total = result.hits.total.value		# Exact number of matches.
for hit in result:					# At most "size" documents, newest first.
	print(hit.meta.id, elk.convert_data_to_str(hit))
```

Compare thresholds against `result.hits.total.value`, not `len(result)`: the result only contains up to `size` documents.

`convert_data_to_str` converts a document (any depth) into one line per field:

```
☑️ host.name = DC01
☑️ user.name = admin
☑️ winlog.event_data.LogonType = 3
```

### Aggregations

```python
# Count of events per user (only the aggregation, no documents).
result = elk.search_query_string_aggregation(conn_es, "winlogbeat-*", "event.code: 4625", "@timestamp", gte, lte, "user.name", False)
for bucket in result.aggregations.events.buckets:
	print(bucket.key, bucket.doc_count)
```

### Snapshots, repositories and indexes

```python
elk.create_repository(conn_es, "backups", "/mnt/backups", compress_repository = True)
elk.create_snapshot(conn_es, "winlogbeat-2026.11.24", "backups")
print(elk.get_snapshot_current_status(conn_es, "winlogbeat-2026.11.24", "backups"))	# SUCCESS, IN_PROGRESS, ... or NOT FOUND
elk.delete_index(conn_es, "winlogbeat-2026.11.24")		# Exact name only: "winlogbeat-*" raises ValueError.
elk.mount_searchable_snapshot(conn_es, "winlogbeat-2026.11.24", "backups")
```

### Integrity validation

```python
# Documents whose version is greater than 1 (modified after being indexed).
altered = elk.validate_index_pattern_integrity(conn_es, "winlogbeat-*", "@timestamp", "now-1d/d", "now/d")
for index, document_id, version in altered:
	print(index, document_id, version)
```

### Error handling

```python
try:
	elk.delete_snapshot(conn_es, "snap-1", "backups")
except ValueError as exception:			# Invalid name (wildcards, uppercase, commas...).
	print(exception)
except RuntimeError as exception:		# Elasticsearch API error (404, 403, ...).
	print(exception, exception.__cause__.status_code)
except ConnectionError as exception:	# Network failure (timeout, TLS, DNS...).
	print(exception)
```

## API

| Method | Description |
|---|---|
| `create_connection(configuration, key_file, context, owner = None, insecure = False, allow_legacy = False, relax_x509_strict = False)` | Connection using the configuration's authentication method. |
| `create_connection_without_auth(...)`, `create_connection_http_auth(...)`, `create_connection_api_key(...)` | Kept for backwards compatibility. |
| `search_query_string(conn_es, index_pattern, query_string, timestamp_field, gte, lte, use_fields, size = 50, fields = [...])` | Query string search, newest first, exact total. |
| `search_query_string_aggregation(..., field_name, use_fields, size = 0, buckets = 1000)` | Query string search with a `terms` aggregation (`events`). |
| `search_aggregation(conn_es, index_pattern, timestamp_field, field_name, gte, lte, buckets = 999)` | `terms` aggregation in a time range. |
| `search_multiple_aggregation(..., field_name, field_name_two, ..., buckets = 999)` | `terms` aggregation with a `top_hits` sub-aggregation (`events_two`). |
| `convert_data_to_str(hit)` | Document converted into text (`a.b.c = value`). |
| `add_new_document(conn_es, index_name, data)` | Indexes a document. |
| `create_snapshot`, `delete_snapshot`, `restore_snapshot`, `mount_searchable_snapshot` | Snapshot operations (exact names). |
| `get_snapshot_info`, `get_snapshot_current_status`, `get_snapshots_by_repository` | Snapshot information (lightweight listing). |
| `create_repository`, `delete_repository`, `get_repositories` | Shared file system repositories. |
| `delete_index`, `get_indexes` | Indexes (system indexes excluded from the listing). |
| `get_nodes_information(conn_es)` | File system statistics of the nodes. |
| `validate_index_integrity(conn_es, index_name)`, `validate_index_pattern_integrity(...)` | Documents with `_version` > 1. |

## Migrating from 2.4

- **Credentials:** they are decrypted with context, as libPyConfiguration 1.3.0 encrypts them. Pass `context` (and `allow_legacy = True` while migrating old files).
- **TLS:** without a custom CA, certificates are now verified against certifi's public CAs (before, verification was disabled). Load the cluster's CA with your configuration tool, or use `insecure = True` explicitly.
- **DSL:** `elasticsearch_dsl` was replaced by `elasticsearch.dsl`. Uninstall `elasticsearch-dsl`.
- **Searches:** `search_query_string` returns 50 documents by default (`size`) instead of 10,000, sorted newest first. Use `result.hits.total.value` for the total.
- **Aggregations:** `search_query_string_aggregation` now really returns the `events` aggregation (it was added to a copy of the search and never executed).
- **Names:** `delete_index` and the snapshot operations reject wildcards and non-exact names (`ValueError`).
- **Errors:** messages now describe the right action, and the original exception is kept in `__cause__`.

## Changelog

### 2.5 - November 2026
- Single `create_connection` with context-bound decryption, HTTPS required for authentication and certificates always verified.
- `relax_x509_strict` option for CAs without RFC 5280 extensions (Python >= 3.13).
- Searches in filter context, sorted newest first, with exact total and configurable size.
- Fixed: aggregation never executed in `search_query_string_aggregation`.
- `convert_data_to_str` rewritten (any depth; fixed the 4th level printing the parent object).
- Integrity validation with `scan`, without `_source` and without threads; the scroll is always cleared.
- Lightweight listings: `cat.indices` for indexes, `verbose = False` for snapshots.
- Name validation in destructive operations and unified error handling.
- `elasticsearch.dsl` instead of `elasticsearch-dsl`; libPyConfiguration is no longer imported at runtime.
