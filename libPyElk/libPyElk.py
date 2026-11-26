"""
Author: Erick Roberto Rodriguez Rodriguez
Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com
GitHub: https://github.com/erickrr-bd/libPyElk
libPyElk v2.5 - November 2026
A lightweight Python library for managing Elasticsearch operations with ease.
Requires elasticsearch >= 8.18 (DSL included as elasticsearch.dsl), libPyUtils >= 2.4.0 and libPyConfiguration >= 1.3.0.
"""
from __future__ import annotations

import re
import ssl
from typing import TYPE_CHECKING
from contextlib import contextmanager
from libPyUtils import libPyUtils
from elasticsearch.dsl import Search, A
from elasticsearch.helpers import scan
from elasticsearch import Elasticsearch, ApiError, TransportError

if TYPE_CHECKING:
	# Only needed for type hints: the service doesn't load libPyDialog/pythondialog.
	from libPyConfiguration import libPyConfiguration

# Exact names of indexes and snapshots (no wildcards, commas or uppercase).
NAME_REGEX = re.compile(r"^[a-z0-9][a-z0-9._+-]*$")

# Prefix of every line of a document converted to text.
CHECK = "☑️"

HTTP_AUTH = "HTTP Authentication"
API_KEY = "API Key"


class libPyElk:

	REQUEST_TIMEOUT = 30
	MAX_RETRIES = 3

	def __init__(self) -> None:
		"""
		Class constructor.
		"""
		self.utils = libPyUtils()


	# --- Internal helpers ----------------------------------------------------------------------
	@contextmanager
	def _es_errors(self, action: str):
		"""
		Context manager that converts Elasticsearch errors into RuntimeError/ConnectionError (keeping the cause).
		"""
		try:
			yield
		except ApiError as api_error:
			raise RuntimeError(f"Elasticsearch API error {action}: {api_error.message} (Status: {api_error.status_code})") from api_error
		except TransportError as trans_error:
			raise ConnectionError(f"Network transport failure {action}: {trans_error}") from trans_error


	@staticmethod
	def _validate_name(name: str, kind: str) -> None:
		"""
		Method that validates an exact index/snapshot name, so a destructive operation never receives a wildcard.
		"""
		if not isinstance(name, str) or not NAME_REGEX.fullmatch(name) or len(name.encode("utf-8")) > 255:
			raise ValueError(f"Invalid {kind} name: {name!r}")


	def _decrypt_pair(self, configuration: libPyConfiguration, fields: tuple, key_file: str, context: str, owner: str = None, allow_legacy: bool = False) -> tuple:
		"""
		Method that decrypts two credentials. The passphrase is wiped from memory afterwards.
		"""
		passphrase = self.utils.get_passphrase(key_file, owner = owner)
		try:
			return tuple(self.utils.decrypt_data(getattr(configuration, field), passphrase, allow_legacy = allow_legacy, context = f"{context}:{field}") for field in fields)
		finally:
			self.utils.zeroize(passphrase)


	def _connection_options(self, configuration: libPyConfiguration, insecure: bool = False, relax_x509_strict: bool = False) -> dict:
		"""
		Method that builds the connection options. Certificates are always verified (custom CA if configured,
		certifi's public CAs otherwise) unless insecure is explicitly True.

		relax_x509_strict: Python >= 3.13 rejects CA certificates that don't fully follow RFC 5280 (for example,
		without the Key Usage extension). If True, only that strict check is disabled: the chain of trust and the
		hostname are still verified. Use it only when the CA can't be regenerated.
		"""
		options = {"hosts": configuration.es_host, "request_timeout": self.REQUEST_TIMEOUT, "max_retries": self.MAX_RETRIES, "retry_on_timeout": True}
		if insecure:
			options["verify_certs"] = False
		elif configuration.verificate_certificate_ssl and configuration.certificate_file and relax_x509_strict:
			# ssl_context replaces verify_certs/ca_certs (they can't be combined).
			ssl_context = ssl.create_default_context(cafile = configuration.certificate_file)
			ssl_context.verify_flags &= ~ssl.VERIFY_X509_STRICT
			options["ssl_context"] = ssl_context
		else:
			options["verify_certs"] = True
			if configuration.verificate_certificate_ssl and configuration.certificate_file:
				options["ca_certs"] = configuration.certificate_file
		return options


	def _require_https(self, configuration: libPyConfiguration) -> None:
		if not self.utils.validate_https_urls(configuration.es_host):
			raise ValueError("Authentication requires all ElasticSearch hosts to use HTTPS.")


	def _base_search(self, conn_es: Elasticsearch, index_pattern: str, query_string: str, timestamp_field: str, gte: str, lte: str) -> Search:
		"""
		Method that builds a search in filter context (no scoring, cacheable) with query string and time range.
		"""
		return (Search(using = conn_es, index = index_pattern)
			.filter("query_string", query = query_string)
			.filter("range", **{timestamp_field: {"gte": gte, "lte": lte}}))


	def _altered_documents(self, conn_es: Elasticsearch, index: str, query: dict) -> list:
		"""
		Method that returns the documents whose version is greater than 1. Only metadata is transferred
		(_source disabled) and the scroll is always cleared, even if an error occurs.
		"""
		body = {"query": query, "version": True, "_source": False}
		return [(hit["_index"], hit["_id"], hit["_version"])
			for hit in scan(conn_es, index = index, query = body, size = 5000, scroll = "2m")
			if hit["_version"] > 1]


	# --- Connection ----------------------------------------------------------------------------
	def create_connection(self, configuration: libPyConfiguration, key_file: str, context: str, owner: str = None, insecure: bool = False, allow_legacy: bool = False, relax_x509_strict: bool = False) -> Elasticsearch:
		"""
		Method that creates a connection to ElasticSearch using the authentication method of the configuration.
		Create it once and reuse it: the client is thread-safe and has its own connection pool.

		Parameters:
			configuration (libPyConfiguration): libPyConfiguration's Object.
			key_file (str): Key file path.
			context (str): Encryption context used by libPyConfiguration (e.g. "telk_alert").
			owner (str): User expected to own the key file.
			insecure (bool): If True, certificates are NOT verified (avoid it; it allows man-in-the-middle attacks).
			allow_legacy (bool): If True, secrets encrypted by libPyConfiguration < 1.3 can be decrypted (migration only).
			relax_x509_strict (bool): If True, accepts a custom CA that doesn't fully follow RFC 5280 (e.g. without Key Usage). Chain and hostname are still verified.

		Returns:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
		"""
		options = self._connection_options(configuration, insecure, relax_x509_strict)
		if configuration.use_authentication:
			self._require_https(configuration)
			if configuration.authentication_method == HTTP_AUTH:
				options["basic_auth"] = self._decrypt_pair(configuration, ("http_authentication_user", "http_authentication_password"), key_file, context, owner, allow_legacy)
			elif configuration.authentication_method == API_KEY:
				options["api_key"] = self._decrypt_pair(configuration, ("api_key_id", "api_key"), key_file, context, owner, allow_legacy)
			else:
				raise ValueError(f"Invalid authentication method: {configuration.authentication_method!r}")
		return Elasticsearch(**options)


	def create_connection_without_auth(self, configuration: libPyConfiguration, insecure: bool = False, relax_x509_strict: bool = False) -> Elasticsearch:
		"""
		Method that creates a connection to ElasticSearch without authentication (kept for backwards compatibility).
		"""
		return Elasticsearch(**self._connection_options(configuration, insecure, relax_x509_strict))


	def create_connection_http_auth(self, configuration: libPyConfiguration, key_file: str, context: str = "telk_alert", owner: str = None, insecure: bool = False, relax_x509_strict: bool = False) -> Elasticsearch:
		"""
		Method that creates a connection to ElasticSearch using HTTP authentication (kept for backwards compatibility).
		"""
		self._require_https(configuration)
		options = self._connection_options(configuration, insecure, relax_x509_strict)
		options["basic_auth"] = self._decrypt_pair(configuration, ("http_authentication_user", "http_authentication_password"), key_file, context, owner)
		return Elasticsearch(**options)


	def create_connection_api_key(self, configuration: libPyConfiguration, key_file: str, context: str = "telk_alert", owner: str = None, insecure: bool = False, relax_x509_strict: bool = False) -> Elasticsearch:
		"""
		Method that creates a connection to ElasticSearch using API Key (kept for backwards compatibility).
		"""
		self._require_https(configuration)
		options = self._connection_options(configuration, insecure, relax_x509_strict)
		options["api_key"] = self._decrypt_pair(configuration, ("api_key_id", "api_key"), key_file, context, owner)
		return Elasticsearch(**options)


	# --- Searches ------------------------------------------------------------------------------
	def search_query_string(self, conn_es: Elasticsearch, index_pattern: str, query_string: str, timestamp_field: str, gte: str, lte: str, use_fields: bool, size: int = 50, **kwargs):
		"""
		Method that searches data in ElasticSearch using query string.
		The exact number of matches is in result.hits.total.value (compare total_events against it, not len(result)).
		The documents are sorted by timestamp_field, newest first.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			index_pattern (str): Index or index pattern where the search will be performed.
			query_string (str): Query string to be used for the search.
			timestamp_field (str): Field's name that corresponds to the index timestamp.
			gte (str): Greater than or equal to the defined range.
			lte (str): Less than or equal to the defined range.
			use_fields (bool): If true, it limits the search result to specific fields, otherwise it returns all the fields in the document.
			size (int): Maximum number of documents returned.

		Keyword Args:
			fields (list): List with field's names.

		Returns:
			result: Search result.
		"""
		# Newest events first: when there are more matches than "size", the most recent ones are returned.
		search = self._base_search(conn_es, index_pattern, query_string, timestamp_field, gte, lte).sort({timestamp_field: {"order": "desc"}}).extra(track_total_hits = True)[0:size]
		if use_fields:
			search = search.source(kwargs["fields"])
		return search.execute()


	def search_query_string_aggregation(self, conn_es: Elasticsearch, index_pattern: str, query_string: str, timestamp_field: str, gte: str, lte: str, field_name: str, use_fields: bool, size: int = 0, buckets: int = 1000, **kwargs):
		"""
		Method that searches data in ElasticSearch using query string and a terms aggregation ("events").

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			index_pattern (str): Index or index pattern where the search will be performed.
			query_string (str): Query string to be used for the search.
			timestamp_field (str): Field's name that corresponds to the index timestamp.
			gte (str): Greater than or equal to the defined range.
			lte (str): Less than or equal to the defined range.
			field_name (str): Field's name to be used for the aggregation.
			use_fields (bool): If true, it limits the returned documents to specific fields.
			size (int): Number of documents returned besides the aggregation (0 = only the aggregation).
			buckets (int): Maximum number of buckets.

		Keyword Args:
			fields (list): List with field's names.

		Returns:
			result: Search result.
		"""
		search = self._base_search(conn_es, index_pattern, query_string, timestamp_field, gte, lte)[0:size]
		if size and use_fields:
			search = search.source(kwargs["fields"])
		search.aggs.bucket("events", "terms", field = field_name, size = buckets)
		return search.execute()


	def search_aggregation(self, conn_es: Elasticsearch, index_pattern: str, timestamp_field: str, field_name: str, gte: str, lte: str, buckets: int = 999):
		"""
		Method that searches data in ElasticSearch using an aggregation.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			index_pattern (str): Index or index pattern where the search will be performed.
			timestamp_field (str): Field's name that corresponds to the index timestamp.
			field_name (str): Field's name to be used for the aggregation.
			gte (str): Greater than or equal to the defined range.
			lte (str): Less than or equal to the defined range.
			buckets (int): Maximum number of buckets.

		Returns:
			result: Search result.
		"""
		search = Search(using = conn_es, index = index_pattern).filter("range", **{timestamp_field: {"gte": gte, "lte": lte}})[0:0]
		search.aggs.bucket("events", "terms", field = field_name, size = buckets)
		return search.execute()


	def search_multiple_aggregation(self, conn_es: Elasticsearch, index_pattern: str, timestamp_field: str, field_name: str, field_name_two: str, gte: str, lte: str, buckets: int = 999):
		"""
		Method that searches data in ElasticSearch using multiple aggregations.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			index_pattern (str): Index or index pattern where the search will be performed.
			timestamp_field (str): Field's name that corresponds to the index timestamp.
			field_name (str): Field's name to be used for the aggregation.
			field_name_two (str): Field's name to be used for the aggregation.
			gte (str): Greater than or equal to the defined range.
			lte (str): Less than or equal to the defined range.
			buckets (int): Maximum number of buckets.

		Returns:
			result: Search result.
		"""
		search = Search(using = conn_es, index = index_pattern).filter("range", **{timestamp_field: {"gte": gte, "lte": lte}})[0:0]
		aggregation = A("terms", field = field_name, size = buckets, order = {"_key": "asc"})
		sub_aggregation = A("top_hits", size = 1, _source = [field_name_two])
		search.aggs.bucket("events", aggregation).metric("events_two", sub_aggregation)
		return search.execute()


	def convert_data_to_str(self, hit) -> str:
		"""
		Method that converts an Elastic document into a string (any depth: "a.b.c = value" per line).

		Parameters:
			hit (dict): Object that contains the document data.

		Returns:
			message (str): String obtained from the conversion.
		"""
		data = hit.to_dict() if hasattr(hit, "to_dict") else dict(hit)
		lines = []

		def walk(node, prefix: str) -> None:
			if isinstance(node, dict):
				for key, value in node.items():
					walk(value, f"{prefix}.{key}" if prefix else str(key))
			else:
				lines.append(f"{CHECK} {prefix} = {node}")

		walk(data, "")
		return ("\n".join(lines) + "\n" if lines else "") + "\n\n"


	# --- Documents -----------------------------------------------------------------------------
	def add_new_document(self, conn_es: Elasticsearch, index_name: str, data: dict) -> None:
		"""
		Method that adds a new document to an index.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			index_name (str): Index's name where the new document will be added.
			data (dict): Dictionary with the data to be added to the new document.
		"""
		with self._es_errors(f"adding a document to '{index_name}'"):
			conn_es.index(index = index_name, document = data)


	# --- Snapshots -----------------------------------------------------------------------------
	def create_snapshot(self, conn_es: Elasticsearch, index_name: str, repository_name: str, wait_for_completion: bool = True) -> None:
		"""
		Method that creates a snapshot (named as the index) in ElasticSearch.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			index_name (str): Index's name.
			repository_name (str): Repository's name.
			wait_for_completion (bool): Option that defines whether to wait for the task to finish. Default value (true).
		"""
		self._validate_name(index_name, "index")
		with self._es_errors(f"creating snapshot '{index_name}'"):
			conn_es.snapshot.create(repository = repository_name, snapshot = index_name, indices = index_name, include_global_state = False, wait_for_completion = wait_for_completion)


	def delete_snapshot(self, conn_es: Elasticsearch, snapshot_name: str, repository_name: str) -> None:
		"""
		Method that deletes a snapshot in ElasticSearch.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			snapshot_name (str): Snapshot's name.
			repository_name (str): Repository's name.
		"""
		self._validate_name(snapshot_name, "snapshot")
		with self._es_errors(f"deleting snapshot '{snapshot_name}'"):
			conn_es.snapshot.delete(repository = repository_name, snapshot = snapshot_name)


	def restore_snapshot(self, conn_es: Elasticsearch, snapshot_name: str, repository_name: str, wait_for_completion: bool = True) -> None:
		"""
		Method that restores a snapshot in ElasticSearch.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			snapshot_name (str): Snapshot's name.
			repository_name (str): Repository's name.
			wait_for_completion (bool): Option that defines whether to wait for the task to finish. Default value (true).
		"""
		self._validate_name(snapshot_name, "snapshot")
		with self._es_errors(f"restoring snapshot '{snapshot_name}'"):
			conn_es.snapshot.restore(repository = repository_name, snapshot = snapshot_name, wait_for_completion = wait_for_completion)


	def mount_searchable_snapshot(self, conn_es: Elasticsearch, snapshot_name: str, repository_name: str, wait_for_completion: bool = True) -> None:
		"""
		Method that mounts a snapshot as a searchable snapshot (the index inside the snapshot has the snapshot's name).

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			snapshot_name (str): Snapshot's name.
			repository_name (str): Repository's name.
			wait_for_completion (bool): Option that defines whether to wait for the task to finish. Default value (true).
		"""
		self._validate_name(snapshot_name, "snapshot")
		with self._es_errors(f"mounting searchable snapshot '{snapshot_name}'"):
			conn_es.searchable_snapshots.mount(repository = repository_name, snapshot = snapshot_name, index = snapshot_name, wait_for_completion = wait_for_completion)


	def get_snapshot_info(self, conn_es: Elasticsearch, snapshot_name: str, repository_name: str) -> dict:
		"""
		Method that obtains information about an snapshot.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			snapshot_name (str): Snapshot's name.
			repository_name (str): Repository's name.

		Returns:
			snapshot_info (dict): Information about a specific snapshot.
		"""
		with self._es_errors(f"getting snapshot '{snapshot_name}'"):
			return conn_es.snapshot.get(repository = repository_name, snapshot = snapshot_name)


	def get_snapshot_current_status(self, conn_es: Elasticsearch, snapshot_name: str, repository_name: str) -> str:
		"""
		Method that obtains a snapshot's current status.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			snapshot_name (str): Snapshot's name.
			repository_name (str): Repository's name.

		Returns:
			snapshot_current_status (str): Snapshot's current status ("NOT FOUND" if it doesn't exist).
		"""
		with self._es_errors(f"getting the status of snapshot '{snapshot_name}'"):
			snapshots_data = conn_es.snapshot.status(repository = repository_name, snapshot = snapshot_name).get("snapshots")
			return snapshots_data[0]["state"] if snapshots_data else "NOT FOUND"


	def get_snapshots_by_repository(self, conn_es: Elasticsearch, repository_name: str) -> list:
		"""
		Method that obtains the names of the snapshots stored in a specific repository (lightweight listing).

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			repository_name (str): Repository's name.

		Returns:
			snapshots_list (list): Snapshots stored in a specific repository.
		"""
		with self._es_errors(f"listing the snapshots of repository '{repository_name}'"):
			snapshots = conn_es.snapshot.get(repository = repository_name, snapshot = "_all", verbose = False)
			return sorted(snapshot["snapshot"] for snapshot in snapshots.get("snapshots", []) if isinstance(snapshot, dict) and "snapshot" in snapshot)


	# --- Indexes -------------------------------------------------------------------------------
	def delete_index(self, conn_es: Elasticsearch, index_name: str) -> None:
		"""
		Method that deletes an index in ElasticSearch (exact name only, wildcards are rejected).

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			index_name (str): Index's name.
		"""
		self._validate_name(index_name, "index")
		with self._es_errors(f"deleting index '{index_name}'"):
			conn_es.indices.delete(index = index_name)


	def get_indexes(self, conn_es: Elasticsearch) -> list:
		"""
		Method that obtains the names of the indexes stored in ElasticSearch. Excludes system indexes.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.

		Returns:
			indexes (list): Indexes' list.
		"""
		with self._es_errors("listing cluster indexes"):
			indexes = conn_es.cat.indices(index = "*,-.*", h = "index", format = "json")
			return sorted(item["index"] for item in indexes or [] if isinstance(item, dict) and "index" in item)


	# --- Repositories --------------------------------------------------------------------------
	def create_repository(self, conn_es: Elasticsearch, repository_name: str, repository_path: str, compress_repository: bool) -> None:
		"""
		Method that creates a repository (shared file system) in ElasticSearch.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			repository_name (str): Repository's name.
			repository_path (str): Repository's path.
			compress_repository (bool): Option that defines whether metadata files are stored compressed in the repository or not.
		"""
		with self._es_errors(f"creating repository '{repository_name}'"):
			# "body" is kept here because its replacement parameter changed name between 8.x client versions.
			conn_es.snapshot.create_repository(name = repository_name, body = {"type": "fs", "settings": {"location": repository_path, "compress": compress_repository}})


	def delete_repository(self, conn_es: Elasticsearch, repository_name: str) -> None:
		"""
		Method that deletes a repository in ElasticSearch.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			repository_name (str): Repository's name.
		"""
		with self._es_errors(f"deleting repository '{repository_name}'"):
			conn_es.snapshot.delete_repository(name = repository_name)


	def get_repositories(self, conn_es: Elasticsearch) -> list:
		"""
		Method that obtains the repositories created in ElasticSearch.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.

		Returns:
			repositories_list (list): Repositories' list.
		"""
		with self._es_errors("listing cluster repositories"):
			repositories_info = conn_es.cat.repositories(format = "json")
			return sorted(repository["id"] for repository in repositories_info or [] if isinstance(repository, dict) and "id" in repository)


	# --- Nodes ---------------------------------------------------------------------------------
	def get_nodes_information(self, conn_es: Elasticsearch) -> dict:
		"""
		Method that obtains file system statistics for all nodes in the cluster.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.

		Returns:
			nodes_info (dict): File system statistics obtained from nodes.
		"""
		with self._es_errors("getting cluster nodes statistics"):
			return conn_es.nodes.stats(metric = "fs").get("nodes") or {}


	# --- Integrity -----------------------------------------------------------------------------
	def validate_document(self, document: dict) -> list:
		"""
		Method that validates the document's integrity (kept for backwards compatibility).

		Returns:
			documents (list): [(index, id, version)] if the document version is greater than 1.
		"""
		return [(document["_index"], document["_id"], document["_version"])] if document["_version"] > 1 else []


	def validate_index_integrity(self, conn_es: Elasticsearch, index_name: str) -> list:
		"""
		Method that validates the integrity of a specific index's documents.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			index_name (str): Index to validate.

		Returns:
			documents (list): Modified or altered documents' list.
		"""
		with self._es_errors(f"validating index '{index_name}'"):
			return self._altered_documents(conn_es, index_name, {"match_all": {}})


	def validate_index_pattern_integrity(self, conn_es: Elasticsearch, index_pattern: str, timestamp_field: str, gte: str, lte: str) -> list:
		"""
		Method that validates the index pattern's integrity in a time range.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			index_pattern (str): Index Pattern to validate.
			timestamp_field (str): Field's name that corresponds to the index timestamp.
			gte (str): Greater than or equal to the defined range.
			lte (str): Less than or equal to the defined range.

		Returns:
			documents (list): Modified or altered documents' list.
		"""
		with self._es_errors(f"validating index pattern '{index_pattern}'"):
			return self._altered_documents(conn_es, index_pattern, {"bool": {"filter": [{"range": {timestamp_field: {"gte": gte, "lte": lte}}}]}})