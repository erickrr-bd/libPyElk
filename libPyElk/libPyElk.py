"""
Author: Erick Roberto Rodriguez Rodriguez
Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com
GitHub: https://github.com/erickrr-bd/libPyElk
libPyElk v2.2 - November 2025
A lightweight Python library for managing Elasticsearch operations with ease.
"""
import os
from libPyUtils import libPyUtils
from elasticsearch import Elasticsearch
from dataclasses import dataclass, field
from elasticsearch_dsl import Search, Q, A, utils
from libPyConfiguration import libPyConfiguration
from concurrent.futures import ThreadPoolExecutor

@dataclass
class libPyElk:

	utils: libPyUtils = field(default_factory = libPyUtils)


	def create_connection_without_auth(self, configuration: libPyConfiguration) -> Elasticsearch:
		"""
		Method that creates a connection to ElasticSearch without authentication.

		Parameters:
			configuration (libPyConfiguration): libPyConfiguration's Object.

		Returns:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
		"""
		if configuration.verificate_certificate_ssl:
			conn_es = Elasticsearch(hosts = configuration.es_host, verify_certs = True, ca_certs = configuration.certificate_file, request_timeout = 90, max_retries = 3, retry_on_timeout = True)
		else:
			conn_es = Elasticsearch(hosts = configuration.es_host, verify_certs = False, ssl_show_warn = False, request_timeout = 90, max_retries = 3, retry_on_timeout = True)
		return conn_es


	def create_connection_http_auth(self, configuration: libPyConfiguration, key_file: str) -> Elasticsearch:
		"""
		Method that creates a connection to ElasticSearch using HTTP authentication.

		Parameters:
			configuration (libPyConfiguration): libPyConfiguration's Object.
			key_file (str): Key file path. 

		Returns:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
		"""
		passphrase = self.utils.get_passphrase(key_file)
		http_authentication_user = self.utils.decrypt_data(configuration.http_authentication_user, passphrase).decode("utf-8")
		http_authentication_password = self.utils.decrypt_data(configuration.http_authentication_password, passphrase).decode("utf-8")
		if configuration.verificate_certificate_ssl:
			conn_es = Elasticsearch(hosts = configuration.es_host, basic_auth = (http_authentication_user, http_authentication_password), verify_certs = True, ca_certs = configuration.certificate_file, request_timeout = 90, max_retries = 3, retry_on_timeout = True)
		else:
			conn_es = Elasticsearch(hosts = configuration.es_host, basic_auth = (http_authentication_user, http_authentication_password), verify_certs = False, ssl_show_warn = False, request_timeout = 90, max_retries = 3, retry_on_timeout = True)
		return conn_es


	def create_connection_api_key(self, configuration: libPyConfiguration, key_file: str) -> Elasticsearch:
		"""
		Method that creates a connection to ElasticSearch using API Key.

		Parameters:
			configuration (libPyConfiguration): libPyConfiguration's Object.
			key_file (str): Key file path. 

		Returns:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
		"""
		passphrase = self.utils.get_passphrase(key_file)
		api_key_id = self.utils.decrypt_data(configuration.api_key_id, passphrase).decode("utf-8")
		api_key = self.utils.decrypt_data(configuration.api_key, passphrase).decode("utf-8")
		if configuration.verificate_certificate_ssl:
			conn_es = Elasticsearch(hosts = configuration.es_host, api_key  = (api_key_id, api_key), verify_certs = True, ca_certs = configuration.certificate_file, request_timeout = 90, max_retries = 3, retry_on_timeout = True)
		else:
			conn_es = Elasticsearch(hosts = configuration.es_host, api_key  = (api_key_id, api_key), verify_certs = False, ssl_show_warn = False, request_timeout = 90, max_retries = 3, retry_on_timeout = True)
		return conn_es


	def search_query_string(self, conn_es: Elasticsearch, index_pattern: str, query_string: str, timestamp_field: str, gte: str, lte: str, use_fields: bool, **kwargs):
		"""
		Method that searches data in ElasticSearch using query string.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			index_pattern (str): Index or index pattern where the search will be performed.
			query_string (str): Query string to be used for the search.
			timestamp_field (str): Field's name that corresponds to the index timestamp.
			gte (str): Greater than or equal to the defined range.
			lte (str): Less than or equal to the defined range.
			use_fields (bool): If true, it limits the search result to specific fields, otherwise it returns all the fields in the document.

		Keyword Args:
			fields (list): List with field's names.

		Returns:
			result: Search result.
		"""
		es_search = Search(using = conn_es, index = index_pattern)
		es_search = es_search[0:10000]
		es_query_string = Q("query_string", query = query_string)
		if use_fields:
			search_qs = es_search.query(es_query_string).query("range", **{timestamp_field : {"gte" : gte, "lte" : lte}}).source(fields = kwargs["fields"])
		else:
			search_qs = es_search.query(es_query_string).query("range", **{timestamp_field : {"gte" : gte, "lte" : lte}}).source(fields = None)
		result = search_qs.execute()
		return result


	def search_query_string_aggregation(self, conn_es: Elasticsearch, index_pattern: str, query_string: str, timestamp_field: str, gte: str, lte: str, field_name: str, use_fields: bool, **kwargs):
		"""
		Method that searches data in ElasticSearch using query string and aggregations.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			index_pattern (str): Index or index pattern where the search will be performed.
			query_string (str): Query string to be used for the search.
			timestamp_field (str): Field's name that corresponds to the index timestamp.
			gte (str): Greater than or equal to the defined range.
			lte (str): Less than or equal to the defined range.
			field_name (str): Field's name to be used for the aggregation.
			use_fields (bool): If true, it limits the search result to specific fields, otherwise it returns all the fields in the document.

		Keyword Args:
			fields (list): List with field's names.

		Returns:
			result: Search result.
		"""
		es_search = Search(using = conn_es, index = index_pattern)
		es_search = es_search[0:10000]
		es_query_string = Q("query_string", query = query_string)
		if use_fields:
			search_qs = es_search.query(es_query_string).query("range", **{timestamp_field : {"gte" : gte, "lte" : lte}}).source(fields = kwargs["fields"])
		else:
			search_qs = es_search.query(es_query_string).query("range", **{timestamp_field : {"gte" : gte, "lte" : lte}}).source(fields = None)
		aggregation = A("terms", field = field_name, size = 10000)
		es_search.aggs.bucket("events", aggregation)
		result = search_qs.execute()
		return result


	def search_aggregation(self, conn_es: Elasticsearch, index_pattern: str, timestamp_field: str, field_name: str, gte: str, lte: str):
		"""
		Method that searches data in ElasticSearch using an aggregation.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			index_pattern (str): Index or index pattern where the search will be performed.
			timestamp_field (str): Field's name that corresponds to the index timestamp.
			field_name (str): Field's name to be used for the aggregation.
			gte (str): Greater than or equal to the defined range.
			lte (str): Less than or equal to the defined range.

		Returns:
			result: Search result.
		"""
		es_search = Search(using = conn_es, index = index_pattern)
		es_search = es_search[0:0]
		aggregation = A("terms", field = field_name, size = 999)
		search_aggs = es_search.query("range", **{timestamp_field : {"gte" : gte, "lte" : lte}}).source(fields = None)
		search_aggs.aggs.bucket("events", aggregation)
		result = search_aggs.execute()
		return result


	def search_multiple_aggregation(self, conn_es: Elasticsearch, index_pattern: str, timestamp_field: str, field_name: str, field_name_two: str, gte: str, lte: str):
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

		Returns:
			result: Search result.
		"""
		es_search = Search(using = conn_es, index = index_pattern)
		es_search = es_search[0:0]
		aggregation = A("terms", field = field_name, size = 999, order = {"_key" : "asc"})
		sub_aggregation = A("top_hits", size = 1, _source = [field_name_two]) 
		search_aggs = es_search.query("range", **{timestamp_field : {"gte" : gte, "lte" : lte}}).source(fields = None)
		search_aggs.aggs.bucket("events", aggregation).metric("events_two", sub_aggregation)
		result = search_aggs.execute()
		return result


	def convert_data_to_str(self, hit: dict) -> str:
		"""
		MMethod that converts an Elastic document into a string.

		Parameters:
			hit (dict): Object that contains the document data.

		Returns:
			message (str): String obtained from the conversion.
		"""
		message = ""
		for hits in hit:
			if not (type(hit[str(hits)]) is utils.AttrDict):
				message += u"\u2611\uFE0F" + ' ' + hits + " = " + str(hit[str(hits)]) + '\n'
			else:
				for hits_two in hit[str(hits)]:
					if not (type(hit[str(hits)][str(hits_two)]) is utils.AttrDict):
						message += u"\u2611\uFE0F" + ' ' + hits + '.' + hits_two + " = " + str(hit[str(hits)][str(hits_two)]) + '\n'
					else:
						for hits_three in hit[str(hits)][str(hits_two)]:
							if not (type(hit[str(hits)][str(hits_two)][str(hits_three)]) is utils.AttrDict):
								message += u"\u2611\uFE0F" + ' ' + hits + '.' + hits_two + '.' + hits_three + " = " + str(hit[str(hits)][str(hits_two)][str(hits_three)]) + '\n'
							else:
								for hits_four in hit[str(hits)][str(hits_two)][str(hits_three)]:
									if not (type(hit[str(hits)][str(hits_two)][str(hits_three)][str(hits_four)]) is utils.AttrDict):
										message += u"\u2611\uFE0F" + ' ' + hits + '.' + hits_two + '.' + hits_three + '.' + hits_four + " = " + str(hit[str(hits)][str(hits_two)][str(hits_three)]) + '\n'
		message += "\n\n"
		return message


	def add_new_document(self, conn_es: Elasticsearch, index_name: str, data: dict) -> None:
		"""
		Method that adds a new document to an index.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			index_name (str): Index's name where the new document will be added.
			data (dict): Dictionary with the data to be added to the new document.
		"""
		conn_es.index(index = index_name, body = data)


	def get_indexes(self, conn_es:  Elasticsearch) -> list:
		"""
		Method that obtains the indexes stored in ElasticSearch. Excludes system indexes.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.

		Returns:
			indexes (list): All indexes' list.
		"""
		indexes = conn_es.indices.get(index = '*')
		indexes = sorted([index for index in indexes if not index.startswith('.')])
		return indexes


	def validate_document(self, document: dict) -> list:
		"""
		Method that validates the document's integrity. Validates if the document version is greater than 1.

		Parameters:
			document (dict): Document to validate.

		Returns:
			documents (list): Documents' list whose version is greater than 1.
		"""
		documents = []
		if document["_version"] > 1:
			documents.append((document["_index"], document["_id"], document["_version"]))
		return documents


	def validate_index_integrity(self, conn_es: Elasticsearch, index_name: str) -> list:
		"""
		Method that validates the integrity of a specific index's documents.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			index_name (str): Index to validate.

		Returns:
			documents (list): Modified or altered documents' list.
		"""
		documents = []
		body = {"query" : {"match_all" : {}}}
		response = conn_es.search(index = index_name, body = body, scroll = "2m", size = 1000, version = True)
		scroll_id = response["_scroll_id"]
		hits = response["hits"]["hits"]
		with ThreadPoolExecutor(max_workers = os.cpu_count() * 2) as executor:
			while hits:
				results = list(executor.map(self.validate_document, hits))
				for item in results:
					documents.extend(item)
				response = conn_es.scroll(scroll_id = scroll_id, scroll = "2m")
				scroll_id = response["_scroll_id"]
				hits = response["hits"]["hits"]
		conn_es.clear_scroll(scroll_id = scroll_id)
		return documents


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
		documents = []
		body = {"query" : {"bool" : {"must" : [{"range" : {timestamp_field : {"gte" : gte, "lte" : lte}}},{"match_all" : {}}]}}}
		response = conn_es.search(index = index_pattern, body = body, scroll = "2m", size = 1000, version = True)
		scroll_id = response["_scroll_id"]
		hits = response["hits"]["hits"]
		with ThreadPoolExecutor(max_workers = os.cpu_count() * 2)  as executor:
			while hits:
				results = list(executor.map(self.validate_document, hits))
				for item in results:
					documents.extend(item)
				response = conn_es.scroll(scroll_id = scroll_id, scroll = "2m")
				scroll_id = response["_scroll_id"]
				hits = response["hits"]["hits"]
		conn_es.clear_scroll(scroll_id = scroll_id)
		return documents
