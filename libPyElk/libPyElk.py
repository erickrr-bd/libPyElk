"""
Author: Erick Roberto Rodriguez Rodriguez
Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com
GitHub: https://github.com/erickrr-bd/libPyElk
libPyElk v2.2 - March 2025
"""
from libPyUtils import libPyUtils
from elasticsearch import Elasticsearch
from dataclasses import dataclass, field
from elasticsearch_dsl import Search, Q, utils
from libPyConfiguration import libPyConfiguration

@dataclass
class libPyElk:
	"""
	Easy integration of ElasticSearch with Python applications. 
	"""

	utils: libPyUtils = field(default_factory = libPyUtils)


	def create_connection_without_auth(self, configuration: libPyConfiguration) -> Elasticsearch:
		"""
		Method that creates a connection to ElasticSearch without authentication.

		Parameters:
			configuration (libPyConfiguration): Object with the configuration to create the connection with ElasticSearch.

		Returns:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
		"""
		if configuration.verificate_certificate_ssl:
			conn_es = Elasticsearch(hosts = configuration.es_host, verify_certs = True, ca_certs = configuration.certificate_file)
		else:
			conn_es = Elasticsearch(hosts = configuration.es_host, verify_certs = False, ssl_show_warn = False)
		return conn_es


	def create_connection_http_auth(self, configuration: libPyConfiguration, key_file: str) -> Elasticsearch:
		"""
		Method that creates a connection to ElasticSearch using HTTP authentication.

		Parameters:
			configuration (libPyConfiguration): Object with the configuration to create the connection with ElasticSearch.
			key_file (str): Key file path. 

		Returns:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
		"""
		passphrase = self.utils.get_passphrase(key_file)
		http_authentication_user = self.utils.decrypt_data(configuration.http_authentication_user, passphrase).decode("utf-8")
		http_authentication_password = self.utils.decrypt_data(configuration.http_authentication_password, passphrase).decode("utf-8")
		if configuration.verificate_certificate_ssl:
			conn_es = Elasticsearch(hosts = configuration.es_host, basic_auth = (http_authentication_user, http_authentication_password), verify_certs = True, ca_certs = configuration.certificate_file)
		else:
			conn_es = Elasticsearch(hosts = configuration.es_host, basic_auth = (http_authentication_user, http_authentication_password), verify_certs = False, ssl_show_warn = False)
		return conn_es


	def create_connection_api_key(self, configuration: libPyConfiguration, key_file: str) -> Elasticsearch:
		"""
		Method that creates a connection to ElasticSearch using API Key.

		Parameters:
			configuration (libPyConfiguration): Object with the configuration to create the connection with ElasticSearch.
			key_file (str): Key file path. 

		Returns:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
		"""
		passphrase = self.utils.get_passphrase(key_file)
		api_key_id = self.utils.decrypt_data(configuration.api_key_id, passphrase).decode("utf-8")
		api_key = self.utils.decrypt_data(configuration.api_key, passphrase).decode("utf-8")
		if configuration.verificate_certificate_ssl:
			conn_es = Elasticsearch(hosts = configuration.es_host, api_key  = (api_key_id, api_key), verify_certs = True, ca_certs = configuration.certificate_file)
		else:
			conn_es = Elasticsearch(hosts = configuration.es_host, api_key  = (api_key_id, api_key), verify_certs = False, ssl_show_warn = False)
		return conn_es


	def search_query_string(self, conn_es: Elasticsearch, index_pattern: str, query_string: str, timestamp_field: str, gte_date: str, lte_date: str, use_fields: bool, **kwargs):
		"""
		Method that searches data in ElasticSearch using query string.

		Parameters:
			conn_es (ElasticSearch): A straightforward mapping from Python to ES REST endpoints.
			index_pattern (str): Index or index pattern where the search will be performed.
			query_string (str): Query string to be used for the search.
			timestamp_field (str): Name of the field that corresponds to the index timestamp.
			gte_date (str): Mayor o igual al rango definido.
			lte_date (str): Menor o igual al rango definido.
			use_fields (bool): Whether or not to use the option to return certain fields in the search result.

		Keyword Args:
			fields (list): List with field's names.

		Returns:
			result: Search result.
		"""
		es_search = Search(using = conn_es, index = index_pattern)
		es_search = es_search[0:10000]
		es_query_string = Q("query_string", query = query_string)
		if use_fields:
			search_qs = es_search.query(es_query_string).query("range", **{timestamp_field : {"gte" : gte_date, "lte" : lte_date}}).source(fields = kwargs["fields"])
		else:
			search_qs = es_search.query(es_query_string).query("range", **{timestamp_field : {"gte" : gte_date, "lte" : lte_date}}).source(fields = None)
		result = search_qs.execute()
		return result


	def convert_data_to_str(self, hit) -> str:
		"""
		Method that converts ElasticSearch data to a string.

		Parameters:
			hit: Data corresponding to the search result in ElasticSearch.

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