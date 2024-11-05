"""
Author: Erick Roberto Rodriguez Rodriguez
Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com
GitHub: https://github.com/erickrr-bd/libPyElk
libPyElk v2.1 - October 2024
"""
from warnings import simplefilter
from libPyUtils import libPyUtils
from ssl import create_default_context
from elasticsearch import Elasticsearch, RequestsHttpConnection, exceptions

class libPyElk:

	def __init__(self):
		"""
		Class constructor.
		"""
		self.utils = libPyUtils()
		simplefilter("ignore", exceptions.ElasticsearchWarning)


	def create_connection_wa(self, data):
		"""
		Method that creates a connection with ElasticSearch without authentication.

		Returns a straightforward mapping from Python to ES REST endpoints.

		:arg data (Dict): Dictionary with saved settings.
		"""
		if data["use_ssl"]:
			if data["verificate_certificate_ssl"]:
				context = create_default_context(cafile = data["certificate_file"])
				conn_es = Elasticsearch(data["es_host"], port = data["es_port"], connection_class = RequestsHttpConnection, use_ssl = data["use_ssl"], verify_certs = data["verificate_certificate_ssl"], ssl_context = context)
			else:
				conn_es = Elasticsearch(data["es_host"], port = data["es_port"], connection_class = RequestsHttpConnection, use_ssl = data["use_ssl"], verify_certs = data["verificate_certificate_ssl"], ssl_show_warn = False)
		else:
			conn_es = Elasticsearch(data["es_host"], port = data["es_port"], use_ssl = data["use_ssl"])
		return conn_es


	def create_connection_ha(self, data, key_file):
		"""
		Method that creates a connection with ElasticSearch using HTTP authentication.

		Returns a straightforward mapping from Python to ES REST endpoints.

		:arg data (Dict): Dictionary with saved settings.
		:arg key_file (String): File with the key to encrypt/decrypt data.
		"""
		passphrase = self.utils.get_passphrase(key_file)
		http_authentication_user = self.utils.decrypt_data(data["http_authentication_user"], passphrase)
		http_authentication_password = self.utils.decrypt_data(data["http_authentication_password"], passphrase)
		if data["use_ssl"]:
			if data["verificate_certificate_ssl"]:
				context = create_default_context(cafile = data["certificate_file"])
				conn_es = Elasticsearch(data["es_host"], port = data["es_port"], http_auth = (http_authentication_user, http_authentication_password), connection_class = RequestsHttpConnection, use_ssl = data["use_ssl"], verify_certs = data["verificate_certificate_ssl"], ssl_context = context)
			else:
				conn_es = Elasticsearch(data["es_host"], port = data["es_port"], http_auth = (http_authentication_user, http_authentication_password), connection_class = RequestsHttpConnection, use_ssl = data["use_ssl"], verify_certs = data["verificate_certificate_ssl"], ssl_show_warn = False)
		else:
			conn_es = Elasticsearch(data["es_host"], port = data["es_port"], http_auth = (http_authentication_user, http_authentication_password), use_ssl = data["use_ssl"])
		return conn_es


	def create_connection_ak(self, data, key_file):
		"""
		Method that creates a connection with ElasticSearch using API Key authentication.

		Returns a straightforward mapping from Python to ES REST endpoints.

		:arg data (Dict): Dictionary with saved settings.
		:arg key_file (String): File with the key to encrypt/decrypt data.
		"""
		passphrase = self.utils.get_passphrase(key_file)
		api_key_id = self.utils.decrypt_data(data["api_key_id"], passphrase)
		api_key = self.utils.decrypt_data(data["api_key"], passphrase)
		if data["use_ssl"]:
			if data["verificate_certificate_ssl"]:
				context = create_default_context(cafile = data["certificate_file"])
				conn_es = Elasticsearch(data["es_host"], port = data["es_port"], api_key = (api_key_id, api_key), connection_class = RequestsHttpConnection, use_ssl = data["use_ssl"], verify_certs = data["verificate_certificate_ssl"], ssl_context = context)
			else:
				conn_es = Elasticsearch(data["es_host"], port = data["es_port"], api_key = (api_key_id, api_key), connection_class = RequestsHttpConnection, use_ssl = data["use_ssl"], verify_certs = data["verificate_certificate_ssl"], ssl_show_warn = False)
		else:
			conn_es = Elasticsearch(data["es_host"], port = data["es_port"], api_key = (api_key_id, api_key), use_ssl = data["use_ssl"])
		return conn_es


	def add_document_index(self, conn_es, index_name, data):
		"""
		Method that adds a new document to an index.

		:arg conn_es (Object): Object that contains a connection to ElasticSearch.
		:arg index_name (String): Index name.
		:arg data (JSON): JSON object with the data of the new document.
		"""
		conn_es.index(index = index_name, body = data)