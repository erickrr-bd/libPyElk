from libPyUtils import libPyUtils
from warnings import simplefilter
from ssl import create_default_context
from elasticsearch_dsl import Q, Search, A
from elasticsearch import Elasticsearch, RequestsHttpConnection, exceptions

class libPyElk:

	__utils = None

	exceptions = None

	def __init__(self):
		"""
		"""
		self.__utils = libPyUtils()
		self.exceptions = exceptions
		simplefilter('ignore', self.exceptions.ElasticsearchWarning)


	def createConnectionToElasticSearch(self, data_configuration, **kwargs):
		"""
		"""
		if data_configuration['use_ssl_tls'] == False and data_configuration['use_http_authentication'] == False:
			conn_es = Elasticsearch(data_configuration['es_host'], port = data_configuration['es_port'], connection_class = RequestsHttpConnection, use_ssl = data_configuration['use_ssl_tls'])
		if data_configuration['use_ssl_tls'] == False and data_configuration['use_http_authentication'] == True:
			passphrase = self.__utils.getPassphraseKeyFile(kwargs['path_key_file'])
			user_http_authentication = self.__utils.decryptDataWithAES(data_configuration['user_http_authentication'], passphrase).decode('utf-8')
			password_http_authentication = self.__utils.decryptDataWithAES(data_configuration['password_http_authentication'], passphrase).decode('utf-8')
			conn_es = Elasticsearch(data_configuration['es_host'], port = data_configuration['es_port'], http_auth = (user_http_authentication, password_http_authentication), use_ssl = data_configuration['use_ssl_tls'])
		if data_configuration['use_ssl_tls'] == True and data_configuration['use_http_authentication'] == False:
			if data_configuration['validate_certificate_ssl'] == False:
				conn_es = Elasticsearch(data_configuration['es_host'], port = data_configuration['es_port'], connection_class = RequestsHttpConnection, use_ssl = data_configuration['use_ssl_tls'], verify_certs = data_configuration['validate_certificate_ssl'], ssl_show_warn = False)
			else:
				context = create_default_context(cafile = data_configuration['path_certificate_file'])
				conn_es = Elasticsearch(data_configuration['es_host'], port = data_configuration['es_port'], connection_class = RequestsHttpConnection, use_ssl = data_configuration['use_ssl_tls'], verify_certs = data_configuration['validate_certificate_ssl'], ssl_context = context)
		if data_configuration['use_ssl_tls'] == True and data_configuration['use_http_authentication']:
			passphrase = self.__utils.getPassphraseKeyFile(kwargs['path_key_file'])
			user_http_authentication = self.__utils.decryptDataWithAES(data_configuration['user_http_authentication'], passphrase).decode('utf-8')
			password_http_authentication = self.__utils.decryptDataWithAES(data_configuration['password_http_authentication'], passphrase).decode('utf-8')
			if data_configuration['validate_certificate_ssl'] == False:
				conn_es = Elasticsearch(data_configuration['es_host'], port = data_configuration['es_port'], connection_class = RequestsHttpConnection, http_auth = (user_http_authentication, password_http_authentication), use_ssl = data_configuration['use_ssl_tls'], verify_certs = data_configuration['validate_certificate_ssl'], ssl_show_warn = False)
			else:
				context = create_default_context(cafile = kwargs['path_certificate_file'])
				conn_es = Elasticsearch(data_configuration['es_host'], port = data_configuration['es_port'], connection_class = RequestsHttpConnection, http_auth = (user_http_authentication, password_http_authentication), use_ssl = data_configuration['use_ssl_tls'], verify_certs = data_configuration['validate_certificate_ssl'], ssl_context = context)
		return conn_es


	def searchQueryStringElasticSearch(self, conn_es, index_name, query_string, gte, use_specific_fields, **kwargs):
		"""
		"""
		query_string_to_elastic = Q("query_string", query = query_string)
		search_to_elastic_aux = Search(index = index_name).using(conn_es)
		search_to_elastic_aux = search_to_elastic_aux[0:10000]
		if use_specific_fields == True:
			search_to_elastic = search_to_elastic_aux.query(query_string_to_elastic).query('range', ** {'@timestamp' : {'gte' : gte, 'lte' : "now"}}).source(fields = kwargs['specific_fields'])
		else:
			search_to_elastic = search_to_elastic_aux.query(query_string_to_elastic).query('range', ** {'@timestamp' : {'gte' : gte, 'lte' : "now"}}).source(fields = None)
		result_search = search_to_elastic.execute()
		return result_search