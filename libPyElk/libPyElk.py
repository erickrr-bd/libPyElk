from libPyUtils import libPyUtils
from warnings import simplefilter
from ssl import create_default_context
from elasticsearch_dsl import Q, Search, A, utils
from elasticsearch import Elasticsearch, RequestsHttpConnection, exceptions

class libPyElk:
	"""
	Attribute that contains an object of the libPyUtils library.
	"""
	__utils = None

	"""
	Attribute containing an object that corresponds to ElasticSearch exceptions.
	"""
	exceptions = None


	def __init__(self):
		"""
		Method that corresponds to the constructor of the class.
		"""
		self.__utils = libPyUtils()
		self.exceptions = exceptions
		simplefilter('ignore', self.exceptions.ElasticsearchWarning)


	def createConnectionToElasticSearch(self, data_configuration, **kwargs):
		"""
		Method that creates a connection with ElasticSearch from data stored in a YAML file.

		Returns an object containing a connection to ElasticSearch.
		
		:arg data_configuration (JSON Object): Object that contains the data obtained from a YAML file.

		Keyword Args:
        	:arg path_key_file (String): Absolute path where the key file is located.
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
				context = create_default_context(cafile = data_configuration['path_certificate_file'])
				conn_es = Elasticsearch(data_configuration['es_host'], port = data_configuration['es_port'], connection_class = RequestsHttpConnection, http_auth = (user_http_authentication, password_http_authentication), use_ssl = data_configuration['use_ssl_tls'], verify_certs = data_configuration['validate_certificate_ssl'], ssl_context = context)
		return conn_es


	def createSearchObject(self, conn_es, index_pattern_name):
		"""
		Method that creates a Search type Object in ElasticSearch.

		Returns a Search type object in ElasticSearch.

		:arg conn_es: Object that contains a connection to ElasticSearch.
		:arg index_pattern_name: Index pattern name where the search is performed.
		"""
		search_in_elastic = Search(index = index_pattern_name).using(conn_es).params(request_timeout = 30)
		search_in_elastic = search_in_elastic[0:10000]
		return search_in_elastic


	def executeSearchQueryString(self, search_in_elastic, gte, lte, query_string, use_fields_option, **kwargs):
		"""
		Method that performs a search in ElasticSearch using Query String.

		Returns an object with the search result.
		
		:arg search_in_elastic (Search Object): Search type object in ElasticSearch.
		:arg gte (String): Gte using to define the time range for the search in ElasticSearch.
		:arg lte (String): Lte using to define the time range for the search in ElasticSearch.
		:arg query_string (String): Query String with which the search is performed in ElasticSearch.
		:arg use_fields_option (Boolean): Whether or not to use the option to use fields.
		
		Keyword Args:
        	:arg fields (String's List): Names of the fields that will be returned by the search in ElasticSearch.
		"""
		query_string_to_elastic = Q("query_string", query = query_string)
		if use_fields_option == True:
			search_to_elastic = search_in_elastic.query(query_string_to_elastic).query('range', ** {'@timestamp' : {'gte' : gte, 'lte' : lte}}).source(fields = kwargs['fields'])
		else:
			search_to_elastic = search_in_elastic.query(query_string_to_elastic).query('range', ** {'@timestamp' : {'gte' : gte, 'lte' : lte}}).source(fields = None)
		result_search = search_to_elastic.execute()
		return result_search


	def executeSearchQueryStringWithAggregation(self, search_in_elastic, field_name, gte, lte, query_string, use_fields_option, **kwargs):
		"""
		Method that performs a search in ElasticSearch using Query String and an Aggregation.
		
		Returns an object with the search result.

		:arg search_in_elastic (Search Object): Search type object in ElasticSearch.
		:arg field_name (String): Field's name that be used for the Aggregation.
		:arg gte (String): Gte using to define the time range for the search in ElasticSearch.
		:arg lte (String): Lte using to define the time range for the search in ElasticSearch.
		:arg query_string (String): Query String with which the search is performed in ElasticSearch.
		:arg use_fields_option (Boolean): Whether or not to use the option to use fields.

		Keyword Args:
        	:arg fields (String's List): Names of the fields that will be returned by the search in ElasticSearch.
		"""
		query_string_to_elastic = Q("query_string", query = query_string)
		if use_fields_option == True:
			search_to_elastic = search_in_elastic.query(query_string_to_elastic).query('range', ** {'@timestamp' : {'gte' : gte, 'lte' : lte}}).source(fields = kwargs['fields'])
		else:
			search_to_elastic = search_in_elastic.query(query_string_to_elastic).query('range', ** {'@timestamp' : {'gte' : gte, 'lte' : lte}}).source(fields = None)
		aggregation = A('terms', field = field_name, size = 10000)
		search_to_elastic.aggs.bucket('events', aggregation)
		result_search = search_to_elastic.execute()
		return result_search


	def searchAggregationsTermsElasticSearch(self, conn_es, index_pattern_name, field_name_in_index):
		"""
		Method that performs a search in ElasticSearch using aggregations by terms.

		Returns an object with the search result.

		:arg conn_es: Object that contains a connection to ElasticSearch.
		:arg index_pattern_name: Name of the index pattern where the search will be performed.
		:arg field_name_in_index: Name of the field in the index pattern that will be used to search for terms.
		"""
		aggregation = A('terms', field = field_name_in_index, size = 10000)
		search_to_elastic_aux = Search(index = index_pattern_name).using(conn_es).params(request_timeout = 30)
		search_to_elastic = search_to_elastic_aux.query('range', ** { '@timestamp' : { 'gte' : "now-1d", 'lte' : "now" }}).source(fields = None)
		search_to_elastic.aggs.bucket('events', aggregation)
		result_search = search_to_elastic.execute()
		return result_search


	def generateTelegramMessagewithElasticData(self, hit):
		"""
		Method that generates the telegram message based on data from ElasticSearch .

		Returns the message to be sent via Telegram.

		:arg hit (Object): Object that contains the ElasticSearch Data.
		"""
		message_telegram = ""
		for hits in hit:
			if not (type(hit[str(hits)]) is utils.AttrDict):
				message_telegram += u'\u2611\uFE0F' + " " + hits + " = " + str(hit[str(hits)]) + '\n'
			else:
				for hits_two in hit[str(hits)]:
					if not (type(hit[str(hits)][str(hits_two)]) is utils.AttrDict):
						message_telegram += u'\u2611\uFE0F' + " " + hits + "." + hits_two + " = " + str(hit[str(hits)][str(hits_two)]) + '\n'
					else:
						for hits_three in hit[str(hits)][str(hits_two)]:
							if not (type(hit[str(hits)][str(hits_two)][str(hits_three)]) is utils.AttrDict):
								message_telegram += u'\u2611\uFE0F' + " " + hits + "." + hits_two + "." + hits_three + " = " + str(hit[str(hits)][str(hits_two)][str(hits_three)]) + '\n'
							else:
								for hits_four in hit[str(hits)][str(hits_two)][str(hits_three)]:
									if not (type(hit[str(hits)][str(hits_two)][str(hits_three)][str(hits_four)]) is utils.AttrDict):
										message_telegram += u'\u2611\uFE0F' + " " + hits + "." + hits_two + "." + hits_three + "." + hits_four + " = " + str(hit[str(hits)][str(hits_two)][str(hits_three)]) + '\n'
		message_telegram += "\n\n"
		return message_telegram		