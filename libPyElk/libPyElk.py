from libPyUtils import libPyUtils
from warnings import simplefilter
from ssl import create_default_context
from elasticsearch_dsl import Q, Search, A, utils
from elasticsearch import Elasticsearch, RequestsHttpConnection, exceptions

class libPyElk:

	def __init__(self):
		"""
		Class constructor.
		"""
		self.utils = libPyUtils()
		self.exceptions = exceptions
		simplefilter("ignore", self.exceptions.ElasticsearchWarning)


	def createConnectionWithoutAuthentication(self, configuration_data):
		"""
		Method that creates a connection with ElasticSearch without authentication.
		
		Returns a straightforward mapping from Python to ES REST endpoints.
		
		:arg configuration_data (dict): Dictionary that stores configuration data.
		"""
		if configuration_data["use_ssl_tls"]:
			if configuration_data["verificate_certificate_ssl"]:
				context = create_default_context(cafile = configuration_data["certificate_file_path"])
				conn_es = Elasticsearch(configuration_data["es_host"], port = configuration_data["es_port"], connection_class = RequestsHttpConnection, use_ssl = configuration_data["use_ssl_tls"], verify_certs = configuration_data["verificate_certificate_ssl"], ssl_context = context)
			else:
				conn_es = Elasticsearch(configuration_data["es_host"], port = configuration_data["es_port"], connection_class = RequestsHttpConnection, use_ssl = configuration_data["use_ssl_tls"], verify_certs = configuration_data["verificate_certificate_ssl"], ssl_show_warn = False)
		else:
			conn_es = Elasticsearch(configuration_data["es_host"], port = configuration_data["es_port"], use_ssl = configuration_data["use_ssl_tls"])
		return conn_es


	def createConnectionHTTPAuthentication(self, configuration_data, key_file_path):
		"""
		Method that creates a connection with ElasticSearch using HTTP authentication.

		Returns a straightforward mapping from Python to ES REST endpoints.

		:arg configuration_data (dict): Dictionary that stores configuration data.
		:arg key_file_path (string): Absolute path of the file containing the encryption key.
		"""
		passphrase = self.utils.getPassphraseKeyFromFile(key_file_path)
		http_authentication_user = self.utils.decryptDataWithAES(configuration_data["http_authentication_user"], passphrase)
		http_authentication_password = self.utils.decryptDataWithAES(configuration_data["http_authentication_password"], passphrase)
		if configuration_data["use_ssl_tls"]:
			if configuration_data["verificate_certificate_ssl"]:
				context = create_default_context(cafile = configuration_data["certificate_file_path"])
				conn_es = Elasticsearch(configuration_data["es_host"], port = configuration_data["es_port"], http_auth = (http_authentication_user, http_authentication_password), connection_class = RequestsHttpConnection, use_ssl = configuration_data["use_ssl_tls"], verify_certs = configuration_data["verificate_certificate_ssl"], ssl_context = context)
			else:
				conn_es = Elasticsearch(configuration_data["es_host"], port = configuration_data["es_port"], http_auth = (http_authentication_user, http_authentication_password), connection_class = RequestsHttpConnection, use_ssl = configuration_data["use_ssl_tls"], verify_certs = configuration_data["verificate_certificate_ssl"], ssl_show_warn = False)
		else:
			conn_es = Elasticsearch(configuration_data["es_host"], port = configuration_data["es_port"], http_auth = (http_authentication_user, http_authentication_password), use_ssl = configuration_data["use_ssl_tls"])
		return conn_es


	def createConnectionAPIKey(self, configuration_data, key_file_path):
		"""
		Method that creates a connection with ElasticSearch using API Key.

		Returns a straightforward mapping from Python to ES REST endpoints.

		:arg configuration_data (dict): Dictionary that stores configuration data.
		:arg key_file_path (string): Absolute path of the file containing the encryption key.
		"""
		passphrase = self.utils.getPassphraseKeyFromFile(key_file_path)
		api_key_id = self.utils.decryptDataWithAES(configuration_data["api_key_id"], passphrase)
		api_key = self.utils.decryptDataWithAES(configuration_data["api_key"], passphrase)
		if configuration_data["use_ssl_tls"]:
			if configuration_data["verificate_certificate_ssl"]:
				context = create_default_context(cafile = configuration_data["certificate_file_path"])
				conn_es = Elasticsearch(configuration_data["es_host"], port = configuration_data["es_port"], api_key = (api_key_id, api_key), connection_class = RequestsHttpConnection, use_ssl = configuration_data["use_ssl_tls"], verify_certs = configuration_data["verificate_certificate_ssl"], ssl_context = context)
			else:
				conn_es = Elasticsearch(configuration_data["es_host"], port = configuration_data["es_port"], api_key = (api_key_id, api_key), connection_class = RequestsHttpConnection, use_ssl = configuration_data["use_ssl_tls"], verify_certs = configuration_data["verificate_certificate_ssl"], ssl_show_warn = False)
		else:
			conn_es = Elasticsearch(configuration_data["es_host"], port = configuration_data["es_port"], api_key = (api_key_id, api_key), use_ssl = configuration_data["use_ssl_tls"])
		return conn_es


	def createSearch(self, conn_es, index_pattern):
		"""
		Method that creates a Search object.

		Returns a Search object.

		:arg conn_es (Object): Object with the connection to ElasticSearch.
		:arg index_pattern (string): Name of the index or index pattern.
		"""
		search = Search(index = index_pattern).using(conn_es).params(request_timeout = 30)
		search = search[0:10000]
		return search


	def searchByQueryString(self, search, query_string, gte, lte, use_fields_selection, **kwargs):
		"""
		Method that performs a search in ElasticSearch using Query String

		Returns results matching a query.

		:arg search (Object): Search Object.
		:arg query_string (string): Query String that defines the event search.
		:arg gte (string): Date math for the gte value.
		:arg lte (string): Date math for the lte value.
		:arg use_fields_selection (boolean): Whether or not the option to select certain fields is going to be used.

		Keyword Args:
        	:arg fields (list): List with field names.
		"""
		es_query_string = Q("query_string", query = query_string)
		if use_fields_selection:
			search_query_string = search.query(es_query_string).query("range", **{"@timestamp" : {"gte" : gte, "lte" : lte}}).source(fields = kwargs["fields_name"])
		else:
			search_query_string = search.query(es_query_string).query("range", **{"@timestamp" : {"gte" : gte, "lte" : lte}}).source(fields = None)
		result = search_query_string.execute()
		return result


	def searchByQueryStringAggregation(self, search, query_string, gte, lte, field, use_fields_selection, **kwargs):
		"""
		Method that performs a search in ElasticSearch using Query String and an Aggregation.
		
		Returns results matching a query.

		:arg search (Object): Search Object.
		:arg query_string (string): Query String that defines the event search.
		:arg gte (string): Date math for the gte value.
		:arg lte (string): Date math for the lte value.
		:arg field (string): Name of the field to be used for the aggregation.
		:arg use_fields_selection (boolean): Whether or not the option to select certain fields is going to be used.

		Keyword Args:
        	:arg fields (list): List with field names.
		"""
		es_query_string = Q("query_string", query = query_string)
		if use_fields_selection:
			search_query_string = search.query(es_query_string).query("range", **{"@timestamp" : {"gte" : gte, "lte" : lte}}).source(fields = kwargs["fields_name"])
		else:
			search_query_string = search.query(es_query_string).query("range", **{"@timestamp" : {"gte" : gte, "lte" : lte}}).source(fields = None)
		aggregation = A("terms", field = field, size = 10000)
		search_query_string.aggs.bucket("events", aggregation)
		result = search_query_string.execute()
		return result


	def createDocumentInIndex(self, conn_es, index_name, body_data):
		"""
		Method that creates a document in an index in ElasticSearch.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		:arg index_name (string): Name of the index where the document will be entered.
		:arg body_data (JSON): JSON object with the data that will be inserted in ElasticSearch.
		"""
		conn_es.index(index = index_name, body = body_data)


	def executeSearchWithAggregation(self, search_in_elastic, field_name_in_index, gte, lte):
		"""
		Method that performs a search in ElasticSearch using Aggregations.
		
		Returns an object with the search result.

		:arg search_in_elastic (object): Search type object in ElasticSearch.
		:arg field_name_in_index (string): Field's name that be used for the Aggregation.
		:arg gte (string): Gte using to define the time range for the search in ElasticSearch.
		:arg lte (string): Lte using to define the time range for the search in ElasticSearch.
		"""
		aggregation = A("terms", field = field_name_in_index, size = 10000)
		search_to_elastic = search_in_elastic.query("range", ** {"@timestamp" : {"gte" : gte, "lte": lte}}).source(fields = None)
		search_to_elastic.aggs.bucket("events", aggregation)
		result_search = search_to_elastic.execute()
		return result_search


	def getDocumentsVersionChangeinIndex(self, conn_es, index_name):
		"""
		Method that obtains the documents where their version has changed.

		Returns the list with all documents where their version has changed.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		:arg index_name (string): Name of the index where the document will be entered.
		"""
		list_documents_version_changes = []
		search_body = {"size" : 10000, "query": {"match_all" : {}}}
		search_in_elastic = conn_es.search(index = index_name, body = search_body, scroll = "3m", version = True)
		scroll_id = search_in_elastic["_scroll_id"]
		scroll_size = len(search_in_elastic["hits"]["hits"])
		while scroll_size > 0:
			for hits in search_in_elastic["hits"]["hits"]:
				if hits["_version"] > 1:
					list_documents_version_changes.append((hits["_index"], hits["_id"], hits["_version"]))
			search_in_elastic = conn_es.scroll(scroll_id = scroll_id, scroll = "2m")
			scroll_id = search_in_elastic["_scroll_id"]
			scroll_size = len(search_in_elastic["hits"]["hits"])
		conn_es.clear_scroll(scroll_id = scroll_id)
		return list_documents_version_changes


	def getDocumentsVersionChangeinIndexPattern(self, conn_es, index_pattern_name, gte, lte):
		"""
		Method that obtains the documents where their version has changed.

		Returns the list with all documents where their version has changed.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		:arg index_pattern_name (string): Name of the index where the document will be entered.
		:arg gte (string): Gte using to define the time range for the search in ElasticSearch.
		:arg lte (string): Lte using to define the time range for the search in ElasticSearch.
		"""
		list_documents_version_changes = []
		search_body = {"size" : 10000, "query": {"bool": {"must": [{"range": {"@timestamp": {"gte": gte, "lte" : lte}}},{"match_all": {}}]}}}
		search_in_elastic = conn_es.search(index = index_pattern_name, body = search_body, scroll = "3m", version = True)
		scroll_id = search_in_elastic["_scroll_id"]
		scroll_size = len(search_in_elastic["hits"]["hits"])
		while scroll_size > 0:
			for hits in search_in_elastic["hits"]["hits"]:
				if hits["_version"] > 1:
					list_documents_version_changes.append((hits["_index"], hits["_id"], hits["_version"]))
			search_in_elastic = conn_es.scroll(scroll_id = scroll_id, scroll = "2m")
			scroll_id = search_in_elastic["_scroll_id"]
			scroll_size = len(search_in_elastic["hits"]["hits"])
		conn_es.clear_scroll(scroll_id = scroll_id)
		return list_documents_version_changes


	def createRepository(self, conn_es, repository_name, path_repository, use_compress_option):
		"""
		Method that creates a repository in ElasticSearch.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		:arg repository_name (string): Repository name.
		:arg path_repository (string): Repository path.
		:arg use_compress_option (boolean): Whether or not to use repository compression.
		"""
		conn_es.snapshot.create_repository(repository = repository_name, body = {"type" : "fs", "settings" : {"location" : path_repository, "compress" : use_compress_option}})


	def deleteRepository(self, conn_es, repository_name):
		"""
		Method that deletes a repository.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		"""
		conn_es.snapshot.delete_repository(repository = repository_name)


	def getRepositories(self, conn_es):
		"""
		Method that obtains a list with all the repositories created in ElasticSearch.

		Returns a list with the name of the repositories.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		"""
		list_all_repositories = []
		repositories_info = conn_es.cat.repositories(format = "json")
		for repository in repositories_info:
			list_all_repositories.append(repository["id"])
		return list_all_repositories


	def createSnapshot(self, conn_es, repository_name, index_name, wait_for_completion):
		"""
		Method that creates a snapshot in ElasticSearch.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		:arg repository_name (string): Name of the repository where the snapshot is stored.
		:arg index_name (string): Name of the index from which the snapshot will be taken.
		:arg wait_for_completion (boolean): Whether or not to wait for the snapshot creation to complete.
		"""
		conn_es.snapshot.create(repository = repository_name, snapshot = index_name, body = {"indices" : index_name, "include_global_state" : False}, wait_for_completion = wait_for_completion)


	def getStatusSnapshot(self, conn_es, repository_name, snapshot_name):
		"""
		Method that obtains the status of a snapshot.

		Returns the current status of the snapshot.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		:arg repository_name (string): Name of the repository where the snapshot is stored.
		:arg snapshot_name (string): Name of the snapshot from which the status will be obtained.
		"""
		status_snapshot = conn_es.snapshot.status(repository = repository_name, snapshot = snapshot_name)
		current_status_snapshot = status_snapshot["snapshots"][0]["state"]
		return current_status_snapshot


	def getSnapshotInfo(self, conn_es, repository_name, snapshot_name):
		"""
		Method that obtains information about an index.

		Returns the snapshot information.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		:arg repository_name (string): Name of the repository where the snapshot is stored.
		:arg snapshot_name (string): Name of the snapshot from which the information will be obtained.
		"""
		snapshot_info = conn_es.snapshot.get(repository = repository_name, snapshot = snapshot_name)
		return snapshot_info


	def getSnapshotsbyRepository(self, conn_es, repository_name):
		"""
		Method that gets all the snapshot names of a specific repository.

		Returns a list with the names of the snapshots.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		:arg repository_name (string): Name of the repository where the snapshots are stored.
		"""
		list_all_snapshots = []
		snapshots_info = conn_es.snapshot.get(repository = repository_name, snapshot = "_all")
		for snapshot_info in snapshots_info["snapshots"]:
			list_all_snapshots.append(snapshot_info["snapshot"])
		list_all_snapshots = sorted(list_all_snapshots)
		return list_all_snapshots


	def restoreSnapshot(self, conn_es, repository_name, snapshot_name, wait_for_completion):
		"""
		Method that restores an ElasticSearch snapshot.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		:arg repository_name (string): Name of the repository where the snapshot is stored.
		:arg snapshot_name (string): Name of the snapshot to restore.
		:arg wait_for_completion (boolean): Whether or not to wait for the snapshot restore to complete.
		"""
		conn_es.snapshot.restore(repository = repository_name, snapshot = snapshot_name, wait_for_completion = wait_for_completion)


	def mountSearchableSnapshot(self, conn_es, repository_name, snapshot_name, wait_for_completion):
		"""
		Method that mounts a snapshot as a searchable snapshot.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		:arg repository_name (string): Name of the repository where the snapshot is stored.
		:arg snapshot_name (string): Name of the snapshot to mount.
		:arg wait_for_completion (boolean): Whether or not to wait for the snapshot mount to complete.
		"""
		conn_es.searchable_snapshots.mount(repository = repository_name, snapshot = snapshot_name, body = {"index" : snapshot_name}, wait_for_completion = wait_for_completion, request_timeout = 7200)


	def deleteSnapshot(self, conn_es, repository_name, snapshot_name):
		"""
		Method that deletes an ElasticSearch snapshot.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		:arg repository_name (string): Name of the repository where the snapshot is stored.
		:arg snapshot_name (string): Name of the snapshot to delete.
		"""
		conn_es.snapshot.delete(repository = repository_name, snapshot = snapshot_name, request_timeout = 7200)


	def getIndexes(self, conn_es):
		"""
		Method that obtains a list with the names of the ElasticSearch indexes.
		
		Returns the list with the names of the indexes.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		"""
		list_all_indexes = conn_es.indices.get('*')
		list_all_indexes = sorted([index for index in list_all_indexes if not index.startswith('.')])
		return list_all_indexes


	def deleteIndex(self, conn_es, index_name):
		"""
		Method that removes an ElasticSearch index.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		:arg index_name (string): Name of the index to delete.
		"""
		conn_es.indices.delete(index = index_name)


	def getNodesInformation(self, conn_es):
		"""
		Method that obtains the information from the ElasticSearch nodes.
		
		Returns an object with the information of the nodes.

		:arg conn_es (object): Object that contains a connection to ElasticSearch.
		"""
		es_nodes_info = conn_es.nodes.stats(metric = "fs")["nodes"]
		return es_nodes_info


	def generateDataTelegramMessage(self, hit):
		"""
		Method that generates a Telegram message based on the result of a search in ElasticSearch.

		RReturns a Telegram message.

		:arg hit (object): Object that contains the search data in ElasticSearch.
		"""
		telegram_message = ""
		for hits in hit:
			if not (type(hit[str(hits)]) is utils.AttrDict):
				telegram_message += u"\u2611\uFE0F" + ' ' + hits + " = " + str(hit[str(hits)]) + '\n'
			else:
				for hits_two in hit[str(hits)]:
					if not (type(hit[str(hits)][str(hits_two)]) is utils.AttrDict):
						telegram_message += u"\u2611\uFE0F" + ' ' + hits + '.' + hits_two + " = " + str(hit[str(hits)][str(hits_two)]) + '\n'
					else:
						for hits_three in hit[str(hits)][str(hits_two)]:
							if not (type(hit[str(hits)][str(hits_two)][str(hits_three)]) is utils.AttrDict):
								telegram_message += u"\u2611\uFE0F" + ' ' + hits + '.' + hits_two + '.' + hits_three + " = " + str(hit[str(hits)][str(hits_two)][str(hits_three)]) + '\n'
							else:
								for hits_four in hit[str(hits)][str(hits_two)][str(hits_three)]:
									if not (type(hit[str(hits)][str(hits_two)][str(hits_three)][str(hits_four)]) is utils.AttrDict):
										telegram_message += u"\u2611\uFE0F" + ' ' + hits + '.' + hits_two + '.' + hits_three + '.' + hits_four + " = " + str(hit[str(hits)][str(hits_two)][str(hits_three)]) + '\n'
		telegram_message += "\n\n"
		return telegram_message


	def getFieldsofElasticData(self, hit):
		"""
		Method that obtains the names of the fields obtained in a search and saves them in a list.

		Returns a list with the names of the fields obtained in the search.

		:arg hit (object): Object that contains the ElasticSearch Data.
		"""
		headers = []
		for hits in hit:
			if not (type(hit[str(hits)]) is utils.AttrDict):
				headers.append(hits)
			else:
				for hits_two in hit[str(hits)]:
					if not (type(hit[str(hits)][str(hits_two)]) is utils.AttrDict):
						headers.append(hits + "." + hits_two)
					else:
						for hits_three in hit[str(hits)][str(hits_two)]:
							if not (type(hit[str(hits)][str(hits_two)][str(hits_three)]) is utils.AttrDict):
								headers.append(hits + "." + hits_two + "." + hits_three)
							else:
								for hits_four in hit[str(hits)][str(hits_two)][str(hits_three)]:
									if not (type(hit[str(hits)][str(hits_two)][str(hits_three)][str(hits_four)]) is utils.AttrDict):
										headers.append(hits + "." + hits_two + "." + hits_three + "." + hits_four)
		return headers


	def generateArraywithElasticData(self, hit):
		"""
		Method that converts the hits obtained in a search into a list.

		Returns a list with other lists with the values obtained in the search in ElasticSearch.

		:arg hit (object): Object that contains the ElasticSearch Data.
		"""
		list_to_data = []
		list_to_hit = []
		for hits in hit:
			if not (type(hit[str(hits)]) is utils.AttrDict):
				list_to_hit.append(str(hit[str(hits)]))
			else:
				for hits_two in hit[str(hits)]:
					if not (type(hit[str(hits)][str(hits_two)]) is utils.AttrDict):
						list_to_hit.append(str(hit[str(hits)][str(hits_two)]))
					else:
						for hits_three in hit[str(hits)][str(hits_two)]:
							if not (type(hit[str(hits)][str(hits_two)][str(hits_three)]) is utils.AttrDict):
								list_to_hit.append(str(hit[str(hits)][str(hits_two)][str(hits_three)]))
							else:
								for hits_four in hit[str(hits)][str(hits_two)][str(hits_three)]:
									if not (type(hit[str(hits)][str(hits_two)][str(hits_three)][str(hits_four)]) is utils.AttrDict):
										list_to_hit.append(str(hit[str(hits)][str(hits_two)][str(hits_three)]))
			list_to_data.append(list_to_hit)
		return list_to_data