import csv
from elasticsearch import Elasticsearch

def bulk_send(FILE_URL):

	ES_HOST = {"host" : "localhost", "port" : 9200}

	INDEX_NAME = 'firebolt'
	TYPE_NAME = 'endpoint'


	with open(FILE_URL) as f:
		csv_file_object = csv.reader(f, delimiter=';')

		header = csv_file_object.next()
		header = [item.lower() for item in header]

		bulk_data = [] 

		for row in csv_file_object:
			data_dict = {}
			for i in range(len(row)):
				data_dict[header[i]] = row[i]
			op_dict = {
				"index": {
					"_index": INDEX_NAME, 
					"_type": TYPE_NAME
				}
			}
			bulk_data.append(op_dict)
			bulk_data.append(data_dict)



	# create ES client, create index
	es = Elasticsearch(hosts = [ES_HOST])


	# since we are running locally, use one shard and no replicas
	request_body = {
		"settings" : {
			"number_of_shards": 1,
			"number_of_replicas": 0
		}
	}


	# bulk index the data
	print("bulk indexing...")
	res = es.bulk(index = INDEX_NAME, body = bulk_data, refresh = True)

	return True