import pandas as pd
import numpy as np

class Processor:

	@staticmethod
	def cleanData(file_name, ):
		data = pd.read_csv(file_name, sep=",", header = None)
		attack_type = pd.read_csv('Attack Types.csv', names=["class", "type"])
		data.columns = ["duration", "protocol_type", "service", "flag" ,"src_bytes"
		    , "dst_bytes", "land", "wrong_fragment", "urgent"
		    , "hot", "num_failed_logins", "logged_in", "num_compromised"
		    , "root_shell", "su_attempted", "num_root", "num_file_creations"
		    , "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login"
		    , "is_guest_login", "count", "srv_count", "serror_rate"
		    , "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate"
		    , "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count"
		    , "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate"
		    , "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
		    , "class", "unknown"]
		attack_type_mapping = dict(zip(attack_type['class'], attack_type['type']))
		data['attackType'] = data['class'].map(attack_type_mapping)
		data = data.drop(['unknown'], axis = 1)
		data = data.drop(['class'], axis = 1)
		return data

	@staticmethod
	def process(data, start, end):
		y = data['isNormal'][start:end]
		dataX = pd.get_dummies(data.drop(['isNormal'], axis = 1))[start:end]
		X = dataX.values
		return X, y

	@staticmethod
	def compareClfs(clfs, trainX, trainY, testX, testY):
		# clfs is a dictionary of classifiers
		result = {}; bestErr = 1; bestName = ''
		for name,clf in clfs.iteritems():
			try:
				predictY = clf.best_estimator_.fit(trainX, trainY).predict(testX)
			except:
				predictY = clf.fit(trainX, trainY).predict(testX)
			result[name] = 1-np.mean(predictY==testY)
			print name,':',result[name]
			if result[name] < bestErr:
				bestErr = result[name]
				bestName = name
		print "Best classifier",bestName,':',bestErr
		return result

	@staticmethod
	def normalize(data):
		mu = data.select_dtypes(['float64', 'int64']).mean(axis=0)
		sigma = data.select_dtypes(['float64', 'int64']).std(axis=0)
		for column in data.select_dtypes(['float64', 'int64']).columns:
			data[column] = ( data[column] - mu[column] ) / sigma[column]
		return data