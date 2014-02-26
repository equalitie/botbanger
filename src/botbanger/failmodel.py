# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :

# This file is part of Fail2Ban.
#
# Fail2Ban is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Fail2Ban is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Fail2Ban; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Author: Cyril Jaquier
# 
# $Revision$

__author__ = "Vmon"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2012 Vmon"
__license__ = "GPL"

##
#  Fail Model class
#
# This class wrap the classfier which judge bad ips
import base64, pickle
import re, sre_constants

#necessary for the pickle to load the model
from os.path import dirname, abspath
from os import getcwd, chdir
import sys

try:
    src_dir  = dirname(abspath(__file__))
except NameError:
    #the best we can do to hope that we are in the test dir
    src_dir = dirname(getcwd())

learn2ban_dir = src_dir + "/learn2ban"
sys.path.append(learn2ban_dir)

class FailModel:

	##
	# Constructor.
	#
	# Creates a new object. This method can throw FailModelException in order to
	# avoid construction of invalid object.
	# @param failmodel the failmodel string
	
	def __init__(self, failmodel):
		#self.unwrap_model(failmodel) #later when bill update the model string
		self.load_model(failmodel)
	##
	# unpickle the model in new classifier 
	# for now the classifer can be only swm.linear
	# 

	##
	# Gets the classifier that is initialized by the model
	#
	# The effective regular expression used is returned.
	# @return the regular expression
	
	def load_model(self, base64_encoded_model):
	    """
	    For a given filename this function attempts to load a pickle
	    file as the current trainer model.
	    On success it returns true on failure it returns an error.
	    """
	    if (1 == 1):
#		try:
                        import pdb
			#pdb.set_trace()
			pickled_model = base64.b64decode(base64_encoded_model)
			pickle_object = {}
			pickle_object = pickle.loads(pickled_model)
			recon_model = pickle_object['model']
			self._ban_classifier = recon_model.ban_classifier
			self._normalisation_data = recon_model.normalisation_data
			#Why the classifier is unpickles as SVC instead of
			#SVC.linear?
			return True

#		except Exception, e:
#			return str(e)

	def getClassifier(self):
		return self._ban_classifier

	def getNormalisationData(self):
		return self._normalisation_data
	
	##
	# Searches the regular expression.
	#
	# Sets an internal cache (match object) in order to avoid searching for
	# the pattern again. This method must be called before calling any other
	# method of this object.
	# @param value the line
	
	# def search(self, value):
	# 	self._matchCache = self._host_regexObj.search(value)
	
	# ##
	# # Checks if the previous call to search() matched.
	# #
	# # @return True if a match was found, False otherwise
	
	# def hasMatched(self):
	# 	if self._matchCache:
	# 		return True
	# 	else:
	# 		return False


	# ##
	# # Returns the matched host.
	# #
	# # This corresponds to the pattern matched by the named group "host".
	# # @return the matched host
	
	# def getHost(self):
	# 	host = self._matchCache.group("host")
	# 	if host == None:
	# 		# Gets a few information.
	# 		s = self._matchCache.string
	# 		r = self._matchCache.re
	# 		raise RegexException("No 'host' found in '%s' using '%s'" % (s, r))
	# 	return host

##
# Exception dedicated to the class FailModel.

class FailModelException(Exception):
	pass


