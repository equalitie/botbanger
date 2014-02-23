"""
Unit test for the file_banger.py

- Vmon (vmon@equalit.ie) June 2013: initial version

"""

import unittest
from os.path import dirname, abspath
from os import getcwd, chdir
import sys

try:
    src_dir  = dirname(dirname(abspath(__file__)))
except NameError:
    #the best we can do to hope that we are in the test dir
    src_dir = dirname(getcwd())

sys.path.append(src_dir)

from file_banger import FileBanger
# from failmodel import FailModel
# import pdb;

from logfetcher import LogFetcher


def test_logfetcher_input():
            logFetcher = LogFetcher();

            cur_log_rec = {}
            cur_log_rec["host"] = "ben.com"
            cur_log_rec["time"] = 12345678
            cur_log_rec["request"] = "GET /https 1.0"
            cur_log_rec["type"] = "type_ex"
            cur_log_rec["status"] = 404
            cur_log_rec["size"] = 1025
            cur_log_rec["agent"] = "Firefox 5.0 Gecko"
            cur_log_rec["hit"] = "hits_ex"
            
            # check if we have a bot and ban it if necessary
            logFetcher.ban_if_bot(cur_log_rec)

class BasicTest(unittest.TestCase):
    def setUp(self):
        """ 
        Call before all tests.
        Loads the pickled model into the FailModel object
        """
        model_file = open("test_model.txt")
        self.model_string = model_file.read()
        self.test_file_banger = FileBanger();
        
        self.test_file_banger.addFailModel(self.model_string);

    def test_find_ban_in_file(self):
        """
        Open the test log file and examine each IP upon the test model to know
        if it should be banned. Print the list of banned IPs at the end.
        """
        print self.test_file_banger.getFailures("deflect_test.log");


if __name__ == "__main__":
    # unittest.main()
    test_logfetcher_input()



        
