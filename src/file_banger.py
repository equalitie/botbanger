"""
AIFilter

A fail2ban filter class which can use classifiers such as svm to decide
which IP to ban. However, it still support the normal Regex filters

AUTHORS: Vmon (C) 2012: Initial version

"""
import logging

#Learn to ban modules
from learn2ban.features import *
from bot_sniffer import BotSniffer

from learn2ban.features.learn2ban_feature import Learn2BanFeature
from learn2ban.ip_sieve import IPSieve
from learn2ban.train2ban import TrainingSet

from failmodel import FailModel, FailModelException

import pdb

# Gets the instance of the logger.
logging = logging.getLogger("fail2ban.filter")

class FileBanger(BotSniffer):
    ##
    # Gets all the failure in the log file.
    #
    # Gets all the failure in the log file which are newer than
    # MyTime.time()-self.findTime. When a failure is detected, a FailTicket
    # is created and is added to the FailManager.
    def getFailures(self, filename):
        """
        Overriden version of getFailures, this is because almost all
        features necessary to classifies the type of requester are 
        statistical and can not be derived from single entry.
        """
        # Try to open log file.
        try:
            container = open(filename)
        except Exception, e:
            logging.error("Unable to open %s" % filename)
            logging.exception(e)
            return False

        #because we also needs the log lines potentially for failModel, 
        #we store them in a list while reading them. 

        #It might be more efficient just to reset the file pointer, specially
        #now that all os caches disks aggressively
        #TODO: Consult bill on this issue, maybe we write a test program to 
        #to compare timing
        lines = list()
        while True:
            #Here we naively read all the lines one by one
            lines.append(container.readline())
            if (lines[-1] == ""):
                # The jail reached the bottom
                break

        container.close()

        #Now we send the lines to feature aggrigation unit only
        #we the filter has ml capability
        if (self._fail_models):
            return self._predict_failure(self._gather_all_features(lines))

    def _gather_all_features(self, log_lines):
        """
        Set the ip_sieve log equal to log_lines and compute features
        from feature list for all ips appearing in the logs.
        """
        self._ip_sieve.set_log_lines(log_lines)
        self._ip_sieve.parse_log()

        ip_feature_db = {}
        for cur_feature_name in self._feature_list:
            cur_feature_tester = self._available_features[cur_feature_name](self._ip_sieve, ip_feature_db)
            cur_feature_tester.compute()

        return ip_feature_db

