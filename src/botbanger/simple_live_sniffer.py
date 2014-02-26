"""
SimpleLiveSniffer

This is a simple sniffer, when ever it receive a new record it adds it to the 
feature db and re-predict the botness of the ip associated with the record
TODO: The db for now grow for ever, records need to be dropped after while.

AUTHORS: Vmon (C) Equalit.ie August 2013: Initial version

"""
import logging

from bot_sniffer import BotSniffer

#Learn to ban modules
from learn2ban.features import *
from learn2ban.features.learn2ban_feature import Learn2BanFeature
from learn2ban.ip_sieve import IPSieve, ATSRecord
from learn2ban.train2ban import TrainingSet

from failmodel import FailModel, FailModelException

from collections import OrderedDict

# Gets the instance of the logger.
logging = logging.getLogger("fail2ban.filter")

class SimpleLiveSniffer(BotSniffer):
    ##
    # Gets all the failure in the log file.
    #
    # Gets all the failure in the log file which are newer than
    # MyTime.time()-self.findTime. When a failure is detected, a FailTicket
    # is created and is added to the FailManager.

    MAX_LOG_DB_SIZE = 1000000 #maximum number of ats record in memory
    def __init__(self):
        """
        Calls the parent constructor then initializes a ip_dictionary
        """
        super(SimpleLiveSniffer, self).__init__()
        self._ip_log_db = OrderedDict()
        self._log_rec_counter = 0
        
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

    def _gather_all_features(self, cur_rec_dict):
        """
        Set the ip_sieve log equal to the cur ip's history and 
        compute features  from feature list for that ip only
        """
        #check for too much memory consumption
        if (self._log_rec_counter == self.MAX_LOG_DB_SIZE):
            oldest_rec = self._ip_log_db.popitem(last=False)
            self._log_rec_counter -= (len(oldest_rec[1]) -1)
        else:
            self._log_rec_counter += 1

        print "no of ips", len(self._ip_log_db), " no of log recs", self._log_rec_counter

        cur_ip = cur_rec_dict["host"]
        cur_ats_rec = ATSRecord(cur_rec_dict)
        if not cur_ip in self._ip_log_db:
            self._ip_log_db[cur_ip] = [cur_ats_rec]
        else:
            #get rid of old session
            if cur_ats_rec.time_to_second() - self._ip_log_db[cur_ip][-1].time_to_second() > self._ip_sieve.DEAD_SESSION_PAUSE:
                self._log_rec_counter -= (len(self._ip_log_db[cur_ip]) - 1)
                self._ip_log_db[cur_ip] = []

            self._ip_log_db[cur_ip].append(cur_ats_rec)
        
        self._ip_sieve.set_pre_seived_order_records(dict(((cur_ip, self._ip_log_db[cur_ip]),)))
        
        ip_feature_db = {}
        for cur_feature_name in self._feature_list:
            cur_feature_tester = self._available_features[cur_feature_name](self._ip_sieve, ip_feature_db)
            cur_feature_tester.compute()

        print ip_feature_db
        return ip_feature_db

    def is_this_a_bot(self, cur_rec_dict):
        """
        Gets an ATS record and add the rec to the log database. Then re-compute the
        features and call the classifier to rejudge the ip.

        INPUT:
            ats_record: the record of the new request to ats
        
        """
        return len(self._predict_failure(self._gather_all_features(cur_rec_dict))) > 0
