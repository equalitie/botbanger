Botbanger
=========

Detector of malicious requesters identified via pre-learned SVM Learn2ban model

Copyright 2013 eQualit.ie

Botbanger is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see `<http://www.gnu.org/licenses/>`.

Installation
============

Other than cloning the git hub repo there is no need installation for Botbanger other than Python 2.7. However, in order to run Botbanger you will need to have already created a Learn2ban pickled model. See `https://github.com/equalitie/Learn2ban` for more details on creating a Learn2ban model.

Testing:
--------
Run python unit tests in the botbanger/src/test/ directory to ensure functionality.


Configuration
=============
Once you have created a Learn2ban model pickle place it in the directory botbanger/src/conf and edit the botbanger.conf file giving it the name of the pickled model.

Running
=======
In src directory run

    python botbanger.py -L /path/to/logfile.log

You need to have the botsniffer filter of Banjax enabled to submit request details to banger.
 
This project forms part of the [Deflect](https://deflect.ca) project.
