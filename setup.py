import os
from setuptools import setup

setup(
    name = "botbanger",
    version = "1.0.0",
    author = "Vmon",
    author_email = "vmon@equalit.ie",
    description = "Model-based bot-banner",
    license = "GNU Affero",
    keywords = "banjax botnetdbp learn2ban",
    url = "http://github.com/equalitie/botbanger",
    packages=['botbanger'],
    package_dir={'':'src'},
    #long_description=read('README.md'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Daemons",
        "License :: GNU Affero License",
        ],
    scripts = ["src/botbanger.py"],
    data_files=[
        ("/etc/botbanger", ["conf/botbanger.conf"])
        ],
    )
