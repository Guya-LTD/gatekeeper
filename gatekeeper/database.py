# -*- coding: utf-8 -*-

"""Copyright Header Details

Copyright
---------
    Copyright (C) Guya , PLC - All Rights Reserved (As Of Pending...)
    Unauthorized copying of this file, via any medium is strictly prohibited
    Proprietary and confidential

LICENSE
-------
    This file is subject to the terms and conditions defined in
    file 'LICENSE.txt', which is part of this source code package.

Authors
-------
    * [Simon Belete](https://github.com/Simonbelete)

Project
-------
    * Name:
        - Guya E-commerce & Guya Express
    * Sub Project Name:
        - Gatekeeper Authenticator Service
    * Description
        - Guyas Authintactor Service
"""


"""Package details

Application features:
--------------------
    Python 3.7
    Flask
    PEP-8 for code style


This module provides means to perform operations on the database.
"""

import os
import redis
from flask import Flask
from dotenv import load_dotenv

# global vars
r = None

def init(app: Flask) -> None:
    """This function initialize the datase ORM/ODM, providing a session
    and command line to create the tables/document in the database.

    Parameters:
    ----------
        app (flask.app.Flask): The application instance.
    """
    global r

    load_dotenv()

    r = redis.Redis(
            host = os.environ.get('REDIS_HOST'),
            port = int(os.environ.get('REDIS_PORT')),
            db = os.environ.get('REDIS_DB'),
            decode_responses=True
        )

    r.ping()