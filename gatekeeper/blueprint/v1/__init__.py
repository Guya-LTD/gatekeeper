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


Blueprint to v1 and group, related endpoint of HTTP REST API.
"""

from flask import Blueprint
from flask_restplus import Api


blueprint = Blueprint('apiv1', __name__)

api = Api(
    blueprint,
    title = 'Gatekeeper Authenticator Service',
    version = '1.0.0',
    description = 'Guyas Authintactor Service',
)
