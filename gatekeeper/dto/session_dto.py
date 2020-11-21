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


from flask_restplus import Namespace, fields

from gatekeeper.blueprint.v1.session import namespace


class SessionDto:
    """Request and Respons Data Transfer Object."""

    request = namespace.model('session_request', {
        'identity' : fields.String(required = True, description = ''),
        'password' : fields.String(required = True, description = '')
    })

    response = namespace.model('session_response', {})
