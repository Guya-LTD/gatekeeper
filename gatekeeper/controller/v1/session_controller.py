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


"""REST namespace Controller

Responses List :
    1xx -> :            Informational response - The request was received, continuing process
        * 100           Continue
        * 101           Switching Protocols
        * 102           Processing
        * 103           Early Hints (RFC 8297)

    2xx -> :            Successful - The request was successfully received, understood, and accepted
        * 200           Ok
        * 201           Created
        * 202           Accepted
        * 203           Non-Authoritative Information
        * 204           No Content
        * 205           Reset Content
        * 206           Partial Content
        * 207           Multi-Status
        * 208           Already Reported
        * 226           IM Used

    3xx -> :            Redirection - Further action needs to be taken in order to complete the request
        * 300           Multiple Choices
        * 301           Moved Permanently
        * 302           Found (Previously "Moved temporarily")
        * 303           See Other
        * 304           Not Modified
        * 305           Use Proxy
        * 306           Switch Proxy
        * 307           Temporary Redirect
        * 308           Permanent Redirect

    4xx -> :            Client Error - The request contains bad syntax or cannot be fulfilled
        * 400           Bad  Request
        * 401           Unauthorized
        * 402           Payment Required
        * 403           Forbidden
        * 404           Not Found
        * 405           Method Not Allowed
        * 406           Not Acceptable
        * 407           Proxy Authentication Required
        * 408           Request Timeout
        * 409           Conflict
        * 410           Gone
        * 411           Length Required
        * 412           Precondition Failed
        * 413           Payload Too Large
        * 414           URI Too Long
        * 415           Unsupported Media Type
        * 416           Range Not Satisfiable
        * 417           Expection Failed
        * 418           I'm a teapot
        * 421           Misdirected Request
        * 422           Unprocessable Entity
        * 423           Locked
        * 424           Failed Dependency
        * 425           Too Early
        * 426           Upgrade Required
        * 428           Precondition Required
        * 429           Too Many Requests
        * 431           Request Header Fields Too Large
        * 451           Unavailable For Legal Reasons

    5xx -> :            Server Error - The server failed to fulfil an apparently valid request
        * 500           Internal Server Error
        * 501           Not Implemented
        * 502           Bad Gateway
        * 503           Service Unavaliable
        * 504           Gateway Timeout
        * 505           HTTP Version Not Supported
        * 506           Variant Also Negotiates
        * 507           Insufficent Storage
        * 508           Loop Detected
        * 510           Not Extended
        * 511           Network Authentication Required


Functions:
    * get - returns list of datas
    * post - returns creation status with the newly created resource link
    * put - return update status with the the newly updated resource link
    * patch - returns the semi updated status with the newly semi updated resource link
    * delete - return delation status

"""

import re
import os
import uuid
import jwt
import datetime
import requests
from flask import request, jsonify, make_response
from flask_restplus import Resource

from gatekeeper.exception import ValueEmpty
from gatekeeper.dto.session_dto import SessionDto
from gatekeeper.blueprint.v1.session import namespace

# ENDPOINT URLS
USER_CREDENTIAL_URL = 'http://' + os.getenv('USER_URL') + '/credentials'
# MOCKING ENDPOINT URL
#USER_CREDENTIAL_URL = 'http://' + os.getenv('MOCKING_SERVER_URL') + '/api/v1/credentials'

# JWT
JWT_ALGORITHM = 'HS256'
# 30 day
JWT_EXPIRES = datetime.datetime.utcnow() + datetime.timedelta(days = 30)


@namespace.route('')
@namespace.response(100, 'Continue')
@namespace.response(101, 'Switching Protocols')
@namespace.response(102, 'Processing')
@namespace.response(103, 'Early Hints (RFC 8297)')
@namespace.response(200, 'Ok')
@namespace.response(201, 'Created')
@namespace.response(202, 'Accepted')
@namespace.response(203, 'Non-Authoritative Information')
@namespace.response(204, 'No Content')
@namespace.response(205, 'Reset Content')
@namespace.response(206, 'Partial Content')
@namespace.response(207, 'Multi-Status')
@namespace.response(208, 'Already Reported')
@namespace.response(226, 'IM Used')
@namespace.response(300, 'Multiple Choices')
@namespace.response(301, 'Moved Permanently')
@namespace.response(302, 'Found (Previously "Moved temporarily")')
@namespace.response(303, 'See Other')
@namespace.response(304, 'Not Modified')
@namespace.response(305, 'Use Proxy')
@namespace.response(306, 'Switch Proxy')
@namespace.response(307, 'Temporary Redirect')
@namespace.response(308, 'Permanent Redirect')
@namespace.response(400, 'Bad  Request')
@namespace.response(401, 'Unauthorized')
@namespace.response(402, 'Payment Required')
@namespace.response(403, 'Forbidden')
@namespace.response(404, 'Not Found')
@namespace.response(405, 'Method Not Allowed')
@namespace.response(406, 'Not Acceptable')
@namespace.response(407, 'Proxy Authentication Required')
@namespace.response(408, 'Request Timeout')
@namespace.response(409, 'Conflict')
@namespace.response(410, 'Gone')
@namespace.response(411, 'Length Required')
@namespace.response(412, 'Precondition Failed')
@namespace.response(413, 'Payload Too Large')
@namespace.response(414, 'URI Too Long')
@namespace.response(415, 'Unsupported Media Type')
@namespace.response(416, 'Range Not Satisfiable')
@namespace.response(417, 'Expection Failed')
@namespace.response(418, 'I\'m a teapot')
@namespace.response(421, 'Misdirected Request')
@namespace.response(422, 'Unprocessable Entity ')
@namespace.response(423, 'Locked')
@namespace.response(424, 'Failed Dependency')
@namespace.response(425, 'Too Early')
@namespace.response(426, 'Upgrade Required')
@namespace.response(428, 'Precondition Required')
@namespace.response(429, 'Too Many Requests')
@namespace.response(431, 'Request Header Fields Too Large')
@namespace.response(451, 'Unavailable For Legal Reasons')
@namespace.response(500, 'Internal Server Error')
@namespace.response(501, 'Not Implemented')
@namespace.response(502, 'Bad Gateway')
@namespace.response(503, 'Service Unavaliable')
@namespace.response(504, 'Gateway Timeout')
@namespace.response(505, 'HTTP Version Not Supported')
@namespace.response(506, 'Variant Also Negotiates')
@namespace.response(507, 'Insufficent Storage')
@namespace.response(508, 'Loop Detected')
@namespace.response(510, 'Not Extended')
@namespace.response(511, 'Network Authentication Required')
class SessionsResource(Resource):
    """Session Related Operation

    ...

    `asc'  +
    `desc` -


    Attributes
    ----------
    LIMIT : Integer
        Max allowed rows

    Methods
    -------
    get() :
        Get All/Semi datas from database

    post() :
        Save data/datas to database

    """ 

    @namespace.expect(SessionDto.request, validate = True)
    def post(self):
        """Save data/datas to database

        ...

        Returns
        -------
            Json Dictionaries

        """
        ## This api endpoint creates session

        # start by validating request fields for extra security
        # step 1 validation: strip payloads for empty string
        if not namespace.payload['identity'].strip() or \
           not namespace.payload['password'].strip():
           raise ValueEmpty({'payload': namespace.payload})

        # call user's credential end point
        user_credential_req = requests.get(USER_CREDENTIAL_URL, data = namespace.payload)
        # Check if response is ok
        if user_credential_req.status_code == 200:
            # Convert response to json
            user_credential = user_credential_req.json()
            # Payload to be stored in jwt token
            jwt_payload = {
                'exp': JWT_EXPIRES,
            }
            # Append the respond data to jwt payload
            jwt_payload.update(user_credential)
            # Encode jwt
            encoded_jwt = jwt.encode(user_credential, os.getenv('SECRET_KEY'), algorithm = JWT_ALGORITHM)
            print(encoded_jwt)
            return make_response(jsonify({
                'status_code': 201,
                'status': 'Created',
                'message': 'New Session Created',
                'data': {
                    'token': encoded_jwt.decode("utf-8"),
                    'token_type': 'Bearer',
                    'expires': JWT_EXPIRES
                }
            }), 201)
        elif user_credential_req.status_code == 204: # No content
            return make_response(jsonify({
                'status_code': 401,
                'status': 'Unauthorized',
                'message': 'Either User is not found or credential is wrong'
            }), 401)
        else:
            print(user_credential_req)
            return make_response(jsonify(user_credential_req.text),user_credential_req.status_code)




@namespace.route('/<string:id>')
@namespace.response(100, 'Continue')
@namespace.response(101, 'Switching Protocols')
@namespace.response(102, 'Processing')
@namespace.response(103, 'Early Hints (RFC 8297)')
@namespace.response(200, 'Ok')
@namespace.response(201, 'Created')
@namespace.response(202, 'Accepted')
@namespace.response(203, 'Non-Authoritative Information')
@namespace.response(204, 'No Content')
@namespace.response(205, 'Reset Content')
@namespace.response(206, 'Partial Content')
@namespace.response(207, 'Multi-Status')
@namespace.response(208, 'Already Reported')
@namespace.response(226, 'IM Used')
@namespace.response(300, 'Multiple Choices')
@namespace.response(301, 'Moved Permanently')
@namespace.response(302, 'Found (Previously "Moved temporarily")')
@namespace.response(303, 'See Other')
@namespace.response(304, 'Not Modified')
@namespace.response(305, 'Use Proxy')
@namespace.response(306, 'Switch Proxy')
@namespace.response(307, 'Temporary Redirect')
@namespace.response(308, 'Permanent Redirect')
@namespace.response(400, 'Bad  Request')
@namespace.response(401, 'Unauthorized')
@namespace.response(402, 'Payment Required')
@namespace.response(403, 'Forbidden')
@namespace.response(404, 'Not Found')
@namespace.response(405, 'Method Not Allowed')
@namespace.response(406, 'Not Acceptable')
@namespace.response(407, 'Proxy Authentication Required')
@namespace.response(408, 'Request Timeout')
@namespace.response(409, 'Conflict')
@namespace.response(410, 'Gone')
@namespace.response(411, 'Length Required')
@namespace.response(412, 'Precondition Failed')
@namespace.response(413, 'Payload Too Large')
@namespace.response(414, 'URI Too Long')
@namespace.response(415, 'Unsupported Media Type')
@namespace.response(416, 'Range Not Satisfiable')
@namespace.response(417, 'Expection Failed')
@namespace.response(418, 'I\'m a teapot')
@namespace.response(421, 'Misdirected Request')
@namespace.response(422, 'Unprocessable Entity ')
@namespace.response(423, 'Locked')
@namespace.response(424, 'Failed Dependency')
@namespace.response(425, 'Too Early')
@namespace.response(426, 'Upgrade Required')
@namespace.response(428, 'Precondition Required')
@namespace.response(429, 'Too Many Requests')
@namespace.response(431, 'Request Header Fields Too Large')
@namespace.response(451, 'Unavailable For Legal Reasons')
@namespace.response(500, 'Internal Server Error')
@namespace.response(501, 'Not Implemented')
@namespace.response(502, 'Bad Gateway')
@namespace.response(503, 'Service Unavaliable')
@namespace.response(504, 'Gateway Timeout')
@namespace.response(505, 'HTTP Version Not Supported')
@namespace.response(506, 'Variant Also Negotiates')
@namespace.response(507, 'Insufficent Storage')
@namespace.response(508, 'Loop Detected')
@namespace.response(510, 'Not Extended')
@namespace.response(511, 'Network Authentication Required')
class SessionResource(Resource):
    """"Single Foobar Related Operation

    ...

    Methods
    -------
    get(id:String) :
        Get a data from database

    put(id:String) :
        Update a data from database

    delete(id:String) :
        Delete a data from database

    """

    def post(self, id):
        """Get All/Semi datas from database

        ...

        Parameters
        ----------
        id : integer
            Object Id, i.e 12-byte, 24 char hexadicmal

        Returns
        -------
            Json Dictionaries

        """
        if not request.headers.get('Authorization').strip():
            raise ValueEmpty({'id': request.headers.get('Authorization')})

        ## Decode jwt token
        encoded_jwt = re.match("^Bearer\s+(.*)", request.headers.get("Authorization"))
        try:
            decoded_jwt = jwt.decode(encoded_jwt.group(1), os.getenv('SECRET_KEY'), algorithms = [JWT_ALGORITHM])
            return make_response(jsonify({
                'status_code': 201,
                'status': 'Created',
                'message': 'Jwt token decoded',
                'data': decoded_jwt
            }), 201)
        except jwt.ExpiredSignatureError as ex:
            ## Signature has expired
            return make_response(jsonify({
                'status_code': 401,
                'status': 'Unauthorize',
                'message': 'Invalid token key',
                'error': {
                    'message': ex,
                    'type': 'jwt.ExpiredSignatureError'
                }
            }), 401)
        except jwt.DecodeError as ex:
            ## Decoding Failed
            return make_response(jsonify({
                'status_code': 401,
                'status': 'Unauthorize',
                'message': 'Failed to decode token. token might be invalid',
                'error': {
                    'message': str(ex),
                    'type': 'jwt.DecodeError'
                }
            }), 401)
