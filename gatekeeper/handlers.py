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


"""This module registers the error handler on the application."""


from flask import jsonify
import redis
from werkzeug.exceptions import HTTPException, default_exceptions
import requests

from .log import log_exception


def register_handler(app):
    """Registers the error handler is a function to common error HTTP codes

    Parameters:
    ----------
        app (flask.app.Flask): The application instance.
    """

    ################################################################
    #                                                              #
    # generic error handlers                                       #
    #                                                              #
    ################################################################

    def generic_http_error_handler(error):
        """Deal with HTTP exceptions.

        Parameters:
        ----------
            error (HTTPException): A werkzeug.exceptions.BadRequest exception object.

        Returns:
        -------
            A flask response object.
        """
        if isinstance(error, HTTPException):
            result = {
                'status_code': error.code,
                'status': '',
                'message': error.description,
                'error': str(error.update({'type': 'HTTPException'}))}
        else:
            result = {
                'status_code': 500,
                'status': 'Internal Server Error',
                'message': error.description,
                'error': str(error.update({'type': 'Other Exceptions'}))}

        log_exception(error = error, extra = result)
        resp = jsonify(result)
        resp.status_code = result['code']
        return resp


    # redis client Exception handler
    def redis_generic_error_handler(error):
        """Deal with mongoengine exceptions.

        Parameters:
        ----------
            error (r.RedisError): Core exceptions raised by the Redis client.

            code int: An HTTP status code.

        Returns:
        -------
            A flask response object.
        """
        # formatting the exception
        result = {
            'status_code': 500, 
            'status': 'Internal Server Error', 
            'message': error.description,
            'error': str(error.update({'type': 'RedisError'}))}

        # logg exception
        log_exception(error = error, extra = result)
        resp = jsonify(result)
        resp.status_code = 500
        return resp

    # requests exceptions
    def requests_generic_error_handler(error):
        custome_error = {
            'type': 'requests',
            'message': str(error)
        }
        # formatting the exception
        result = {
            'status_code': 500,
            'status': 'Internal Server Error',
            'message': 'Error caused form calling other RESTful API',
            'error': custome_error
        }

        # logg exception
        log_exception(error = error, extra = result)
        resp = jsonify(result)
        resp.status_code = 500
        return resp

    
    # request exceptions
    def requests_request_exception(error):
        return requests_generic_error_handler(error)

    def requests_connection_error(error):
        return requests_generic_error_handler(error)

    def requests_http_error(error):
        return requests_generic_error_handler(error)

    def requests_url_required(error):
        return requests_generic_error_handler(error)

    def requests_tomany_redirects(error):
        return requests_generic_error_handler(error)

    def requests_connect_timeout(error):
        return requests_generic_error_handler(error)

    def requests_readtimeout(error):
        return requests_generic_error_handler(error)

    def request_timeout(error):
        return requests_generic_error_handler(error)
        
    # redis exceptions
    def redis_connection_error(error):
        return redis_generic_error_handler(error)

    def redis_timeout_error(error):
        return redis_generic_error_handler(error)

    def redis_authentication_error(error):
        return redis_generic_error_handler(error)

    def redis_busy_loading_error(error):
        return redis_generic_error_handler(error)

    def redis_invalid_response_error(error):
        return redis_generic_error_handler(error)

    def redis_response_error(error):
        return redis_generic_error_handler(error)

    def redis_data_error(error):
        return redis_generic_error_handler(error)

    def redis_pub_sub_error(error):
        return redis_generic_error_handler(error)

    def redis_watch_error(error):
        return redis_generic_error_handler(error)

    def redis_no_script_error(error):
        return redis_generic_error_handler(error)

    def redis_exec_abort_error(error):
        return redis_generic_error_handler(error)

    def redis_read_only_error(error):
        return redis_generic_error_handler(error)

    def redis_no_permission_error(error):
        return redis_generic_error_handler(error)

    def redis_module_error(error):
        return redis_generic_error_handler(error)

    def redis_lock_error(error):
        return redis_generic_error_handler(error)

    def redis_lock_not_owned_error(error):
        return redis_generic_error_handler(error)

    def redis_child_deadlock_error(error):
        return redis_generic_error_handler(error)

    def redis_authentication_wrong_number_of_args_error(error):
        return redis_generic_error_handler(error)

    ################################################################
    #                                                              #
    # register exception handlers to flask                         #
    #                                                              #
    ################################################################

    # register http status codes
    for code in default_exceptions.keys():
        app.register_error_handler(code, generic_http_error_handler)


    # redis 
    app.register_error_handler(redis.ConnectionError, redis_connection_error)
    app.register_error_handler(redis.TimeoutError,redis_timeout_error)
    app.register_error_handler(redis.AuthenticationError,redis_authentication_error)
    app.register_error_handler(redis.BusyLoadingError,redis_busy_loading_error)
    app.register_error_handler(redis.InvalidResponse,redis_invalid_response_error)
    app.register_error_handler(redis.ResponseError,redis_response_error)
    app.register_error_handler(redis.DataError,redis_data_error)
    app.register_error_handler(redis.PubSubError,redis_pub_sub_error)
    app.register_error_handler(redis.WatchError,redis_watch_error)
    #app.register_error_handler(redis.NoScriptError,redis_no_script_error)
    #app.register_error_handler(redis.ExecAbortError,redis_exec_abort_error)
    app.register_error_handler(redis.ReadOnlyError,redis_read_only_error)
    #app.register_error_handler(redis.NoPermissionError,redis_no_permission_error)
    #app.register_error_handler(redis.ModuleError,redis_module_error)
    #app.register_error_handler(redis.LockError,redis_lock_error)
    #app.register_error_handler(redis.LockNotOwnedError,redis_lock_not_owned_error)
    app.register_error_handler(redis.ChildDeadlockedError,redis_child_deadlock_error)
    app.register_error_handler(redis.AuthenticationWrongNumberOfArgsError,redis_authentication_wrong_number_of_args_error)


    # requests
    app.register_error_handler(requests.RequestException, requests_request_exception)
    app.register_error_handler(requests.ConnectionError, requests_connection_error)
    app.register_error_handler(requests.HTTPError, requests_http_error)
    app.register_error_handler(requests.URLRequired, requests_url_required)
    app.register_error_handler(requests.TooManyRedirects, requests_tomany_redirects)
    app.register_error_handler(requests.ConnectTimeout, requests_connect_timeout)
    app.register_error_handler(requests.ReadTimeout, requests_readtimeout)
    app.register_error_handler(requests.Timeout, request_timeout)