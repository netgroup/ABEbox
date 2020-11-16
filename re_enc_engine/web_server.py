"""
This file contains all functions required to run the Re-Encryption Engine web server and to handle HTTP incoming
requests.
"""

from flask import Blueprint, Flask, request
from flask_restx import Resource, Api, fields
from re_enc_engine.function_utils import init_logger
from urllib.parse import parse_qs, urlparse

import argparse
import json
import logging
import re_enc_engine.const as const
import re_enc_engine.request_handler as handler

# =================================================== FLASK SERVER =================================================== #

app = Flask(__name__, root_path=const.ROOT_PATH + const.FLASK_ROOT_PATH)
api = Api(app)
ns = api.namespace('', description='APIs to communicate with Re-Encryption Engine web server')

debug = 1


@ns.route('/' + const.GET_COMPANY_ROOT_DIR)
class GetCompanyRootDir(Resource):

    # Model for request parameters structure
    input_model = api.model('Params', {
        const.COMPANY_ID: fields.String,
    })

    # Model for request response structure
    output_model = api.model('Response', {
        const.COMPANY_ID: fields.String,
    })

    @api.doc('Generate an unique root directory for the applying company.')
    @api.expect(input_model)
    @api.response(const.OK, 'Company root directory correctly created!', output_model)
    @api.response(const.NO_RESULT[1], const.NO_RESULT[0])
    def get(self):
        """
        Generate an unique root directory for the applying company.
        :return: The root directory name or an error
        """

        logging.info('POST request received on /' + const.GET_COMPANY_ROOT_DIR)
        logging.info('Parsing request body...')

        if debug:  # ONLY USE FOR DEBUG
            print('POST request received on /' + const.GET_COMPANY_ROOT_DIR)
            print('Parsing request body...')

        # Extract parameters from the request
        request_params = parse_qs(urlparse(request.url).query)

        # Check if there are all required parameters
        if not handler.check_request_params(request_params.keys(), const.GET_COMPANY_ROOT_DIR_PARAMS):

            logging.error('Missing params!')

            if debug:  # ONLY USE FOR DEBUG
                print('Missing params!')

            return const.BAD_REQ[0], const.BAD_REQ[1]

        # Get company ID from request url
        company_id = request_params[const.COMPANY_ID][0]

        logging.info('Request body successfully parsed!')
        logging.info('Getting unique company root directory...')

        if debug:  # ONLY USE FOR DEBUG
            print('Request body successfully parsed!')
            print('Getting unique company root directory...')

        # Get an unique ID used as root directory for the given company ID
        unique_root_dir = handler.get_company_root_dir(company_id, debug)

        # Check if an error occurred
        if unique_root_dir is None:

            logging.error('Unique company root directory could not be created!')

            if debug:  # ONLY USE FOR DEBUG
                print('Unique company root directory could not be created!')

            return const.NO_RESULT[0], const.NO_RESULT[1]

        logging.error('Unique company root directory successfully created!')

        if debug:  # ONLY USE FOR DEBUG
            print('Unique company root directory successfully created!')

        return json.dumps({const.COMPANY_ID: unique_root_dir}), const.OK


@ns.route('/' + const.GET_FILES_LIST)
class GetFilesList(Resource):

    # Model for request parameters structure
    input_model = api.model('Params', {
        const.COMPANY_ID: fields.String,
    })

    # Model for request response structure
    output_model = api.model('Response', {
        const.FILES_LIST: fields.List(fields.String),
    })

    @api.doc('Send the list of csv files stored into the server.')
    @api.expect(input_model)
    @api.response(const.OK, 'Files list found!', output_model)
    @api.response(const.NO_RESULT[1], const.NO_RESULT[0])
    def get(self):
        """
        Send the list of csv files stored into the server.
        :return: The files list in the specific root directory or an error
        """

        logging.info('POST request received on /' + const.GET_FILES_LIST)
        logging.info('Parsing request body...')

        if debug:  # ONLY USE FOR DEBUG
            print('POST request received on /' + const.GET_FILES_LIST)
            print('Parsing request body...')

        # Extract parameters from the request
        request_params = parse_qs(urlparse(request.url).query)

        # Check if there are all required parameters
        if not handler.check_request_params(request_params.keys(), const.GET_FILES_LIST_PARAMS):

            logging.error('Missing params!')

            if debug:  # ONLY USE FOR DEBUG
                print('Missing params!')

            return const.BAD_REQ[0], const.BAD_REQ[1]

        # Get company ID from request url
        company_id = request_params[const.COMPANY_ID][0]

        logging.info('Request body successfully parsed!')
        logging.info('Getting list of files in specified directory...')

        if debug:  # ONLY USE FOR DEBUG
            print('Request body successfully parsed!')
            print('Getting list of files in specified directory...')

        # Get list of files in the specific directory
        files_list = handler.get_files_list(company_id + '/' + const.STORAGE_PATH, debug)

        # Check if an error occurred
        if files_list is None:

            logging.error('Files list could not be obtained!')

            if debug:  # ONLY USE FOR DEBUG
                print('Files list could not be obtained!')

            return const.NO_RESULT[0], const.NO_RESULT[1]

        logging.error('Files list successfully obtained!')

        if debug:  # ONLY USE FOR DEBUG
            print('Files list successfully obtained!')

        return json.dumps({const.FILES_LIST: files_list}), const.OK


@ns.route('/' + const.SEND_RE_ENC_INFO)
class SendReEncInfo(Resource):

    # Models for request parameters structure
    input_model1 = api.model('Params', {
        const.COMPANY_ID: fields.String,
        const.TIMELY: fields.Boolean(),
        const.TIME_INTERVAL: fields.Integer(min=0),
        const.FULL: fields.Boolean,
        const.RE_ENC_DATA: fields.List(fields.Nested(api.model('File re-encryption info', {
            const.FILE_NAME: fields.String,
            const.PUB_KEYS: fields.List(fields.String),
            const.POLICIES: fields.List(fields.String),
            const.RE_ENC_LENGTHS: fields.List(fields.Integer)
        })), description='Used if file-level re-encryption is required (full = False)')
    })

    input_model2 = api.model('Params', {
        const.COMPANY_ID: fields.String,
        const.TIMELY: fields.Boolean(),
        const.TIME_INTERVAL: fields.Integer(min=0),
        const.FULL: fields.Boolean,
        const.RE_ENC_DATA: fields.List(fields.Nested(api.model('Full root directory re-encryption info', {
            const.PUB_KEYS: fields.List(fields.String),
            const.POLICIES: fields.List(fields.String),
            const.RE_ENC_LENGTHS: fields.List(fields.Integer)
        })), description='Used if directory-level re-encryption is required (full = True)')
    })

    @api.expect(input_model1)
    @api.expect(input_model2)
    @api.response(const.OK, 'Re-encryption success!')
    @api.response(const.NO_RESULT[1], const.NO_RESULT[0])
    def post(self):
        """
        Try to execute the specified re-encryption operation.
        :return: Success or an error
        """

        logging.info('POST request received on /' + const.SEND_RE_ENC_INFO)
        logging.info('Getting request body...')

        if debug:  # ONLY USE FOR DEBUG
            logging.info('POST request received on /' + const.SEND_RE_ENC_INFO)
            logging.info('Obtaining request body...')

        # Parse request body
        re_enc_data = request.form
        pub_key_files = request.files

        # Check if there are all required parameters
        if not handler.check_request_params([key for key in re_enc_data.keys()], const.SEND_RE_ENC_INFO_PARAMS):

            logging.error('Missing params!')

            if debug:  # ONLY USE FOR DEBUG
                print('Missing params!')

            return const.BAD_REQ[0], const.BAD_REQ[1]

        logging.info('Request body successfully obtained!')
        logging.info('Saving sent public key files...')

        if debug:  # ONLY USE FOR DEBUG
            print('Request body successfully obtained!')
            print('Saving sent public key files...')

        # Save sent public key files
        handler.save_files(pub_key_files, re_enc_data[const.COMPANY_ID] + '/' + const.KEY_PATH, debug)

        logging.info('Public key files saved!')
        logging.info('Starting re-encryption process...')

        if debug:  # ONLY USE FOR DEBUG
            print('Public key files saved!')
            print('Starting re-encryption process...')

        # Handle re-encryption operations
        handler.send_re_enc_info.send(re_enc_data, debug)

        logging.info('Re-encryption process started!')

        if debug:  # ONLY USE FOR DEBUG
            print('Re-encryption process started')

        return const.OK


def initialise_app(flask_app):
    """
    Initialise application creating and configuring the web server.
    :param flask_app: Flask application web server info
    """

    api_blueprint = Blueprint('api', __name__, url_prefix='/api')
    api.init_app(api_blueprint)
    api.add_namespace(ns)
    flask_app.register_blueprint(api_blueprint)


if __name__ == '__main__':
    """
    Main function that runs the web server.
    """

    # Initialise logger
    init_logger()

    # Running documentation and input parameters definition
    parser = argparse.ArgumentParser(description='Flask server for proxy re-encryption operations',
                                     usage='web_server.py -a [IPADDR] -p [PORT] (default: -a localhost -p 9000)')
    parser.add_argument('-a', type=str, help='The IP address of the server', default='localhost')
    parser.add_argument('-p', type=int, help='The port of the server', default=9000)

    logging.info('Parsing starting input arguments...')

    # Parse input parameters
    args = parser.parse_args()

    logging.info('Starting input arguments parsed!')
    logging.info('Verifying IP address format...')

    # Check if given IP address is valid
    if handler.is_valid_ip(args.a, debug):

        logging.info('IP address is valid!')
        logging.info('Starting Flask web server...')

        # Initialise and launch the web server
        initialise_app(app)
        app.run(host=args.a, port=str(args.p))

    else:

        logging.error('Invalid IP address')

        if debug:  # ONLY USE FOR DEBUG
            print(const.INVALID_IP[0])
