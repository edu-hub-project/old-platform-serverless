import os
import time
from typing import Optional, Dict, Union, Any
import requests
from authlib.jose import jwt
import json
import yaml
import logging
import sys
import urllib
import base64
from datetime import datetime, timedelta


# [START functions_oc_zoom_http]
# [START functions_http_content]
from flask import escape
from flask import jsonify

# [END functions_oc_zoom_http]
# [END functions_http_content]

CONFIG_FILE = 'config.yaml'

# [START functions_oc_get_participants_meeting]


def oc_get_participants_meeting(request):
    """Get the participants from Zoom and returns the report.
    Args:
        request (flask.Request): HTTP request object.
        It must contains a field "meeting_id", otherwise the request will not be handled.
    Returns:
        the report for the participants from the Zoom API,
        containing name and information about the participants.
    """
    request_json = request.get_json()
    logging.info(f"json request: {request_json}")
    if request.args and 'meeting_id' in request.args:
        return request.args.get('meeting_id')
    elif request_json and 'meeting_id' in request_json:
        meeting_id = clear_meeting_id(request_json['meeting_id'])
        if not os.path.exists(CONFIG_FILE):
            return("No config file found")
        else:
            logging.info("trying to read config file")
            config = read_yaml(CONFIG_FILE)
            logging.info("read config file")
            zz = Zoom()
            zz.set_api_key(config['api-key'])
            zz.set_api_secret(config['api-secret'])
            zz.set_jwt_token(zz.generate_jwt_token())
            logging.info("generated token")
            API_response = zz.zoom_get_meeting_participants(meeting_id)
            logging.info(f"Zoom API response: {API_response}")
            logging.info(f"Zoom API response text: {API_response.text}")
            report = json.loads(API_response.text)
            if 'participants' in report.keys():
                # participants = report['participants']
                return report
            else:
                return "Report has no participants. Are you sure the meeting id is correct?\nReport:\n{API_response.text}"
    else:
        return 'No meeting ID given!'
# [END functions_oc_get_participants_meeting]

# [START oc_get_full_meeting_report]
def oc_get_full_meeting_report(request):
    """Get the participants from Zoom and returns the report.
    Args:
        request (flask.Request): HTTP request object.
        It must contains a field "meeting_id", otherwise the request will not be handled.
    Returns:
        the report for a meeting (not only participants) the Zoom API,
        containing information about meeting (date and time, name) and
        about the participants (name, time, mail).
    """
    request_json = request.get_json()
    logging.info(f"json request: {request_json}")
    if request.args and 'meeting_id' in request.args:
        return request.args.get('meeting_id')
    elif request_json and 'meeting_id' in request_json:
        meeting_id = clear_meeting_id(request_json['meeting_id'])
        if not os.path.exists(CONFIG_FILE):
            return("No config file found")
        else:
            logging.info("trying to read config file")
            config = read_yaml(CONFIG_FILE)
            logging.info("read config file")
            zz = Zoom()
            zz.set_api_key(config['api-key'])
            zz.set_api_secret(config['api-secret'])
            zz.set_jwt_token(zz.generate_jwt_token())
            logging.info("generated token")
            API_response = zz.zoom_get_meeting_participants(meeting_id)
            logging.info(f"Zoom API response: {API_response}")
            logging.info(f"Zoom API response text: {API_response.text}")

            if API_response.status_code == 200:
                meeting_report_API_response = zz.zoom_get_meeting_report(
                    meeting_id)
                meeting_report = json.loads(meeting_report_API_response.text)
                participants_report = json.loads(API_response.text)
                participants = participants_report['participants']
                meeting_report['participants_report'] = participants_report

                if 'participants' in participants_report.keys():
                    #participants = report['participants']
                    return meeting_report
                else:
                    return f"Report has no participants. Are you sure the meeting id is correct?\nReport:\n{API_response.text}"
            else:
                return f"Zoom API answered with {API_response} \n\nFull Text: {API_response.text}"
    else:
        return f'No meeting ID given!'
# [END oc_get_full_meeting_report]


# [START oc_get_participants_hybrid]
def oc_get_participants_hybrid(request):
    """Get the participants from Zoom and Limesurvey and returns a list.
    Args:
        request (flask.Request): HTTP request object.
        It must contains a field "meeting_id", otherwise the request will not be handled.
    Returns:
        the report for a meeting including
        the reponses from the Limesurvey Survey and
        the repport from the Zoom API,
        containing information about meeting (date and time, name) and
        about the participants (name, time, mail).
    """
    request_json = request.get_json()
    logging.info(f"json request: {request_json}")
    if request.args and 'meeting_id' in request.args:
        return request.args.get('meeting_id')
    elif request_json and 'meeting_id' in request_json:
        meeting_id = clear_meeting_id(request_json['meeting_id'])
        if not os.path.exists(CONFIG_FILE):
            return(f"No config file found, {CONFIG_FILE} does not exist")
        else:
            logging.info("trying to read config file")
            config = read_yaml(CONFIG_FILE)
            logging.info("read config file")
            zz = Zoom()
            zz.set_api_key(config['api-key'])
            zz.set_api_secret(config['api-secret'])
            zz.set_jwt_token(zz.generate_jwt_token())
            logging.info("generated token")
            # this gets the participants
            API_response = zz.zoom_get_meeting_participants(meeting_id)
            logging.info(f"Zoom API response: {API_response}")
            logging.info(f"Zoom API response text: {API_response.text}")

            filtering = False
            if 'filter' in request_json:
                filtering = True
            lms = OC_limesurvey(usr=config['lms-user'],
                                psw=config['lms-password'],
                                url=config['lms-url'])
            lms.set_survey_id(config["lms-sid"])
            lms.set_key(lms.get_session_key())
            print("getting offline participants")
            survey_answers = lms.get_answers()
            offline_participants = lms.clean_responses(survey_answers)

            if API_response.status_code == 200:
                # this getst the meeting information, time, name, etc.
                meeting_report_API_response = zz.zoom_get_meeting_report(
                    meeting_id)
                # if the one before worked, this should work too, no check on
                # status = 200
                if meeting_report_API_response.status_code == 200:
                    meeting_report = json.loads(
                        meeting_report_API_response.text)
                    participants_report = json.loads(API_response.text)
                    # participants = participants_report['participants']
                    meeting_report['participants_report'] = participants_report

                    logging.info("participants:", participants_report)
                    if filtering:
                        start_time = meeting_report['start_time']
                        end_time = meeting_report['end_time']
                        offline_participants = lms.filter_responses(
                            offline_participants, start_time, end_time)

                    all_participants = merge(
                        participants_report['participants'], offline_participants)

                    if 'participants' in participants_report.keys():
                        meeting_report['all_participants'] = all_participants
                        return meeting_report
                    else:
                        return f"Report has no participants. Are you sure the meeting id is correct?\nReport:\n{API_response.text}"
                else:
                    return "The second API call (meeting info) did not work"
            else:
                return f"Zoom API answered with {API_response} \n\nFull Text: {API_response.text}"
    else:
        return 'No meeting ID given!'
# [END oc_get_participants_hybrid]


class Zoom:
    def __init__(self):
        self.api_key = ""
        self.api_secret = ""
        self.base_url = "https://api.zoom.us/v2"
        self.reports_url = f"{self.base_url}/report/meetings"
        self.jwt_token_exp = 1800
        self.jwt_token_algo = "HS256"
        self.jwt_token = ""

    def set_api_key(self, api_key: str):
        self.api_key = api_key

    def set_api_secret(self, api_secret: str):
        self.api_secret = api_secret

    def set_jwt_token(self, jwt_token: str):
        self.jwt_token = jwt_token

    def get_jwt_token(self):
        return self.jwt_token

    def generate_jwt_token(self) -> bytes:
        iat = int(time.time())
        jwt_payload: Dict[str, Any] = {
            "aud": None,
            "iss": self.api_key,
            "exp": iat + self.jwt_token_exp,
            "iat": iat
        }
        header: Dict[str, str] = {"alg": self.jwt_token_algo}
        jwt_token: bytes = jwt.encode(header, jwt_payload, self.api_secret)

        return jwt_token

    def zoom_get_meeting_participants(self, meeting_id: str,
                                      next_page_token: Optional[str] = None) -> requests.Response:
        url: str = f"{self.reports_url}/{meeting_id}/participants"
        query_params: Dict[str, Union[int, str]] = {"page_size": 3000}
        if next_page_token:
            query_params.update({"next_page_token": next_page_token})

        r: requests.Response = requests.get(url,
                                            headers={
                                                "Authorization": f"Bearer {self.jwt_token.decode('utf-8')}"},
                                            params=query_params)

        return r

    def zoom_get_meeting_report(self, meeting_id: str) -> requests.Response:
        url: str = f"{self.reports_url}/{meeting_id}"
        r: requests.Response = requests.get(url,
                                            headers={"Authorization": f"Bearer {self.jwt_token.decode('utf-8')}"})
        return r


# version 13/10/2021
class OC_limesurvey:

    def __init__(self, usr, psw, url):
        self.user = usr
        self.url = url
        self.psw = psw
        self.sID = ""  # 918679
        self.s_key = ""

    def set_user(self, user: str):
        self.user = user

    def set_psw(self, psw: str):
        self.psw = psw

    def set_url(self, url: str):
        self.url = url

    def set_survey_id(self, sID: int):
        self.sID = sID

    def set_key(self, s_key):
        self.s_key = s_key

    def create_lms_request(self, payload):
        req = urllib.request.Request(
            url=self.url, data=json.dumps(payload).encode("utf-8"))
        req.add_header('content-type', 'application/json')
        req.add_header('connection', 'Keep-Alive')
        # to avoid 403 Forbidden / scraping block
        req.add_header('User-Agent', 'Mozilla/5.0')
        return req

    def get_session_key(self):
        func_name = "get_session_key"
        payload = {'method': func_name,
                   'params': [self.user, self.psw],
                   'id': 1}

        req = self.create_lms_request(payload)
        try:
            f = urllib.request.urlopen(req)
            myretun = f.read()
            # print("response: ", myretun)
            j = json.loads(myretun)
            return j['result']
        except:
            e = sys.exc_info()[0]
            print("<p>Error: %s</p>" % e)

    def get_answers(self):
        func_name = "export_responses"
        payload = {'method': func_name,
                   'params': [self.s_key, self.sID, 'json'],
                   'id': 1}
        req = self.create_lms_request(payload)
        try:
            f = urllib.request.urlopen(req)
            answersb64 = f.read()
            ans_j = json.loads(answersb64)
            return base64.b64decode(ans_j['result'])
        except:
            e = sys.exc_info()[0]
            print("<p>Error: %s</p>" % e)

    def get_summary(self):
        func_name = "get_summary"
        payload = {'method': func_name,
                   'params': [self.key, self.sID],
                   'id': 1}
        req = self.create_lms_request(payload)
        try:
            f = urllib.request.urlopen(req)
            myretun = f.read()
            print(myretun)
            # pdb.set_trace()
            j = json.loads(myretun)
            return j
        except:
            e = sys.exc_info()[0]
            print("<p>Error: %s</p>" % e)

    def clean_responses(self, json_response: str):
        """remove empty and non valid responses."""
        valid_responses = []
        resp_list = json.loads(json_response)['responses']
        logging.info(f"Got {len(resp_list)} responses")
        for i, resp in enumerate(resp_list):
            # resp is a dict
            for d_key in resp.keys():
                resp_data = resp[d_key]  # so it is encapsulated
                # I do not know beforehand the id key
                if resp_data['N1'] is not None and resp_data['N2'] is not None:
                    valid_responses.append({
                        'name': resp_data['N1'],
                        'surname': resp_data['N2'],
                        'place': resp_data['Place'],
                        'datestamp': resp_data['datestamp']
                    })
        return valid_responses

    def filter_responses(self, all_responses, time_start: str, time_end: str):
        """
        It returns only the responses within the given time range.
        Times should be strings in Zoom format, timestamptz %Y-%m-%dT%H:%M:%SZ.
        """
        format_zoom = '%Y-%m-%dT%H:%M:%SZ'
        start_date = datetime.strptime(time_start, format_zoom)
        end_date = datetime.strptime(time_end, format_zoom)
        # we allow 1 hour before and after for the registration
        # but zoom time have 2 hours less than german times,
        # so we add 2 and then -1 and +1 becomes +1 and +3
        start_timerange_allowed = start_date + timedelta(hours=1)
        end_timerange_allowed = end_date + timedelta(hours=3)
        filtered_resp = []
        for resp in all_responses:
            datestamp = resp['datestamp']
            format_survey = '%Y-%m-%d %H:%M:%S'
            survey_date = datetime.strptime(datestamp, format_survey)
            if survey_date.date() == start_date.date():
                if survey_date.time() > start_timerange_allowed.time() and survey_date.time() < end_timerange_allowed.time():
                    filtered_resp.append(resp)

        return filtered_resp

    def read_survey_response(self):

        responses_string = self.get_answers()
        responses_json = json.loads(responses_string)
        responses_list = responses_json['responses']
        cleaned_responses = self.clean_responses(responses_list)

        return cleaned_responses


def read_yaml(yaml_path):
    """Read the configuration parameters and secrets from the YAML file"""
    with open(yaml_path) as file:
        yaml_config = yaml.load(file, Loader=yaml.FullLoader)
    return yaml_config


def clear_meeting_id(full_link):
    """It removes the http part at the beginning and password or addon part in the end of the meeting_id"""
    if full_link[:4] == 'http' or full_link.find('/j/') > 0:
        full_link = full_link.split('/j/')[1]
    if full_link.find('?') > 0:
        full_link = full_link[:full_link.index('?')]
    return full_link


def merge(online_participants, offline_participants):

    all_participants = []
    for part in online_participants:
        h_part = {'name': part['name'],
                  'email': part['user_email'],
                  'join_time': part['join_time'],
                  'leave_time': part['leave_time'],
                  'duration': part['duration'],
                  'type': "online",
                  'place': "zoom"
                  }
        all_participants.append(h_part)

    for part in offline_participants:
        join_time = part['datestamp'][:10] + "T" + part['datestamp'][11:] + "Z"
        h_part = {'name': part['name'] + " " + part['surname'],
                  'email': "",
                  'join_time': join_time,
                  'leave_time': "",
                  'duration': "",
                  'type': "offline",
                  'place': part['place']
                  }
        all_participants.append(h_part)

    return all_participants


"""
https://dev.to/googlecloud/using-secrets-in-google-cloud-functions-5aem
import os
from google.cloud import secretmanager

client = secretmanager.SecretManagerServiceClient()
secret_name = "my-secret"
project_id = "my-gcp-project"
request = {"name": f"projects/{project_id}/secrets/{secret_name}/versions/latest"}
response = client.access_secret_version(request)
secret_string = response.payload.data.decode("UTF-8")
"""
