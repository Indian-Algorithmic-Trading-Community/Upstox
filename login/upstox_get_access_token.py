import os
import httpx
import asyncio
import secrets
import base64
import pyotp
import logging
from urllib.parse import urlparse, parse_qs

#logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG)

#os.environ['PYTHONASYNCIODEBUG'] = '1'

# Paste your credentials below: 
API_KEY = ""
SECRET_KEY = "" 
RURL = "" # Redirect url
TOTP_KEY = ""
MOBILE_NO = ""
PIN   =    ""

host = "https://api-v2.upstox.com/login/authorization"
service_host = "https://service.upstox.com/login"

routes = {
    "auth" : f"{host}/dialog",
    "otp_generate" : f"{service_host}/open/v5/auth/1fa/otp/generate",
    "otp_verify" : f"{service_host}/open/v4/auth/1fa/otp-totp/verify",
    "2fa" : f"{service_host}/open/v3/auth/2fa",
    "redirect_url" : f"{host}/redirect",
    "oauth" : f"{service_host}/v2/oauth/authorize",
    "accesstoken_url" :  f"{host}/token",
}

headers = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "content-type": "application/json"
    }

def generateUniqueID(length=10):
    characters = "1234567890abcdef"
    unique_id = ''.join(secrets.choice(characters) for _ in range(length))
    return unique_id

def encode_twofa(twofa):
    encoded_pin = base64.b64encode(twofa.encode()).decode()
    return encoded_pin

auth_params = {
        "response_type": "code",
        "client_id": API_KEY,
        "redirect_uri": RURL,
    }

    
otp_data = {
    "data": {
        "mobileNumber": MOBILE_NO
        }
    }

twofa_data = {
    "data": {
        "twoFAMethod": "SECRET_PIN", 
        "inputText": encode_twofa(PIN),
        }
    }

oauth_data = {
        "data": {
            "userOAuthApproval": True
        }
    }

accesstoken_data = {
        'client_id': API_KEY,
        'client_secret': SECRET_KEY,
        'redirect_uri': RURL,
        'grant_type': 'authorization_code'
    }

async def display(response):
    try:
        logging.info("Error :: {}".format(response.json()["errors"]))
    except:
        logging.info("Error :: {}".format(response.json()["error"]))

async def get_code():
    
    async with httpx.AsyncClient(http2= True, headers= headers) as client:
        response = await client.get(
            routes["auth"], 
            params=auth_params
            )

        if response.status_code == 302:
            client.headers.update(
                {"x-device-details": "platform=WEB|osName=Windows/10|osVersion=Chrome/116.0.0.0|appVersion=4.0.0|modelName=Chrome|manufacturer=unknown"}
                )
            if response.next_request:
                redirect_url = response.next_request.url
                logging.info("Redirect URL: {}".format(redirect_url))
                query_params = parse_qs(urlparse(str(redirect_url)).query)
                if 'client_id' in query_params:
                    client_id = query_params['client_id'][0]
                    logging.info("client_id:{}".format(client_id))

                    response = await client.post(
                        routes["otp_generate"],
                        json=otp_data, 
                        params={
                                "requestId" : f"WPRO-{generateUniqueID()}"
                                }
                        )
                    if response.status_code == 200:
                        validateOTPToken = response.json()["data"].get("validateOTPToken", "")
                        logging.info(validateOTPToken)
    
                        response = await client.post(
                            routes["otp_verify"], 
                            json = {
                                "data": {
                                    "otp": pyotp.TOTP(TOTP_KEY).now(), 
                                    "validateOtpToken": validateOTPToken,
                                    }
                                }, 
                            params={
                                "requestId" : f"WPRO-{generateUniqueID()}"
                                }
                            )
                        if response.status_code == 200:
                            logging.info(response.text)
    
                            response = await client.post(
                                routes["2fa"], 
                                json = twofa_data, 
                                params={
                                        "client_id": client_id,
                                        "redirect_uri": routes["redirect_url"],
                                        "requestId": f"WPRO-{generateUniqueID()}"
                                    }
                                )
                            
                            if response.status_code == 200:
                                logging.info(response.text)
    
                                response = await client.post(
                                    routes["oauth"], 
                                    json = oauth_data, 
                                    params={
                                            "client_id": client_id,
                                            "redirect_uri": routes["redirect_url"],
                                            "requestId": f"WPRO-{generateUniqueID()}",
                                            "response_type": "code",
                                        }
                                    )
                                if response.status_code == 200:
                                    logging.info(response.text)
                                    redirectUri = response.json()["data"].get("redirectUri", "")

                                    query_params = parse_qs(urlparse(redirectUri).query)
                                    if 'code' in query_params:
                                        code = query_params['code'][0]
                                        logging.info(code)
                                        return code
                                else:
                                    await display(response)
                            else:
                                await display(response)
                        else:
                            await display(response)
                    else:
                        await display(response)
        else:
            await display(response)
                

async def getAccessToken(code):

    accesstoken_data["code"] = code

    async with httpx.AsyncClient(http2= True) as client:
        response = await client.post(
            routes["accesstoken_url"],
            data=accesstoken_data
            )
    if response.status_code == 200:
        logging.info(response.text)
        access_token = response.json().get("access_token", "")
        logging.info("access_token: {}".format(access_token))
        return access_token
    
if __name__ == "__main__":
    code = asyncio.run(get_code())
    access_token = asyncio.run(getAccessToken(code))
    print(access_token)
    

    
        
