import os
import httpx
import asyncio
import secrets
import base64
import pyotp
import logging
from urllib.parse import urlparse, parse_qs

#logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

#os.environ['PYTHONASYNCIODEBUG'] = '1'

# Paste your credentials below: 
API_KEY = ""
SECRET_KEY = "" 
RURL = "" # Redirect url
TOTP_KEY = ""
MOBILE_NO = ""
PIN   =    ""

host = "https://api.upstox.com/v2" #"https://api-v2.upstox.com"
host_2 = "https://api-v2.upstox.com"
service_host = "https://service.upstox.com"
login_host = "https://login.upstox.com"

routes = {
    "auth" : f"{host}/login/authorization/dialog",
    "otp_generate" : f"{service_host}/login/open/v6/auth/1fa/otp/generate",
    "otp_verify" : f"{service_host}/login/open/v4/auth/1fa/otp-totp/verify",
    "2fa" : f"{service_host}/login/open/v3/auth/2fa",
    "redirect_url" : f"{host_2}/login/authorization/redirect",
    "oauth" : f"{service_host}/login/v2/oauth/authorize",
    "accesstoken_url" :  f"{host}/login/authorization/token",
}

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

service_headers = {
    'Accept': '*/*',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
    'Content-Type': 'application/json',
    'Host': 'service.upstox.com',
    'Origin': login_host,
    'Referer': f"{login_host}/",
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-site',
    'TE': 'trailers',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0',
    'X-Device-Details': 'platform=WEB|osName=Windows/10|osVersion=Firefox/118.0|appVersion=4.0.0|modelName=Firefox|manufacturer=unknown'
    
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
    logging.info("Error :: {}".format(response.text))
    
async def get_code():
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            routes["auth"], 
            headers=headers, 
            params=auth_params
            )

        if response.status_code == 302:
            if response.next_request:
                redirect_url = response.next_request.url
                logging.info("Redirect URL: {}".format(redirect_url))
                query_params = parse_qs(urlparse(str(redirect_url)).query)
                if 'client_id' in query_params:
                    client_id = query_params['client_id'][0]
                    user_id = query_params['user_id'][0]
                    logging.info("client_id: {}    user_id: {}".format(client_id, user_id))

                    #await client.options(routes["otp_generate"], headers=service_headers)
                    logging.info(f"Cookies :: {client.cookies}")
                    response = await client.post(
                        routes["otp_generate"], 
                        headers={
                            **service_headers, 
                            "X-Request-ID": generateUniqueID()
                            }, 
                        json={
                            "data": {
                                **otp_data["data"],
                                "userId":user_id
                                }
                            } 
                        
                        )
                    if response.status_code == 200:
                        try:
                            validateOTPToken = response.json()["data"].get("validateOTPToken", "")
                            logging.info(validateOTPToken)
                        except KeyError:
                            logging.error(response.json().get("error"))
                            sys.exit()
    
                        response = await client.post(
                            routes["otp_verify"], 
                            headers = {
                                    **service_headers, 
                                    "X-Request-ID": generateUniqueID()
                                    } , 
                            json = {
                                "data": {
                                    "otp": pyotp.TOTP(TOTP_KEY).now(), 
                                    "validateOtpToken": validateOTPToken,
                                    }
                                }, 
                            
                            )
                        if response.status_code == 200:
                            logging.info(response.text)
                            userprofile = response.json()["data"]["userProfile"]
                            profile_id = userprofile.get("profileId")
                            user_id = userprofile.get("userId")
                            logging.info("Profile :: {} and user :: {}".format(profile_id, user_id))
    
                            response = await client.post(
                                routes["2fa"], 
                                headers = {
                                    **service_headers, 
                                    "X-Request-ID": generateUniqueID(),
                                    "X-Profile-Id": str(profile_id),
                                    "X-User-Id":user_id
                                    }, 
                                json = twofa_data, 
                                params={
                                        "client_id": client_id,
                                        "redirect_uri": routes["redirect_url"]
                                    }
                                )
                            
                            if response.status_code == 200:
                                logging.info(response.text)
    
                                response = await client.post(
                                    routes["oauth"], 
                                    headers = {
                                        **service_headers, 
                                        "X-Request-ID": generateUniqueID()
                                        }, 
                                    json = oauth_data, 
                                    params={
                                            "client_id": client_id,
                                            "redirect_uri": routes["redirect_url"],
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
    
        
