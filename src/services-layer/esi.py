import time

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError

ESI_BASE_URL = "https://esi.evetech.net/"
TOKEN_ENDPOINT = "https://login.eveonline.com/v2/oauth/token/"


class ESI:
    def __init__(self, client_id: str, secret_key: str, refresh_token: str):
        self.client_id = client_id
        self.secret_key = secret_key

        self.refresh_token = refresh_token
        self.access_token_cache = None

    def get_structure_market_orders(self, structure_id: int):
        url = ESI_BASE_URL + f"/v1/markets/structures/{structure_id}/"

        headers = {"Authorization": f"Bearer {self.__get_access_token()}"}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
        except HTTPError as e:
            raise Exception(f"Failed to retrieve market orders: {e}")

        return response.json()

    def __get_access_token(self) -> str:
        current_unix = time.time()

        if (
            self.access_token_cache is not None
            and self.access_token_cache.get("expiration_unix", 0) > current_unix
        ):
            return self.access_token_cache.get("access_token", "")

        auth = HTTPBasicAuth(self.client_id, self.secret_key)

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "login.eveonline.com",
        }

        data = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
        }

        try:
            response = requests.post(
                TOKEN_ENDPOINT,
                auth=auth,
                headers=headers,
                data=data,
            )
            response.raise_for_status()
            access_token = response.json()
        except HTTPError as e:
            raise Exception(f"Failed to retrieve access token: {e}")

        self.access_token_cache = {
            "access_token": access_token.get("access_token"),
            "expiration_unix": access_token.get("expires_in", 0) + current_unix,
        }

        return self.access_token_cache.get("access_token", "")
