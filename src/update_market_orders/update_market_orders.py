import os

from esi import ESI

EVE_CLIENT_ID = os.getenv("EVE_CLIENT_ID")
EVE_SECRET_KEY = os.getenv("EVE_SECRET_KEY")
REFRESH_TOKEN = os.getenv("REFRESH_TOKEN")


def handler(event, context):

    if (
        EVE_CLIENT_ID is None
        or EVE_SECRET_KEY is None
        or REFRESH_TOKEN is None
        or EVE_CLIENT_ID == "UNSET"
        or EVE_SECRET_KEY == "UNSET"
        or REFRESH_TOKEN == "UNSET"
    ):
        raise ValueError("Missing environment variables.")

    esi = ESI(
        EVE_CLIENT_ID,
        EVE_SECRET_KEY,
        REFRESH_TOKEN,
    )

    return esi.get_structure_market_orders(1040278453044)[0]
