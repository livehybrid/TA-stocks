import json
import logging

import import_declare_test
from solnlib import conf_manager, log
from splunklib import modularinput as smi
import requests
from typing import Callable


ADDON_NAME = "TA-stocks"


def logger_for_input(input_name: str) -> logging.Logger:
    return log.Logs().get_logger(f"{ADDON_NAME.lower()}_{input_name}")


def get_account_api_key(session_key: str, account_name: str):
    cfm = conf_manager.ConfManager(
        session_key,
        ADDON_NAME,
        realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-ta-stocks_account",
    )
    account_conf_file = cfm.get_conf("ta-stocks_account")
    return account_conf_file.get(account_name).get("api_key")


def parse_tiingocrypto_resp(resp, logger: logging):
    ts_array = []
    for ticker in resp:
        for data in ticker["priceData"]:
            ts_obj = data
            ts_obj["baseCurrency"] = ticker["baseCurrency"]
            ts_obj["quoteCurrency"] = ticker["quoteCurrency"]
            ts_obj["ticker"] = ticker["ticker"]
            ts_array.append(ts_obj)
    return ts_array


def parse_tiingo_resp(resp, logger: logging):
    return resp


def parse_alphavantage_ts_resp(resp, logger: logging.Logger):
    """
    {
        "Time Series (Daily)": {
        "2024-11-14": {
            "1. open": "110.0600",
            "2. high": "110.6300",
            "3. low": "109.7965",
            "4. close": "109.9700",
            "5. volume": "68938"
        },
        ...
    """
    ts_array = []
    for date, ts in resp["Time Series (Daily)"].items():
        logger.info(date)
        logger.info(ts)
        ts_obj = {}
        ts_obj["date"] = f"{date}T23:59:59.000Z"
        for ts_key, ts_val in ts.items():
            ts_obj[ts_key.split(" ")[1]] = ts_val
        ts_array.append(ts_obj)
    return ts_array


def parse_alphavantage_global_resp(resp, logger: logging.Logger):
    """
    {
        "Global Quote": {
            "1. open": "110.0600",
            "2. high": "110.6300",
            "3. low": "109.7965",
            "4. close": "109.9700",
            "5. volume": "68938"
        },
        ...
    """
    ts_obj = {}
    # ts_obj['date']=f"{date}T23:59:59.000Z"
    for ts_key, ts_val in resp["Global Quote"].items():
        ts_obj[ts_key.split(" ")[1]] = ts_val
    ts_obj["date"] = f"{ts_obj['latest']}T23:59:59.000Z"
    return [ts_obj]


def get_input_url(input_type: str, ticker: str, api_key: str):
    options = {
        "alphavantage_daily": f"https://www.alphavantage.co/query?function=GLOBAL_QUOTE&symbol={ticker}&apikey={api_key}",  # &outputsize=full
        "tiingo_iex_current": f"https://api.tiingo.com/iex/?tickers={ticker}",
        "tiingo_fx_current": f"https://api.tiingo.com/tiingo/fx/top?resampleFreq=5min&tickers={ticker}&token={api_key}",
        "tiingo_crypto_endofday": f"https://api.tiingo.com/tiingo/crypto/prices?resampleFreq=1hour&tickers={ticker}&token={api_key}",
        "tiingo_stock_endofday": f"https://api.tiingo.com/tiingo/daily/prices?&tickers={ticker}&token={api_key}",
        # https://api.tiingo.com/tiingo/crypto/prices?resampleFreq=1hour&tickers=
    }
    return options.get(input_type)


def get_input_headers(input_type: str, api_key: str):
    options = {
        "alphavantage_daily": {"Content-Type": "application/json"},
        "tiingo_iex_current": {"Content-Type": "application/json", "Authorization": f"Token {api_key}"},
        "tiingo_fx_current": {"Content-Type": "application/json", "Authorization": f"Token {api_key}"},
        "tiingo_crypto_endofday": {"Content-Type": "application/json", "Authorization": f"Token {api_key}"},
        "tiingo_stock_endofday": {"Content-Type": "application/json", "Authorization": f"Token {api_key}"},
    }
    return options.get(input_type)


def get_input_parser(input_type: str, logger: logging.Logger, response: dict):
    options = {
        "alphavantage_daily": "parse_alphavantage_global_resp",
        "tiingo_iex_current": "parse_tiingo_resp",
        "tiingo_fx_current": "parse_tiingo_resp",
        "tiingo_crypto_endofday": "parse_tiingocrypto_resp",
        "tiingo_stock_endofday": "parse_tiingo_resp",
    }
    parserFuncName = options.get(input_type)
    parserFunc: Callable[dict, logging.logger] = globals()[parserFuncName]
    return parserFunc(response, logger)


def get_data_from_api(logger: logging.Logger, input_name: str, input_item: dict, api_key: str):
    logger.info("Getting data from an external API")
    input_type, input_stanza_name = input_name.split("://")

    ticker = input_item["ticker"] if "ticker" in input_item else input_item["tickers"]
    logger.info(f"Getting data for ticker(s)={ticker}")
    url = get_input_url(input_type, ticker, api_key)
    headers = get_input_headers(input_type, api_key)

    # https://api.tiingo.com/tiingo/daily/csco/prices

    # https://www.alphavantage.co/documentation/#daily
    tickets = "AAPL,CSCO,VWRL.LON"
    logger.info(url)
    requestResponse = requests.get(url, headers=headers)
    json_resp = requestResponse.json()
    #    logger.info(json_resp)
    return get_input_parser(input_type, logger, json_resp)


def validate_input(definition: smi.ValidationDefinition):
    return


def get_vanguard_graphql(logger: logging.Logger, input_name: str, input_item: dict):

    # Reusable components for API interaction
    API_URL = "https://www.vanguard.co.uk/gpx/graphql"
    HEADERS = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "en-US,en;q=0.9",
        "apollographql-client-name": "gpx",
        "content-type": "application/json",
        "x-consumer-id": "uk2",
    }

    # Define the GraphQL queries
    QUERIES = {
        "breakdown": {
            "operationName": "FundsHoldingsQuery",
            "variables": {
                "portIds": input_item.get("portids", "").split(","),
                "lastItemKey": '{"portIdKey":"fundBorHoldings-9218-2024-10-31","skey":0.00016,"pkey":"fundBorHoldings-9218-c02f0eeb7f852bf4e25fbaa5823727eb43b5c66d"}',
                "securityTypes": [
                    "FI.ABS",
                    "FI.CONV",
                    "FI.CORP",
                    "FI.IP",
                    "FI.LOAN",
                    "FI.MBS",
                    "FI.MUNI",
                    "FI.NONUS_GOV",
                    "FI.US_GOV",
                    "MF.MF",
                    "MM.AGC",
                    "MM.BACC",
                    "MM.CD",
                    "MM.CP",
                    "MM.MCP",
                    "MM.RE",
                    "MM.TBILL",
                    "MM.TD",
                    "MM.TFN",
                    "EQ.DRCPT",
                    "EQ.ETF",
                    "EQ.FSH",
                    "EQ.PREF",
                    "EQ.PSH",
                    "EQ.REIT",
                    "EQ.STOCK",
                    "EQ.RIGHT",
                    "EQ.WRT",
                ],
            },
            "query": """query FundsHoldingsQuery($portIds: [String!], $securityTypes: [String!], $lastItemKey: String) {
            funds(portIds: $portIds) {
                profile {
                fundFullName
                fundCurrency
                primarySectorEquityClassification
                __typename
                }
                __typename
            }
            borHoldings(portIds: $portIds) {
                holdings(limit: 1500, securityTypes: $securityTypes, lastItemKey: $lastItemKey) {
                items {
                    issuerName
                    securityLongDescription
                    gicsSectorDescription
                    icbSectorDescription
                    icbIndustryDescription
                    marketValuePercentage
                    sedol1
                    quantity
                    ticker
                    securityType
                    finalMaturity
                    effectiveDate
                    marketValueBaseCurrency
                    bloombergIsoCountry
                    couponRate
                    __typename
                }
                totalHoldings
                lastItemKey
                __typename
                }
                __typename
            }
            }""",
        },
        "endofday": {
            "operationName": "PriceAnalysisGqlQuery",
            "variables": {"portIds": ["9218"]},
            "query": """query PriceAnalysisGqlQuery($portIds: [String!]!) {
            funds(portIds: $portIds) {
                pricingDetails {
                navPrices(limit: -1, sortAsc: true) {
                    items {
                    asOfDate
                    currencyCode
                    price
                    __typename
                    }
                    __typename
                }
                marketPrices(limit: -1, sortAsc: true) {
                    items {
                    items {
                        asOfDate
                        currencyCode
                        price
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                __typename
                }
                __typename
            }
            }""",
        },
    }

    function = input_item.get("function")
    """Execute a GraphQL query based on the function variable."""
    if function not in QUERIES:
        raise ValueError(f"Invalid function: {function}. Must be one of {list(QUERIES.keys())}.")

    query_data = QUERIES[function]
    response = requests.post(API_URL, headers=HEADERS, json=query_data)

    if response.status_code == 200:
        if function == "endofday":
            resp_array = []
            for item in response.json()["data"]["funds"][0]["pricingDetails"]["navPrices"]["items"]:
                item["date"] = f"{item['asOfDate']}T23:59:59.000Z"
                del item["asOfDate"]
                resp_array.append(item)
            return resp_array
        return response.json()["data"]["borHoldings"][0]["holdings"]["items"]
    else:
        raise Exception(f"Query failed with status code {response.status_code}: {response.text}")


def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter):
    # inputs.inputs is a Python dictionary object like:
    # {
    #   "stocks://<input_name>": {
    #     "account": "<account_name>",
    #     "disabled": "0",
    #     "host": "$decideOnStartup",
    #     "index": "<index_name>",
    #     "interval": "<interval_value>",
    #     "python.version": "python3",
    #   },
    # }
    for input_name, input_item in inputs.inputs.items():
        normalized_input_name = input_name.split("/")[-1]
        logger = logger_for_input(normalized_input_name)
        try:
            session_key = inputs.metadata["session_key"]
            log_level = conf_manager.get_log_level(
                logger=logger,
                session_key=session_key,
                app_name=ADDON_NAME,
                conf_name="ta-stocks_settings",
            )
            logger.setLevel(log_level)
            log.modular_input_start(logger, normalized_input_name)

            if input_item.get("account"):
                api_key = get_account_api_key(session_key, input_item.get("account"))
            if "vanguard" in input_name:
                data = get_vanguard_graphql(logger, input_name, input_item)
            else:
                data = get_data_from_api(logger, input_name, input_item, api_key)

            sourcetype = input_name.split("://")[0]
            for line in data:
                event_writer.write_event(
                    smi.Event(
                        data=json.dumps(line, ensure_ascii=False, default=str),
                        index=input_item.get("index"),
                        sourcetype=sourcetype,
                    )
                )
            log.events_ingested(
                logger,
                input_name,
                sourcetype,
                len(data),
                input_item.get("index"),
                account=input_item.get("account"),
            )
            log.modular_input_end(logger, normalized_input_name)
        except Exception as e:
            log.log_exception(logger, e, "my custom error type", msg_before="Exception raised while ingesting data for demo_input: ")
