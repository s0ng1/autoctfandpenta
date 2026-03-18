from typing import Annotated
import base64
import os
from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport

from core import tool, toolset, namespace

namespace()

@toolset()
class Proxy:
    def __init__(self, url: str, token: str):
        transport = RequestsHTTPTransport(url=url, headers={'Authorization': f'Bearer {token}'})
        self.__client = Client(transport=transport)
    
    @tool()
    def list_traffic(self, limit: int=5, offset: int=0, filter: Annotated[str, '''Caido HTTPQL statement, such as ' req.host.like:"%.example.com" and req.method.like:"POST" ' ''']=None) -> dict:
        query = gql("""
            query($offset: Int, $limit: Int, $filter: HTTPQL) {
              interceptEntriesByOffset(
                limit: $limit
                offset: $offset
                filter: $filter
                order: {by: REQ_CREATED_AT, ordering: DESC}
              ) {
                count {
                  value
                }
                nodes {
                  request {
                    id
                    createdAt
                    host
                    port
                    method
                    path
                    query
                    length
                    response {
                      length
                      roundtripTime
                      statusCode
                    }
                  }
                }
              }
            }
        """)
        if filter:
            filter = f"{filter} and preset:no-images and preset:no-styling"
        else:
            filter = "preset:no-images and preset:no-styling"
        result = self.__client.execute(query, variable_values={"limit": limit, "offset": offset, "filter": filter})
        return result['interceptEntriesByOffset']
    
    @tool()
    def view_traffic(self, id: int, b64encode: Annotated[str, "whether the returned traffic needs to be base64 encoded. Generally, not required, so you can view the results directly"]=False) -> dict:
        query = gql("""
            query ($id: ID!) {
              request(id: $id) {
                id
                isTls
                host
                port
                raw
                response {
                    roundtripTime
                    raw
                }
              }
            }
        """)
        result = self.__client.execute(query, variable_values={"id": str(id)})
        if not b64encode and result['request'] and 'raw' in result['request']:
            result['request']['raw'] = base64.b64decode(result['request']['raw']).decode('utf-8', errors='replace')
            if result['request']['response'] and 'raw' in result['request']['response']:
                result['request']['response']['raw'] = base64.b64decode(result['request']['response']['raw']).decode('utf-8', errors='replace')
        return result



if __name__ == "__main__":
    from . import proxy
    proxy.list_traffic()