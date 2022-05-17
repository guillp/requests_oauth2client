# Usage

To use requests_oauth2client in a project

```
    from requests_oauth2client import *
```

Alternatively, you can import only the required components one by one instead of `*`.

You usually also have to use requests for your actual API calls:

```
import requests
```

That is unless you use the [ApiClient](/api/#requests_oauth2client.api_client.ApiClient) class as a wrapper around `requests.Session`. In that case, you don't need to import requests at all!
