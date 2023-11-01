# libPyElk v1.2

Easy integration of ElasticSearch with Python applications.

## Utilities
- Create connection to the ElasticSearch cluster based on a defined configuration file.
  - Create connection to the ElasticSearch cluster without authentication method.
  - Create connection to the ElasticSearch cluster using HTTP Authentication as the authentication method.
  - Create connection to the ElasticSearch cluster using API Key as an authentication method.
  - The connection can be created using or not using the SSL/TLS protocol. It's recommended to use the SSL/TLS protocol for security reasons.
  - When using the SSL/TLS protocol, the option to verify or not verify the SSL certificate can be used. It's recommended to use the option to verify the SSL certificate, for security reasons.
- Create a Search object
- Performs a search in ElasticSearch using Query String.
- Performs a search in ElasticSearch using Query String and Aggregations.
- Generates a Telegram message based on the result of a search in ElasticSearch.

# Requirements
- CentOS 8, Red Hat 8 or Rocky Linux 8
- Python 3.9
- Python Libraries
  - requests == 2.31.0
  - elasticsearch == 7.17.9
  - elasticsearch-dsl == 7.4.1
  - libPyUtils v1.2 (https://github.com/erickrr-bd/libPyUtils)
    
**NOTE:** The versions displayed are the versions with which it was tested. This doesn't mean that versions older than these don't work. This library doesn't work with versions 8.x of the Python ElasticSearch Client.

# Installation

Copy the "libPyElk" folder to the following path:

`/usr/local/lib/python3.9/site-packages`

**NOTE:** The path depends on the Python version.

# Commercial Support
![Tekium](https://github.com/unmanarc/uAuditAnalyzer2/blob/master/art/tekium_slogo.jpeg)

Tekium is a cybersecurity company specialized in red team and blue team activities based in Mexico, it has clients in the financial, telecom and retail sectors.

Tekium is an active sponsor of the project, and provides commercial support in the case you need it.

For integration with other platforms such as the Elastic stack, SIEMs, managed security providers in-house solutions, or for any other requests for extending current functionality that you wish to see included in future versions, please contact us: info at tekium.mx

For more information, go to: https://www.tekium.mx/
