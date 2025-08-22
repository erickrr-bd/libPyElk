# libPyElk v2.2

A lightweight Python library for managing Elasticsearch operations with ease.

## Features
- Connect to local or remote Elasticsearch clusters
  - Connect to local or remote Elasticsearch clusters without authentication method.
  - Connect to local or remote Elasticsearch clusters using HTTP Authentication as the authentication method.
  - Connect to local or remote Elasticsearch clusters using API Key as an authentication method.
  - Connect to local or remote Elasticsearch clusters using the SSL/TLS protocol.
  - Connect to local or remote Elasticsearch clusters verifying the SSL certificate.
- Create and manage indices.
- Insert and query documents.
- Search using Query String.
- Converts a document to a string.

## Requirements
- Red Hat 8 or Rocky Linux 8
- Elasticsearch 7.x or 8.x
- Python 3.12
- Python Libraries
  - elasticsearch
  - elasticsearch-dsl
  - libPyUtils v2.2 (https://github.com/erickrr-bd/libPyUtils)

## Installation

Copy the "libPyElk" folder to the following path:

`/usr/local/lib/python3.12/site-packages`

**NOTE:** The path depends on the Python version.
