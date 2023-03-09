Kong plugin template WITH DOCKER / DOCKER COMPOSE running on a DBLESS Kong 2.8.1 installation
====================

Datadome plugin tests

- Open the file handler.lua, paste your Datadome key and save the file

- To start the containers:
`docker-compose up` or `docker-compose up -d`

You need the following ports available:
- 8000 (Kong the API Gateway)
- 8001 (Kong Admin API)
- 8444

Now you can make a request to a route and see one of the the activated plugin in action.
To perform this, just make a GET request to (http://localhost:8000/v1/my-plugin-data).

To confirm the plugin is activated and working, look the response headers or check the logs being printed in the terminal (running docker-compose with -d flag).

To stop the containers:
`docker-compose down`

