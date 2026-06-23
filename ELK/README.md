These are some links, that have been followed, setting up this environment

This readme follows some of the [Elastic Multi Node Cluster documentation](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-compose)

## Prerequisites:
- Install Docker and the Docker Compose plugin. Instructions can be found in the [Docker Compose documentation](https://docs.docker.com/desktop/setup/install/linux/ubuntu/)
- Clone this repository
```bash
git clone https://github.com/bundgaarrd/ElasticForCFS.git
```

Environment variables have to be declared in an environment `.env` file. Make sure that this file is hidden in production environments. This is provided here to make the setup easier and the information is not sensitive.

## Run the setup
Navigate to the ELK folder and run the following command to start the containers in detached mode, so that they run in the background.
```bash
sudo docker compose up -d
```