VERSION=2.9.2
GITHUB_USERNAME=wilsonify

integrate: build push

ghcr-login:
	echo $(GITHUB_TOKEN) | docker login ghcr.io -u ${GITHUB_USERNAME} --password-stdin

build: ghcr-login
	docker build --progress=plain -t 064592191516.dkr.ecr.us-east-1.amazonaws.com/mlflow:${VERSION} .

ecr-login:
	aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 064592191516.dkr.ecr.us-east-1.amazonaws.com

push: ecr-login
	docker push 064592191516.dkr.ecr.us-east-1.amazonaws.com/mlflow:${VERSION}