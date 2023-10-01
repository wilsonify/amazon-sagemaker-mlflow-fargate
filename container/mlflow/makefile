

build:
	docker build --progress=plain -t 064592191516.dkr.ecr.us-east-1.amazonaws.com/mlflow:latest .

push:
	aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 064592191516.dkr.ecr.us-east-1.amazonaws.com
	docker push 064592191516.dkr.ecr.us-east-1.amazonaws.com/mlflow:latest