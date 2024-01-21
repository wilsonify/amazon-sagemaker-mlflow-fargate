FROM ghcr.io/mlflow/mlflow:v2.9.2
RUN mkdir -p /mlflow
RUN apt-get update && apt-get install -y curl
RUN pip install boto3 psycopg2-binary
EXPOSE 80
ENTRYPOINT ["mlflow"]
CMD [ "server", "--host", "0.0.0.0", "--port", "80" ]
