FROM python:3.10.12
RUN mkdir -p /mlflow
RUN pip install mlflow==2.6.0 boto3
EXPOSE 80
ENTRYPOINT ["mlflow"]
CMD [ "server", "--host", "0.0.0.0", "--port", "80" ]
