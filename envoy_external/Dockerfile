FROM envoyproxy/envoy:latest
COPY envoy.yaml /etc/envoy/envoy.yaml

RUN sed -i -r "s/IAP_AUDIENCE/${IAP_AUDIENCE}/g" /etc/envoy/envoy.yaml

COPY server_neg_crt.pem /certs/server_neg_crt.pem
COPY server_neg_key.pem /certs/server_neg_key.pem
EXPOSE 443
