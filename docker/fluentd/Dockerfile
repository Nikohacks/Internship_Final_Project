FROM fluent/fluentd:v1.18-debian-1

USER root
RUN gem install fluent-plugin-out-http --no-document
USER fluent

COPY pipeline/fluentd/opt/fluent/plugins /fluentd/plugins

EXPOSE 22424 22425
