FROM fluent/fluentd:v1.18-debian-1

USER root
RUN gem install fluent-plugin-out-http --no-document
COPY configs/fluentd-configuration/filter_ecs_normalizer.rb /fluentd/plugins/filter_ecs_normalizer.rb
USER fluent

EXPOSE 22424 22425
