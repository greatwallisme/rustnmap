FROM registry.cn-shanghai.aliyuncs.com/greatwallisme/ubuntu-desktop-lxde-vnc:focal

# Override: replace supervisord entrypoint with our own low-CPU VNC server
COPY Dockerfiles/vnc/start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 5900
ENTRYPOINT ["/bin/bash", "/start.sh"]
