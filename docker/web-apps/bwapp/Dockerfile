# bWAPP - Buggy Web Application
# 100+ web vulnerabilities for practice

FROM raesene/bwapp:latest

LABEL maintainer="CyberLab"
LABEL description="bWAPP - A free and open source deliberately insecure web application"
LABEL lab.category="web"
LABEL lab.difficulty="beginner"

# Expose HTTP
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s \
  CMD curl -f http://localhost/ || exit 1

CMD ["sh", "-c", "service mysql start && service apache2 start && tail -f /var/log/apache2/access.log"]
