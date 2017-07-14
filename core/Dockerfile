
FROM template/backend:template

ENV UTILS_VERSION 0.5.0
ENV HTTP_BRANCH master

RUN pip3 install --upgrade rapydo-utils==$UTILS_VERSION
RUN pip3 install --upgrade \
    git+https://github.com/rapydo/http-api.git@$HTTP_BRANCH
